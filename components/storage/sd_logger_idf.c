#include "sd_logger.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "board_sd.h"
#include "capture_serial_protocol.h"
#include "driver/usb_serial_jtag.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#define SD_LOGGER_TASK_STACK       6144u
#define SD_LOGGER_TASK_PRIORITY    2u
#define SD_LOGGER_TASK_BURST       8u
#define SD_LOGGER_IDLE_WAIT_MS     100u
#define SD_LOGGER_REPORT_PERIOD_MS 3000u
#define SD_LOGGER_STOP_WAIT_MS     5000u
#define SD_LOGGER_CONSOLE_STACK    4096u
#define SD_LOGGER_CONSOLE_LINE_MAX 160u
#define SD_LOGGER_EVENT_DONE       (1u << 0)
#define SD_LOGGER_DIR              BOARD_SD_MOUNT_POINT "/capture"

static const char *TAG = "SDLOG";
static sd_logger_core_t s_core;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t s_task;
static TaskHandle_t s_console_task;
static EventGroupHandle_t s_events;
static bool s_initialized;
static char s_firmware_sha[SD_LOGGER_FW_SHA_MAX + 1u];
static FILE *s_pcap_file_handle;
static FILE *s_summary_file_handle;
static char s_last_io_error[40] = "none";
static vprintf_like_t s_previous_vprintf;
static bool s_log_wrapper_installed;
static atomic_bool s_export_streaming = ATOMIC_VAR_INIT(false);
static atomic_uint s_log_vprintf_inflight = ATOMIC_VAR_INIT(0u);

typedef enum {
    SERIAL_EXPORT_NONE = 0,
    SERIAL_EXPORT_INFO,
    SERIAL_EXPORT_FILE,
} serial_export_kind_t;

typedef struct {
    bool busy;
    bool pending;
    serial_export_kind_t kind;
    uint64_t session_id;
    char file_kind;
    uint32_t file_index;
    uint64_t offset;
} serial_export_request_t;

static serial_export_request_t s_export_request;
static uint8_t s_export_chunk[CAPTURE_SERIAL_CHUNK_MAX];
static char s_export_frame[CAPTURE_SERIAL_FRAME_MAX];

static bool process_serial_export(void);

static void sync_lock(void *ctx)
{
    (void)ctx;
    portENTER_CRITICAL(&s_mux);
}

static void sync_unlock(void *ctx)
{
    (void)ctx;
    portEXIT_CRITICAL(&s_mux);
}

static void sync_wake(void *ctx)
{
    (void)ctx;
    if (s_task != NULL) {
        xTaskNotifyGive(s_task);
    }
}

static void set_last_io_error(const char *stage, int error_number)
{
    char value[sizeof(s_last_io_error)];
    memset(value, 0, sizeof(value));
    (void)snprintf(value, sizeof(value), "%s:%d", stage, error_number);
    portENTER_CRITICAL(&s_mux);
    memcpy(s_last_io_error, value, sizeof(s_last_io_error));
    s_last_io_error[sizeof(s_last_io_error) - 1u] = '\0';
    portEXIT_CRITICAL(&s_mux);
}

static void clear_last_io_error(void)
{
    portENTER_CRITICAL(&s_mux);
    memset(s_last_io_error, 0, sizeof(s_last_io_error));
    memcpy(s_last_io_error, "none", sizeof("none") - 1u);
    portEXIT_CRITICAL(&s_mux);
}

static void copy_last_io_error(char *output, size_t capacity)
{
    if (output == NULL || capacity == 0u) {
        return;
    }
    portENTER_CRITICAL(&s_mux);
    size_t i = 0u;
    while (i + 1u < capacity && s_last_io_error[i] != '\0') {
        output[i] = s_last_io_error[i];
        ++i;
    }
    output[i] = '\0';
    portEXIT_CRITICAL(&s_mux);
}

static int capture_log_vprintf(const char *format, va_list args)
{
    (void)atomic_fetch_add_explicit(&s_log_vprintf_inflight, 1u,
                                    memory_order_acquire);
    int result = 0;
    vprintf_like_t previous = s_previous_vprintf;
    if (!atomic_load_explicit(&s_export_streaming, memory_order_acquire) &&
        previous != NULL) {
        result = previous(format, args);
    }
    (void)atomic_fetch_sub_explicit(&s_log_vprintf_inflight, 1u,
                                    memory_order_release);
    return result;
}

static bool serial_export_reserved(void)
{
    portENTER_CRITICAL(&s_mux);
    const bool busy = s_export_request.busy;
    portEXIT_CRITICAL(&s_mux);
    return busy;
}

static bool serial_export_request(serial_export_kind_t kind,
                                  uint64_t session_id, char file_kind,
                                  uint32_t file_index, uint64_t offset)
{
    portENTER_CRITICAL(&s_mux);
    if (s_export_request.busy) {
        portEXIT_CRITICAL(&s_mux);
        return false;
    }
    s_export_request.busy = true;
    s_export_request.pending = true;
    s_export_request.kind = kind;
    s_export_request.session_id = session_id;
    s_export_request.file_kind = file_kind;
    s_export_request.file_index = file_index;
    s_export_request.offset = offset;
    portEXIT_CRITICAL(&s_mux);
    if (s_task != NULL) {
        xTaskNotifyGive(s_task);
    }
    return true;
}

static bool serial_export_take(serial_export_request_t *out)
{
    bool available = false;
    portENTER_CRITICAL(&s_mux);
    if (s_export_request.pending && out != NULL) {
        *out = s_export_request;
        s_export_request.pending = false;
        available = true;
    }
    portEXIT_CRITICAL(&s_mux);
    return available;
}

static void serial_export_finish(void)
{
    portENTER_CRITICAL(&s_mux);
    s_export_request.busy = false;
    s_export_request.pending = false;
    s_export_request.kind = SERIAL_EXPORT_NONE;
    portEXIT_CRITICAL(&s_mux);
    atomic_store_explicit(&s_export_streaming, false, memory_order_release);
}

static bool ensure_mounted(void)
{
    if (board_sd_is_mounted()) {
        return true;
    }
    const esp_err_t result = board_sd_init();
    if (result != ESP_OK) {
        set_last_io_error("mount", (int)result);
        ESP_LOGW(TAG, "manual mount retry failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

static sd_logger_open_result_t io_open_new(void *ctx, uint64_t session_id,
                                           uint32_t file_index, bool summary,
                                           char *path, size_t path_capacity,
                                           void **handle)
{
    (void)ctx;
    if (path == NULL || path_capacity == 0u || handle == NULL ||
        !ensure_mounted()) {
        return SD_LOGGER_OPEN_ERROR;
    }
    *handle = NULL;
    if (mkdir(SD_LOGGER_DIR, 0775) != 0 && errno != EEXIST) {
        set_last_io_error(summary ? "summary_mkdir" : "pcap_mkdir", errno);
        ESP_LOGE(TAG, "mkdir %s failed errno=%d", SD_LOGGER_DIR, errno);
        return SD_LOGGER_OPEN_ERROR;
    }

    int name_length;
    if (summary) {
        name_length = snprintf(path, path_capacity,
                               SD_LOGGER_DIR "/session-%016" PRIX64 ".txt",
                               session_id);
    } else {
        name_length = snprintf(path, path_capacity,
                               SD_LOGGER_DIR "/capture-%016" PRIX64 "-%04" PRIu32 ".pcap",
                               session_id, file_index);
    }
    if (name_length < 0 || (size_t)name_length >= path_capacity) {
        return SD_LOGGER_OPEN_ERROR;
    }

    /* O_EXCL is the no-overwrite guarantee across boots and random-id reuse. */
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) {
        set_last_io_error(summary ? "summary_open" : "pcap_open", errno);
        return errno == EEXIST ? SD_LOGGER_OPEN_EXISTS : SD_LOGGER_OPEN_ERROR;
    }
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        const int saved_errno = errno;
        set_last_io_error(summary ? "summary_fdopen" : "pcap_fdopen",
                          saved_errno);
        (void)close(fd);
        (void)unlink(path); /* only this call's O_EXCL-created empty file */
        ESP_LOGE(TAG, "fdopen failed errno=%d", saved_errno);
        return SD_LOGGER_OPEN_ERROR;
    }
    /* The producer already batches to 4 KiB; avoid an extra stdio payload
     * buffer. The logger's core buffer is the sole batch owner. */
    if (setvbuf(file, NULL, _IONBF, 0) != 0) {
        set_last_io_error(summary ? "summary_setvbuf" : "pcap_setvbuf",
                          errno);
        (void)fclose(file);
        (void)unlink(path);
        return SD_LOGGER_OPEN_ERROR;
    }
    *handle = file;
    portENTER_CRITICAL(&s_mux);
    if (summary) {
        s_summary_file_handle = file;
    } else {
        s_pcap_file_handle = file;
    }
    portEXIT_CRITICAL(&s_mux);
    if (summary) {
        clear_last_io_error();
    }
    return SD_LOGGER_OPEN_OK;
}

static size_t io_write(void *ctx, void *handle, const uint8_t *data,
                       size_t length, bool *error, bool *storage_full)
{
    (void)ctx;
    FILE *file = (FILE *)handle;
    if (error != NULL) {
        *error = true;
    }
    if (storage_full != NULL) {
        *storage_full = false;
    }
    if (file == NULL || data == NULL || length == 0u) {
        return 0u;
    }
    errno = 0;
    const size_t written = fwrite(data, 1u, length, file);
    const bool failed = ferror(file) != 0;
    const int saved_errno = errno;
    if (error != NULL) {
        *error = failed;
    }
    if (storage_full != NULL) {
        *storage_full = saved_errno == ENOSPC;
    }
    if (failed) {
        portENTER_CRITICAL(&s_mux);
        const bool summary = file == s_summary_file_handle;
        portEXIT_CRITICAL(&s_mux);
        set_last_io_error(summary ? "summary_write" : "pcap_write",
                          saved_errno);
        ESP_LOGE(TAG, "fwrite failed errno=%d", saved_errno);
    }
    return written;
}

static bool io_flush_sync(void *ctx, void *handle)
{
    (void)ctx;
    FILE *file = (FILE *)handle;
    if (file == NULL) {
        return false;
    }
    portENTER_CRITICAL(&s_mux);
    const bool summary = file == s_summary_file_handle;
    portEXIT_CRITICAL(&s_mux);
    const char *const prefix = summary ? "summary" : "pcap";
    errno = 0;
    if (fflush(file) != 0 || ferror(file) != 0) {
        char stage[32];
        (void)snprintf(stage, sizeof(stage), "%s_fflush", prefix);
        set_last_io_error(stage, errno);
        return false;
    }
    const int fd = fileno(file);
    errno = 0;
    if (fd < 0 || fsync(fd) != 0) {
        char stage[32];
        (void)snprintf(stage, sizeof(stage), "%s_fsync", prefix);
        set_last_io_error(stage, errno);
        return false;
    }
    return true;
}

static bool io_close(void *ctx, void *handle)
{
    (void)ctx;
    if (handle == NULL) {
        return false;
    }
    FILE *file = (FILE *)handle;
    portENTER_CRITICAL(&s_mux);
    const bool summary = file == s_summary_file_handle;
    if (summary) {
        s_summary_file_handle = NULL;
    } else if (file == s_pcap_file_handle) {
        s_pcap_file_handle = NULL;
    }
    portEXIT_CRITICAL(&s_mux);
    errno = 0;
    const int result = fclose(file);
    if (result != 0) {
        const int saved_errno = errno;
        const char *const stage = summary ? "summary_close" : "pcap_close";
        set_last_io_error(stage, saved_errno);
        ESP_LOGE(TAG, "%s failed errno=%d", stage, saved_errno);
        return false;
    }
    return true;
}

static uint64_t io_now_us(void *ctx)
{
    (void)ctx;
    const int64_t now = esp_timer_get_time();
    return now < 0 ? 0u : (uint64_t)now;
}

static void update_done_event(const sd_logger_stats_t *stats)
{
    if (stats->state == SD_LOGGER_STOPPED || stats->state == SD_LOGGER_ERROR ||
        stats->state == SD_LOGGER_DISABLED) {
        xEventGroupSetBits(s_events, SD_LOGGER_EVENT_DONE);
    } else {
        xEventGroupClearBits(s_events, SD_LOGGER_EVENT_DONE);
    }
}

static void logger_task(void *arg)
{
    (void)arg;
    uint64_t next_report_us = io_now_us(NULL);
    while (true) {
        bool did_work = false;
        if (process_serial_export()) {
            did_work = true;
        }
        for (uint32_t step = 0; step < SD_LOGGER_TASK_BURST; ++step) {
            if (!sd_logger_core_process_one(&s_core)) {
                break;
            }
            did_work = true;
            sd_logger_stats_t stats;
            sd_logger_core_get_stats(&s_core, &stats);
            update_done_event(&stats);
        }

        const uint64_t now = io_now_us(NULL);
        if (now >= next_report_us &&
            now - next_report_us >= (uint64_t)SD_LOGGER_REPORT_PERIOD_MS * 1000u) {
            sd_logger_stats_t stats;
            sd_logger_core_get_stats(&s_core, &stats);
            stats.logger_stack_hwm = (uint32_t)uxTaskGetStackHighWaterMark(NULL);
            portENTER_CRITICAL(&s_mux);
            s_core.stats.logger_stack_hwm = stats.logger_stack_hwm;
            portEXIT_CRITICAL(&s_mux);
            ESP_LOGI(TAG,
                     "state=%s accept=%" PRIu64 " serial=%" PRIu64
                     " written=%" PRIu64 " flushed=%" PRIu64
                     " storage_drop=%" PRIu64 " (queue=%" PRIu64
                     " old_rx=%" PRIu64 " io_drop=%" PRIu64
                     " limit_drop=%" PRIu64 ") q=%u/%u"
                     " bytes=%" PRIu64 " rotations=%" PRIu64
                     " full=%" PRIu64 " errors=%" PRIu64
                     " limit_reached=%u"
                     " io_max_us=open:%" PRIu64 "/write:%" PRIu64
                     "/sync:%" PRIu64 "/close:%" PRIu64
                     " slow=%" PRIu64 " stack_hwm=%u file=%s",
                     sd_logger_state_name(stats.state), stats.accepted,
                     stats.serialized, stats.written, stats.flushed,
                     stats.storage_drop, stats.drop_queue_full,
                     stats.drop_pre_session, stats.drop_io, stats.drop_limit,
                     (unsigned)stats.queue_depth,
                     (unsigned)stats.queue_peak, stats.pcap_bytes,
                     stats.file_rotations, stats.storage_full_errors,
                     stats.io_errors, stats.limit_reached ? 1u : 0u,
                     stats.max_open_us, stats.max_write_us,
                     stats.max_flush_us, stats.max_close_us,
                     stats.io_slow_count,
                     (unsigned)stats.logger_stack_hwm,
                     stats.current_path[0] ? stats.current_path : "-");
            next_report_us = now;
        }

        if (!did_work) {
            (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(SD_LOGGER_IDLE_WAIT_MS));
        }
    }
}

esp_err_t sd_logger_init(const char *firmware_sha, bool media_mounted)
{
    if (s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (firmware_sha != NULL) {
        strncpy(s_firmware_sha, firmware_sha, sizeof(s_firmware_sha) - 1u);
    }
    s_events = xEventGroupCreate();
    if (s_events == NULL) {
        return ESP_ERR_NO_MEM;
    }
    const uint32_t heap_before =
        (uint32_t)heap_caps_get_free_size(MALLOC_CAP_8BIT);
    const sd_logger_io_t io = {
        .open_new = io_open_new,
        .write = io_write,
        .flush_sync = io_flush_sync,
        .close = io_close,
        .now_us = io_now_us,
    };
    const sd_logger_sync_t sync = {
        .lock = sync_lock,
        .unlock = sync_unlock,
        .wake_worker = sync_wake,
    };
    sd_logger_core_init(&s_core, &io, &sync, media_mounted);
    if (xTaskCreate(logger_task, "sd_logger", SD_LOGGER_TASK_STACK, NULL,
                    SD_LOGGER_TASK_PRIORITY, &s_task) != pdPASS) {
        vEventGroupDelete(s_events);
        s_events = NULL;
        return ESP_ERR_NO_MEM;
    }
    s_initialized = true;
    ESP_LOGI(TAG,
             "logger ready: state=%s core=%uB slots=%u x %uB batch=%uB"
             " stack=%uB heap_before=%u heap_after=%u min_heap=%u",
             media_mounted ? "STOPPED" : "DISABLED",
             (unsigned)sizeof(s_core), SD_LOGGER_POOL_SIZE,
             (unsigned)sizeof(radio_packet_t), SD_LOGGER_BATCH_SIZE,
             SD_LOGGER_TASK_STACK, (unsigned)heap_before,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT));
    return ESP_OK;
}

bool sd_logger_try_submit(const radio_packet_t *packet)
{
    return s_initialized && sd_logger_core_try_submit(&s_core, packet);
}

bool sd_logger_is_accepting(void)
{
    if (!s_initialized) {
        return false;
    }
    portENTER_CRITICAL(&s_mux);
    const bool accepting = s_core.accepting;
    portEXIT_CRITICAL(&s_mux);
    return accepting;
}

esp_err_t sd_logger_start(void)
{
    if (!s_initialized || serial_export_reserved()) {
        return ESP_ERR_INVALID_STATE;
    }
    const int64_t now_signed = esp_timer_get_time();
    const uint64_t now = now_signed < 0 ? 0u : (uint64_t)now_signed;
    const uint64_t session = ((uint64_t)esp_random() << 32) |
                             (uint64_t)esp_random();
    if (!sd_logger_core_request_start(&s_core, session, now, s_firmware_sha)) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupClearBits(s_events, SD_LOGGER_EVENT_DONE);
    return ESP_OK;
}

bool sd_logger_request_stop(void)
{
    if (!s_initialized || serial_export_reserved()) {
        return false;
    }
    return sd_logger_core_request_stop(&s_core);
}

sd_logger_wait_result_t sd_logger_wait_stopped(uint32_t timeout_ms)
{
    if (!s_initialized) {
        return SD_LOGGER_WAIT_ERROR;
    }
    const TickType_t started = xTaskGetTickCount();
    const TickType_t timeout = pdMS_TO_TICKS(timeout_ms);
    for (;;) {
        sd_logger_stats_t stats;
        sd_logger_get_stats(&stats);
        if (stats.state == SD_LOGGER_STOPPED || stats.state == SD_LOGGER_DISABLED) {
            return SD_LOGGER_WAIT_STOPPED;
        }
        if (stats.state == SD_LOGGER_ERROR) {
            return SD_LOGGER_WAIT_ERROR;
        }
        const TickType_t elapsed = xTaskGetTickCount() - started;
        if (elapsed >= timeout) {
            return SD_LOGGER_WAIT_PENDING;
        }
        const TickType_t remaining = timeout - elapsed;
        (void)xEventGroupWaitBits(s_events, SD_LOGGER_EVENT_DONE, pdTRUE, pdFALSE,
                                  remaining);
    }
}

void sd_logger_get_stats(sd_logger_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    if (!s_initialized) {
        memset(out, 0, sizeof(*out));
        out->state = SD_LOGGER_DISABLED;
        return;
    }
    sd_logger_core_get_stats(&s_core, out);
}

/* The IDF stdio USB Serial/JTAG driver is installed during startup on some
 * configurations, so esp_console_new_repl_usb_serial_jtag() can reject its
 * second install with ESP_ERR_INVALID_STATE. Keep this tiny command reader on
 * the existing driver and avoid taking any ownership of the logger's buffers
 * or file handle. Console I/O is bounded and isolated to this task. */
static void console_write(const char *text)
{
    size_t remaining = strlen(text);
    TickType_t started = xTaskGetTickCount();
    const TickType_t budget = pdMS_TO_TICKS(200u);
    while (remaining > 0u) {
        const TickType_t elapsed = xTaskGetTickCount() - started;
        if (elapsed >= budget) {
            return;
        }
        int wrote = usb_serial_jtag_write_bytes(text, (uint32_t)remaining,
                                                 budget - elapsed);
        if (wrote <= 0) {
            return;
        }
        text += wrote;
        remaining -= (size_t)wrote;
    }
}

static bool console_write_exact(const char *data, size_t length)
{
    size_t remaining = length;
    TickType_t started = xTaskGetTickCount();
    const TickType_t budget = pdMS_TO_TICKS(200u);
    while (remaining > 0u) {
        const TickType_t elapsed = xTaskGetTickCount() - started;
        if (elapsed >= budget) {
            return false;
        }
        const int wrote = usb_serial_jtag_write_bytes(
            data, (uint32_t)remaining, budget - elapsed);
        if (wrote <= 0) {
            return false;
        }
        data += wrote;
        remaining -= (size_t)wrote;
    }
    return true;
}

static bool valid_session_id(const char *text, uint64_t *session_id)
{
    if (text == NULL || session_id == NULL || strlen(text) != 16u) {
        return false;
    }
    for (size_t i = 0u; i < 16u; ++i) {
        const char ch = text[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') ||
              (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    errno = 0;
    char *end = NULL;
    const unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0u) {
        return false;
    }
    *session_id = (uint64_t)parsed;
    return true;
}

static bool parse_u64_decimal(const char *text, uint64_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

static bool export_path(uint64_t session_id, char file_kind,
                        uint32_t file_index, char *path, size_t capacity)
{
    if (session_id == 0u || path == NULL || capacity == 0u) {
        return false;
    }
    int length;
    if (file_kind == 'P' && file_index < 16u) {
        length = snprintf(path, capacity,
                          SD_LOGGER_DIR "/capture-%016" PRIX64 "-%04" PRIu32 ".pcap",
                          session_id, file_index);
    } else if (file_kind == 'S' && file_index == 0u) {
        length = snprintf(path, capacity,
                          SD_LOGGER_DIR "/session-%016" PRIX64 ".txt",
                          session_id);
    } else {
        return false;
    }
    return length >= 0 && (size_t)length < capacity;
}

static bool export_file_size(uint64_t session_id, char file_kind,
                             uint32_t file_index, uint64_t *size)
{
    char path[SD_LOGGER_PATH_MAX];
    struct stat info;
    if (size == NULL || !export_path(session_id, file_kind, file_index,
                                     path, sizeof(path)) ||
        stat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0) {
        return false;
    }
    *size = (uint64_t)info.st_size;
    return true;
}

static bool send_export_line(const char *line)
{
    return line != NULL && console_write_exact(line, strlen(line));
}

static bool send_export_error(const char *reason)
{
    char line[96];
    const int length = snprintf(line, sizeof(line), "!PCAP,ERROR,%s\r\n",
                                reason != NULL ? reason : "UNKNOWN");
    return length > 0 && (size_t)length < sizeof(line) &&
           send_export_line(line);
}

static bool export_info(uint64_t session_id)
{
    sd_logger_stats_t stats;
    sd_logger_get_stats(&stats);
    if (stats.state != SD_LOGGER_STOPPED && stats.state != SD_LOGGER_ERROR) {
        return send_export_error("LOGGER_NOT_STOPPED");
    }
    if (!ensure_mounted()) {
        return send_export_error("MEDIA_UNAVAILABLE");
    }

    uint64_t sizes[16] = {0u};
    bool present[16] = {false};
    uint32_t count = 0u;
    for (uint32_t i = 0u; i < 16u; ++i) {
        present[i] = export_file_size(session_id, 'P', i, &sizes[i]);
        if (present[i]) {
            ++count;
        }
    }
    uint64_t summary_size = 0u;
    const bool summary_present =
        export_file_size(session_id, 'S', 0u, &summary_size);
    if (count == 0u && !summary_present) {
        return send_export_error("SESSION_FILES_NOT_FOUND");
    }

    char line[160];
    int length = snprintf(line, sizeof(line),
        "!PCAP,INFO,SESSION,%s,%016" PRIX64 ",%" PRIu32 "\r\n",
        sd_logger_state_name(stats.state), session_id, count);
    if (length <= 0 || (size_t)length >= sizeof(line) ||
        !send_export_line(line)) {
        return false;
    }
    for (uint32_t i = 0u; i < 16u; ++i) {
        if (!present[i]) {
            continue;
        }
        length = snprintf(line, sizeof(line),
                          "!PCAP,INFO,PCAP,%" PRIu32 ",%" PRIu64 "\r\n",
                          i, sizes[i]);
        if (length <= 0 || (size_t)length >= sizeof(line) ||
            !send_export_line(line)) {
            return false;
        }
    }
    length = snprintf(line, sizeof(line), "!PCAP,INFO,SUMMARY,%" PRIu64 "\r\n",
                      summary_present ? summary_size : 0u);
    if (length <= 0 || (size_t)length >= sizeof(line) ||
        !send_export_line(line)) {
        return false;
    }
    return send_export_line("!PCAP,INFO,END\r\n");
}

static bool export_file(const serial_export_request_t *request)
{
    char path[SD_LOGGER_PATH_MAX];
    uint64_t file_size = 0u;
    if (request == NULL ||
        !export_path(request->session_id, request->file_kind,
                     request->file_index, path, sizeof(path)) ||
        !export_file_size(request->session_id, request->file_kind,
                          request->file_index, &file_size)) {
        return send_export_error("FILE_NOT_FOUND");
    }
    if (request->offset > file_size || request->offset > (uint64_t)LONG_MAX) {
        return send_export_error("OFFSET_OUT_OF_RANGE");
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return send_export_error("OPEN_READ_FAILED");
    }
    if (fseek(file, (long)request->offset, SEEK_SET) != 0) {
        (void)fclose(file);
        return send_export_error("SEEK_FAILED");
    }

    uint64_t offset = request->offset;
    bool ok = true;
    while (offset < file_size) {
        const uint64_t remaining = file_size - offset;
        const size_t wanted = remaining > CAPTURE_SERIAL_CHUNK_MAX
                                  ? CAPTURE_SERIAL_CHUNK_MAX
                                  : (size_t)remaining;
        const size_t got = fread(s_export_chunk, 1u, wanted, file);
        if (got != wanted || ferror(file) != 0) {
            ok = false;
            (void)send_export_error("READ_FAILED");
            break;
        }
        size_t frame_length = 0u;
        if (!capture_serial_encode_data(request->file_kind,
                                        request->file_index, offset,
                                        s_export_chunk, got,
                                        s_export_frame,
                                        sizeof(s_export_frame),
                                        &frame_length) ||
            !console_write_exact(s_export_frame, frame_length)) {
            ok = false;
            break;
        }
        offset += got;
    }
    if (fclose(file) != 0) {
        ok = false;
        (void)send_export_error("CLOSE_READ_FAILED");
    }
    if (ok) {
        char line[96];
        const int length = snprintf(line, sizeof(line),
            "!PCAP,END,%c,%" PRIu32 ",%" PRIu64 "\r\n",
            request->file_kind, request->file_index, file_size);
        ok = length > 0 && (size_t)length < sizeof(line) &&
             send_export_line(line);
    }
    return ok;
}

static bool process_serial_export(void)
{
    serial_export_request_t request;
    if (!serial_export_take(&request)) {
        return false;
    }
    /* Let the command task finish its echo and prompt before taking the
     * shared USB Serial/JTAG output stream. */
    vTaskDelay(1u);
    atomic_store_explicit(&s_export_streaming, true, memory_order_release);
    for (uint32_t wait = 0u;
         wait < 25u &&
         atomic_load_explicit(&s_log_vprintf_inflight, memory_order_acquire) != 0u;
         ++wait) {
        vTaskDelay(1u);
    }
    bool ok = atomic_load_explicit(&s_log_vprintf_inflight,
                                   memory_order_acquire) == 0u;
    if (!ok) {
        (void)send_export_error("CONSOLE_BUSY");
    } else if (request.kind == SERIAL_EXPORT_INFO) {
        ok = export_info(request.session_id);
    } else if (request.kind == SERIAL_EXPORT_FILE) {
        sd_logger_stats_t stats;
        sd_logger_get_stats(&stats);
        if (stats.state != SD_LOGGER_STOPPED &&
            stats.state != SD_LOGGER_ERROR) {
            ok = send_export_error("LOGGER_NOT_STOPPED");
        } else if (!ensure_mounted()) {
            ok = send_export_error("MEDIA_UNAVAILABLE");
        } else {
            ok = export_file(&request);
        }
    } else {
        ok = send_export_error("BAD_REQUEST");
    }
    (void)ok;
    atomic_store_explicit(&s_export_streaming, false, memory_order_release);
    serial_export_finish();
    return true;
}

static void print_stats(void)
{
    sd_logger_stats_t stats;
    char output[640];
    char last_error[sizeof(s_last_io_error)];
    sd_logger_get_stats(&stats);
    copy_last_io_error(last_error, sizeof(last_error));
    (void)snprintf(output, sizeof(output),
                   "state=%s accepted=%" PRIu64 " serialized=%" PRIu64
                   " written=%" PRIu64 " flushed=%" PRIu64
                   " storage_drop=%" PRIu64 " queue_full=%" PRIu64
                   " old_rx=%" PRIu64
                   " io_drop=%" PRIu64 " full=%" PRIu64 " io_errors=%" PRIu64
                   " incomplete=%" PRIu64 " short_writes=%" PRIu64
                   " limit=%u rotations=%" PRIu64 " invalid=%" PRIu64
                   " filtered=%" PRIu64 " queue=%u/%u session=%016" PRIX64
                   " pcap_bytes=%" PRIu64 " last_io_error=%s"
                   " max_io_us=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
                   " slow=%" PRIu64
                   " file=%s summary=%s\r\n",
                   sd_logger_state_name(stats.state), stats.accepted, stats.serialized,
                   stats.written, stats.flushed, stats.storage_drop,
                   stats.drop_queue_full, stats.drop_pre_session, stats.drop_io,
                   stats.storage_full_errors,
                   stats.io_errors, stats.files_incomplete, stats.short_writes,
                   stats.limit_reached ? 1u : 0u, stats.file_rotations,
                   stats.rejected_invalid, stats.filtered_non_data,
                   (unsigned)stats.queue_depth,
                   (unsigned)stats.queue_peak, stats.session_id, stats.pcap_bytes,
                   last_error,
                   stats.max_open_us, stats.max_write_us, stats.max_flush_us,
                   stats.max_close_us, stats.io_slow_count,
                   stats.current_path[0] ? stats.current_path : "-",
                   stats.summary_path[0] ? stats.summary_path : "-");
    console_write(output);
}

static int cmd_capture_start(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        console_write("usage: capture-start\r\n");
        return 2;
    }
    const esp_err_t result = sd_logger_start();
    if (result != ESP_OK) {
        char output[96];
        (void)snprintf(output, sizeof(output), "capture start rejected: %s\r\n",
                       esp_err_to_name(result));
        console_write(output);
        print_stats();
        return 1;
    }
    console_write("capture start requested; use capture-status for state\r\n");
    return 0;
}

static int cmd_capture_stop(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        console_write("usage: capture-stop\r\n");
        return 2;
    }
    sd_logger_stats_t before;
    sd_logger_get_stats(&before);
    if (before.state == SD_LOGGER_STOPPED || before.state == SD_LOGGER_DISABLED) {
        console_write("capture is already stopped\r\n");
        print_stats();
        return 0;
    }
    if (!sd_logger_request_stop() && before.state != SD_LOGGER_STOPPING) {
        console_write("capture stop request rejected\r\n");
        print_stats();
        return 1;
    }
    const sd_logger_wait_result_t result =
        sd_logger_wait_stopped(SD_LOGGER_STOP_WAIT_MS);
    if (result == SD_LOGGER_WAIT_PENDING) {
        console_write("STOPPING is still pending; logger still owns its buffers\r\n");
    } else if (result == SD_LOGGER_WAIT_ERROR) {
        console_write("capture stopped with ERROR\r\n");
    } else {
        console_write("capture stopped and drained\r\n");
    }
    print_stats();
    return result == SD_LOGGER_WAIT_STOPPED ? 0 : 1;
}

static int cmd_capture_status(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        console_write("usage: capture-status\r\n");
        return 2;
    }
    print_stats();
    return 0;
}

static char *next_console_token(char **cursor)
{
    if (cursor == NULL || *cursor == NULL) {
        return NULL;
    }
    char *at = *cursor;
    while (*at == ' ') {
        ++at;
    }
    if (*at == '\0') {
        *cursor = at;
        return NULL;
    }
    char *token = at;
    while (*at != '\0' && *at != ' ') {
        ++at;
    }
    if (*at != '\0') {
        *at++ = '\0';
    }
    *cursor = at;
    return token;
}

static void dispatch_export_info(char *line)
{
    char *cursor = line;
    const char *command = next_console_token(&cursor);
    const char *session_text = next_console_token(&cursor);
    const char *extra = next_console_token(&cursor);
    uint64_t session_id = 0u;
    if (command == NULL || strcmp(command, "capture-export-info") != 0 ||
        session_text == NULL || extra != NULL ||
        !valid_session_id(session_text, &session_id)) {
        console_write("usage: capture-export-info <16-hex-session-id>\r\n");
        return;
    }
    if (!serial_export_request(SERIAL_EXPORT_INFO, session_id, 0, 0u, 0u)) {
        console_write("serial export busy\r\n");
        return;
    }
    console_write("serial export info queued\r\n");
}

static void dispatch_export_file(char *line)
{
    char *cursor = line;
    const char *command = next_console_token(&cursor);
    const char *session_text = next_console_token(&cursor);
    const char *kind_text = next_console_token(&cursor);
    const char *index_text = next_console_token(&cursor);
    const char *offset_text = next_console_token(&cursor);
    const char *extra = next_console_token(&cursor);
    uint64_t session_id = 0u;
    uint64_t parsed_index = 0u;
    uint64_t offset = 0u;
    const char kind = kind_text != NULL && strcmp(kind_text, "pcap") == 0
                          ? 'P'
                          : kind_text != NULL && strcmp(kind_text, "summary") == 0
                                ? 'S' : 0;
    if (command == NULL || strcmp(command, "capture-export") != 0 ||
        session_text == NULL || kind == 0 || index_text == NULL ||
        offset_text == NULL || extra != NULL ||
        !valid_session_id(session_text, &session_id) ||
        !parse_u64_decimal(index_text, &parsed_index) || parsed_index > 15u ||
        !parse_u64_decimal(offset_text, &offset) ||
        (kind == 'S' && parsed_index != 0u)) {
        console_write("usage: capture-export <session-id> <pcap|summary> <index> <offset>\r\n");
        return;
    }
    if (!serial_export_request(SERIAL_EXPORT_FILE, session_id, kind,
                               (uint32_t)parsed_index, offset)) {
        console_write("serial export busy\r\n");
        return;
    }
    console_write("serial export read queued\r\n");
}

static void dispatch_console_line(char *line)
{
    if (strcmp(line, "capture-start") == 0) {
        (void)cmd_capture_start(1, NULL);
    } else if (strcmp(line, "capture-stop") == 0) {
        (void)cmd_capture_stop(1, NULL);
    } else if (strcmp(line, "capture-status") == 0) {
        (void)cmd_capture_status(1, NULL);
    } else if (strcmp(line, "help") == 0) {
        console_write("capture-start  start a new bounded PCAP session\r\n"
                      "capture-stop   drain, sync and close capture\r\n"
                      "capture-status show state and counters\r\n"
                      "capture-export-info <id> list one stopped session\r\n"
                      "capture-export <id> <pcap|summary> <index> <offset>\r\n");
    } else if (strncmp(line, "capture-export-info ",
                       sizeof("capture-export-info ") - 1u) == 0) {
        dispatch_export_info(line);
    } else if (strncmp(line, "capture-export ",
                       sizeof("capture-export ") - 1u) == 0) {
        dispatch_export_file(line);
    } else if (line[0] != '\0') {
        console_write("unknown command; type help\r\n");
    }
}

static void console_task(void *arg)
{
    (void)arg;
    char line[SD_LOGGER_CONSOLE_LINE_MAX];
    size_t used = 0u;
    bool overflow = false;
    bool swallow_lf = false;
    uint8_t input[32];
    console_write("\r\nPhase 3C capture controls ready; type help\r\ncapture> ");

    for (;;) {
        const int received = usb_serial_jtag_read_bytes(
            input, sizeof(input), pdMS_TO_TICKS(100u));
        if (received <= 0) {
            continue;
        }
        for (int i = 0; i < received; ++i) {
            if (atomic_load_explicit(&s_export_streaming,
                                     memory_order_acquire)) {
                used = 0u;
                overflow = false;
                swallow_lf = false;
                continue;
            }
            const uint8_t ch = input[i];
            if (swallow_lf) {
                swallow_lf = false;
                if (ch == '\n') {
                    continue;
                }
            }
            if (ch == '\r' || ch == '\n') {
                swallow_lf = (ch == '\r');
                console_write("\r\n");
                if (overflow) {
                    console_write("command too long\r\n");
                } else {
                    line[used] = '\0';
                    dispatch_console_line(line);
                }
                used = 0u;
                overflow = false;
                console_write("capture> ");
            } else if (ch == 0x08u || ch == 0x7fu) {
                if (used > 0u && !overflow) {
                    --used;
                    console_write("\b \b");
                }
            } else if (ch >= 0x20u && ch <= 0x7eu) {
                if (!overflow && used + 1u < sizeof(line)) {
                    line[used++] = (char)ch;
                    char echo[2] = { (char)ch, '\0' };
                    console_write(echo);
                } else {
                    overflow = true;
                }
            }
        }
    }
}

esp_err_t sd_logger_console_start(void)
{
    if (!s_initialized || s_console_task != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!s_log_wrapper_installed) {
        s_previous_vprintf = esp_log_set_vprintf(capture_log_vprintf);
        s_log_wrapper_installed = true;
    }
    const uint32_t heap_before =
        (uint32_t)heap_caps_get_free_size(MALLOC_CAP_8BIT);
    usb_serial_jtag_driver_config_t driver_config =
        USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    const bool driver_was_installed = usb_serial_jtag_is_driver_installed();
    if (!driver_was_installed) {
        const esp_err_t install_result =
            usb_serial_jtag_driver_install(&driver_config);
        if (install_result != ESP_OK) {
            return install_result;
        }
    }
    if (xTaskCreate(console_task, "capture_console", SD_LOGGER_CONSOLE_STACK,
                    NULL, 1u, &s_console_task) != pdPASS) {
        s_console_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG,
             "capture console ready heap_before=%u heap_after=%u min_heap=%u driver=%s stack=%u",
             (unsigned)heap_before,
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT),
             driver_was_installed ? "already-installed" : "installed",
             SD_LOGGER_CONSOLE_STACK);
    return ESP_OK;
}
