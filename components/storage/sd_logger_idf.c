#include "sd_logger.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "board_sd.h"
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

static bool ensure_mounted(void)
{
    if (board_sd_is_mounted()) {
        return true;
    }
    const esp_err_t result = board_sd_init();
    if (result != ESP_OK) {
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
        return errno == EEXIST ? SD_LOGGER_OPEN_EXISTS : SD_LOGGER_OPEN_ERROR;
    }
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        const int saved_errno = errno;
        (void)close(fd);
        (void)unlink(path); /* only this call's O_EXCL-created empty file */
        ESP_LOGE(TAG, "fdopen failed errno=%d", saved_errno);
        return SD_LOGGER_OPEN_ERROR;
    }
    /* The producer already batches to 4 KiB; avoid an extra stdio payload
     * buffer. The logger's core buffer is the sole batch owner. */
    if (setvbuf(file, NULL, _IONBF, 0) != 0) {
        (void)fclose(file);
        (void)unlink(path);
        return SD_LOGGER_OPEN_ERROR;
    }
    *handle = file;
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
        ESP_LOGE(TAG, "fwrite failed errno=%d", saved_errno);
    }
    return written;
}

static bool io_flush_sync(void *ctx, void *handle)
{
    (void)ctx;
    FILE *file = (FILE *)handle;
    if (file == NULL || fflush(file) != 0 || ferror(file) != 0) {
        return false;
    }
    const int fd = fileno(file);
    return fd >= 0 && fsync(fd) == 0;
}

static bool io_close(void *ctx, void *handle)
{
    (void)ctx;
    return handle != NULL && fclose((FILE *)handle) == 0;
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
    if (!s_initialized) {
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
    if (!s_initialized) {
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

static void print_stats(void)
{
    sd_logger_stats_t stats;
    char output[512];
    sd_logger_get_stats(&stats);
    (void)snprintf(output, sizeof(output),
                   "state=%s accepted=%" PRIu64 " serialized=%" PRIu64
                   " written=%" PRIu64 " flushed=%" PRIu64
                   " storage_drop=%" PRIu64 " queue_full=%" PRIu64
                   " old_rx=%" PRIu64
                   " io_drop=%" PRIu64 " full=%" PRIu64 " io_errors=%" PRIu64
                   " limit=%u rotations=%" PRIu64 " invalid=%" PRIu64
                   " filtered=%" PRIu64 " queue=%u/%u session=%016" PRIX64
                   " max_io_us=%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
                   " slow=%" PRIu64
                   " file=%s summary=%s\r\n",
                   sd_logger_state_name(stats.state), stats.accepted, stats.serialized,
                   stats.written, stats.flushed, stats.storage_drop,
                   stats.drop_queue_full, stats.drop_pre_session, stats.drop_io,
                   stats.storage_full_errors,
                   stats.io_errors,
                   stats.limit_reached ? 1u : 0u, stats.file_rotations,
                   stats.rejected_invalid, stats.filtered_non_data,
                   (unsigned)stats.queue_depth,
                   (unsigned)stats.queue_peak, stats.session_id,
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
                      "capture-status show state and counters\r\n");
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
