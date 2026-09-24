#include "sd_logger_core.h"

#include <stdio.h>
#include <string.h>

#include "ieee80211_parser.h"

#define SD_LOGGER_RETRY_COLLISIONS 32u
#define SD_LOGGER_SUMMARY_SIZE    768u

typedef enum {
    STEP_NONE = 0,
    STEP_ERROR,
    STEP_LIMIT,
} step_result_t;

static void lock_core(sd_logger_core_t *core)
{
    if (core->sync.lock != NULL) {
        core->sync.lock(core->sync.ctx);
    }
}

static void unlock_core(sd_logger_core_t *core)
{
    if (core->sync.unlock != NULL) {
        core->sync.unlock(core->sync.ctx);
    }
}

static void wake_worker(sd_logger_core_t *core)
{
    if (core->sync.wake_worker != NULL) {
        core->sync.wake_worker(core->sync.ctx);
    }
}

static void sat_add(uint64_t *value, uint64_t addend)
{
    if (UINT64_MAX - *value < addend) {
        *value = UINT64_MAX;
    } else {
        *value += addend;
    }
}

#define STAT_ADD(core, field, value) do { \
    lock_core(core); \
    sat_add(&(core)->stats.field, (value)); \
    unlock_core(core); \
} while (0)

static uint64_t elapsed_us(sd_logger_core_t *core, uint64_t started)
{
    const uint64_t finished = core->io.now_us(core->io.ctx);
    return finished >= started ? finished - started : 0u;
}

static void record_io_duration(sd_logger_core_t *core, uint64_t *maximum,
                               uint64_t duration_us)
{
    lock_core(core);
    if (duration_us > *maximum) {
        *maximum = duration_us;
    }
    if (duration_us >= SD_LOGGER_IO_SLOW_THRESHOLD_US) {
        sat_add(&core->stats.io_slow_count, 1u);
    }
    unlock_core(core);
}

static sd_logger_open_result_t open_new_timed(sd_logger_core_t *core,
                                               uint64_t session_id,
                                               uint32_t file_index,
                                               bool summary, char *path,
                                               size_t path_capacity,
                                               void **handle)
{
    const uint64_t started = core->io.now_us(core->io.ctx);
    const sd_logger_open_result_t result = core->io.open_new(
        core->io.ctx, session_id, file_index, summary, path, path_capacity,
        handle);
    record_io_duration(core, &core->stats.max_open_us, elapsed_us(core, started));
    return result;
}

static bool flush_sync_timed(sd_logger_core_t *core, void *handle)
{
    const uint64_t started = core->io.now_us(core->io.ctx);
    const bool result = core->io.flush_sync(core->io.ctx, handle);
    record_io_duration(core, &core->stats.max_flush_us,
                       elapsed_us(core, started));
    return result;
}

static bool close_timed(sd_logger_core_t *core, void *handle)
{
    const uint64_t started = core->io.now_us(core->io.ctx);
    const bool result = core->io.close(core->io.ctx, handle);
    record_io_duration(core, &core->stats.max_close_us,
                       elapsed_us(core, started));
    return result;
}

static void set_state(sd_logger_core_t *core, sd_logger_state_t state,
                      bool accepting)
{
    lock_core(core);
    core->state = state;
    core->accepting = accepting;
    core->stats.state = state;
    core->stats.accepting = accepting;
    unlock_core(core);
}

const char *sd_logger_state_name(sd_logger_state_t state)
{
    switch (state) {
    case SD_LOGGER_DISABLED: return "DISABLED";
    case SD_LOGGER_STARTING: return "STARTING";
    case SD_LOGGER_RECORDING: return "RECORDING";
    case SD_LOGGER_STOPPING: return "STOPPING";
    case SD_LOGGER_STOPPED: return "STOPPED";
    case SD_LOGGER_ERROR: return "ERROR";
    default: return "UNKNOWN";
    }
}

const char *sd_logger_state_short_name(sd_logger_state_t state)
{
    switch (state) {
    case SD_LOGGER_DISABLED: return "NO CARD";
    case SD_LOGGER_STARTING: return "START";
    case SD_LOGGER_RECORDING: return "REC";
    case SD_LOGGER_STOPPING: return "STOP";
    case SD_LOGGER_STOPPED: return "IDLE";
    case SD_LOGGER_ERROR: return "ERR";
    default: return "?";
    }
}

static void baseline_session_counters(sd_logger_core_t *core)
{
    lock_core(core);
    core->session_baseline = core->stats;
    unlock_core(core);
}

void sd_logger_core_init(sd_logger_core_t *core, const sd_logger_io_t *io,
                         const sd_logger_sync_t *sync, bool media_mounted)
{
    if (core == NULL) {
        return;
    }
    memset(core, 0, sizeof(*core));
    if (io != NULL) {
        core->io = *io;
    }
    if (sync != NULL) {
        core->sync = *sync;
    }
    core->state = media_mounted ? SD_LOGGER_STOPPED : SD_LOGGER_DISABLED;
    core->stats.state = core->state;
}

bool sd_logger_core_request_start(sd_logger_core_t *core, uint64_t session_id,
                                  uint64_t monotonic_now_us,
                                  const char *firmware_sha)
{
    if (core == NULL || core->io.open_new == NULL || core->io.write == NULL ||
        core->io.flush_sync == NULL || core->io.close == NULL ||
        core->io.now_us == NULL) {
        return false;
    }

    lock_core(core);
    const bool can_start = (core->state == SD_LOGGER_DISABLED ||
                            core->state == SD_LOGGER_STOPPED ||
                            core->state == SD_LOGGER_ERROR) &&
                           !core->start_pending &&
                           !core->error_cleanup_pending && !core->pcap_open &&
                           !core->summary_open && core->count == 0u &&
                           core->reserved_count == 0u;
    if (!can_start) {
        unlock_core(core);
        return false;
    }

    core->session_id = session_id;
    core->session_anchor_rx_us = monotonic_now_us;
    core->session_start_us = monotonic_now_us;
    core->file_open_us = 0;
    core->last_flush_us = monotonic_now_us;
    core->file_index = 0;
    core->session_pcap_bytes = 0;
    core->current_file_bytes = 0;
    core->batch_length = 0;
    core->batch_record_count = 0;
    core->pending_flush_records = 0;
    core->limit_reached = false;
    core->stop_requested = false;
    core->pcap_incomplete = false;
    core->summary_incomplete = false;
    memset(&core->serializer_stats, 0, sizeof(core->serializer_stats));
    memset(core->current_path, 0, sizeof(core->current_path));
    memset(core->summary_path, 0, sizeof(core->summary_path));
    memset(core->firmware_sha, 0, sizeof(core->firmware_sha));
    if (firmware_sha != NULL) {
        size_t n = strlen(firmware_sha);
        if (n > SD_LOGGER_FW_SHA_MAX) {
            n = SD_LOGGER_FW_SHA_MAX;
        }
        memcpy(core->firmware_sha, firmware_sha, n);
    }
    core->start_pending = true;
    core->state = SD_LOGGER_STARTING;
    core->accepting = false;
    core->stats.state = SD_LOGGER_STARTING;
    core->stats.accepting = false;
    core->stats.limit_reached = false;
    core->stats.max_open_us = 0;
    core->stats.max_write_us = 0;
    core->stats.max_flush_us = 0;
    core->stats.max_close_us = 0;
    core->stats.session_id = session_id;
    core->stats.session_anchor_rx_us = monotonic_now_us;
    core->stats.session_start_us = monotonic_now_us;
    core->stats.file_index = 0;
    memset(core->stats.current_path, 0, sizeof(core->stats.current_path));
    memset(core->stats.summary_path, 0, sizeof(core->stats.summary_path));
    core->session_baseline = core->stats;
    unlock_core(core);
    wake_worker(core);
    return true;
}

bool sd_logger_core_request_stop(sd_logger_core_t *core)
{
    if (core == NULL) {
        return false;
    }
    lock_core(core);
    if (core->state == SD_LOGGER_STARTING) {
        /* A stop queued during startup is completed after the header opens. */
        core->stop_requested = true;
        unlock_core(core);
        wake_worker(core);
        return true;
    }
    if (core->state != SD_LOGGER_RECORDING || !core->accepting) {
        unlock_core(core);
        return false;
    }
    core->accepting = false;
    core->stop_requested = true;
    core->state = SD_LOGGER_STOPPING;
    core->stats.accepting = false;
    core->stats.state = SD_LOGGER_STOPPING;
    unlock_core(core);
    wake_worker(core);
    return true;
}

static bool raw_capture_minimum(const radio_packet_t *packet,
                                uint16_t *mac_header_length)
{
    if (packet == NULL || packet->length < 2u ||
        packet->length > RADIO_PACKET_MAX_LEN ||
        packet->orig_length < 4u || packet->length > packet->orig_length) {
        return false;
    }

    const uint16_t fc = (uint16_t)packet->data[0] |
                        ((uint16_t)packet->data[1] << 8);
    const uint8_t frame_type = (uint8_t)((fc & IEEE80211_FC_TYPE_MASK) >>
                                         IEEE80211_FC_TYPE_SHIFT);
    const uint8_t subtype = (uint8_t)((fc & IEEE80211_FC_SUBTYPE_MASK) >>
                                      IEEE80211_FC_SUBTYPE_SHIFT);
    if (frame_type != packet->packet_type ||
        frame_type > IEEE80211_FC_TYPE_VALUE_DATA) {
        return false;
    }

    uint16_t min_header = 0;
    if (frame_type == IEEE80211_FC_TYPE_VALUE_MGMT) {
        min_header = IEEE80211_MGMT_HDR_LEN;
    } else if (frame_type == IEEE80211_FC_TYPE_VALUE_CTRL) {
        /* ACK and CTS end after addr1; all other supported control forms
         * need at least the duration plus receiver and transmitter fields. */
        min_header = (subtype == IEEE80211_CTRL_CTS ||
                      subtype == IEEE80211_CTRL_ACK) ? 10u : 16u;
    } else {
        min_header = 24u;
        if (subtype >= IEEE80211_DATA_QOS_DATA &&
            subtype <= IEEE80211_DATA_QOS_NULL) {
            min_header += 2u;
            if ((fc & IEEE80211_FC_ORDER_MASK) != 0u) {
                min_header += 4u;
            }
        }
    }

    rx_capture_view_t view;
    if (!rx_path_make_capture_view(packet, &view) ||
        !view.original_mac_length_valid ||
        view.original_mac_length < min_header ||
        view.captured_mac_length < min_header) {
        return false;
    }
    if (mac_header_length != NULL) {
        *mac_header_length = min_header;
    }
    return true;
}

static void count_rejection(sd_logger_core_t *core, bool filtered)
{
    lock_core(core);
    if (filtered) {
        sat_add(&core->stats.filtered_non_data, 1u);
    } else {
        sat_add(&core->stats.rejected_invalid, 1u);
    }
    unlock_core(core);
}

static void count_drop(sd_logger_core_t *core, uint64_t *reason_counter)
{
    lock_core(core);
    sat_add(&core->stats.storage_drop, 1u);
    sat_add(reason_counter, 1u);
    unlock_core(core);
}

bool sd_logger_core_try_submit(sd_logger_core_t *core,
                               const radio_packet_t *packet)
{
    if (core == NULL || packet == NULL) {
        if (core != NULL) {
            count_rejection(core, false);
        }
        return false;
    }
    if (packet->packet_type > RX_PATH_TYPE_DATA) {
        count_rejection(core, true);
        return false;
    }
    if (!raw_capture_minimum(packet, NULL)) {
        count_rejection(core, false);
        return false;
    }

    uint8_t slot = SD_LOGGER_POOL_SIZE;
    lock_core(core);
    if (!core->accepting || core->state != SD_LOGGER_RECORDING) {
        sat_add(&core->stats.storage_drop, 1u);
        sat_add(&core->stats.drop_not_recording, 1u);
        unlock_core(core);
        return false;
    }
    for (uint8_t i = 0; i < SD_LOGGER_POOL_SIZE; ++i) {
        if (core->slot_state[i] == SD_LOGGER_SLOT_FREE) {
            slot = i;
            core->slot_state[i] = SD_LOGGER_SLOT_RESERVED;
            core->reserved_count++;
            break;
        }
    }
    if (slot == SD_LOGGER_POOL_SIZE || core->count >= SD_LOGGER_POOL_SIZE) {
        if (slot != SD_LOGGER_POOL_SIZE) {
            core->slot_state[slot] = SD_LOGGER_SLOT_FREE;
            core->reserved_count--;
        }
        sat_add(&core->stats.storage_drop, 1u);
        sat_add(&core->stats.drop_queue_full, 1u);
        unlock_core(core);
        return false;
    }
    unlock_core(core);

    /* The bounded copy is outside the critical section; no writer or radio
     * pool memory is shared with the logger task. */
    core->packets[slot] = *packet;

    lock_core(core);
    core->slot_state[slot] = SD_LOGGER_SLOT_QUEUED;
    if (core->error_cleanup_pending || core->state == SD_LOGGER_ERROR ||
        core->state == SD_LOGGER_STOPPED ||
        core->state == SD_LOGGER_DISABLED) {
        core->slot_state[slot] = SD_LOGGER_SLOT_FREE;
        core->reserved_count--;
        sat_add(&core->stats.storage_drop, 1u);
        sat_add(&core->stats.drop_io, 1u);
        unlock_core(core);
        wake_worker(core);
        return false;
    }
    core->queue[core->tail] = slot;
    core->tail = (uint8_t)((core->tail + 1u) % SD_LOGGER_POOL_SIZE);
    core->count++;
    core->reserved_count--;
    sat_add(&core->stats.accepted, 1u);
    core->stats.queue_depth = core->count;
    if (core->count > core->stats.queue_peak) {
        core->stats.queue_peak = core->count;
    }
    unlock_core(core);
    wake_worker(core);
    return true;
}

static bool write_full(sd_logger_core_t *core, void *handle,
                       const uint8_t *bytes, size_t length, bool pcap)
{
    size_t offset = 0;
    while (offset < length) {
        bool error = false;
        bool storage_full = false;
        const uint64_t started = core->io.now_us(core->io.ctx);
        const size_t count = core->io.write(core->io.ctx, handle,
                                            bytes + offset, length - offset,
                                            &error, &storage_full);
        record_io_duration(core, &core->stats.max_write_us,
                           elapsed_us(core, started));
        if (count > (length - offset)) {
            return false;
        }
        if (count > 0u) {
            if (count < length - offset) {
                STAT_ADD(core, short_writes, 1u);
            }
            offset += count;
            if (pcap) {
                STAT_ADD(core, pcap_bytes, count);
            }
        }
        if (storage_full) {
            STAT_ADD(core, storage_full_errors, 1u);
        }
        if (error || count == 0u) {
            return false;
        }
    }
    return true;
}

static bool create_new_file(sd_logger_core_t *core, uint32_t *index,
                            bool summary, void **handle, char *path)
{
    for (uint32_t attempt = 0; attempt < SD_LOGGER_RETRY_COLLISIONS; ++attempt) {
        const sd_logger_open_result_t result = open_new_timed(
            core, core->session_id, *index, summary, path,
            SD_LOGGER_PATH_MAX, handle);
        if (result == SD_LOGGER_OPEN_OK && *handle != NULL) {
            return true;
        }
        if (result != SD_LOGGER_OPEN_EXISTS) {
            return false;
        }
        STAT_ADD(core, filename_collisions, 1u);
        if (*index == UINT32_MAX) {
            return false;
        }
        ++*index;
    }
    return false;
}

static bool open_next_pcap(sd_logger_core_t *core, bool first_file)
{
    uint32_t index = first_file ? 0u : core->file_index + 1u;
    if (!first_file && index == 0u) {
        return false;
    }
    void *handle = NULL;
    char path[SD_LOGGER_PATH_MAX] = {0};
    if (!create_new_file(core, &index, false, &handle, path)) {
        return false;
    }

    uint8_t header[PCAP_SERIALIZER_FILE_HEADER_LEN];
    size_t header_length = 0;
    if (!pcap_serializer_write_global_header(header, sizeof(header),
                                             &header_length) ||
        !write_full(core, handle, header, header_length, true) ||
        !flush_sync_timed(core, handle)) {
        (void)close_timed(core, handle);
        core->pcap_incomplete = true;
        STAT_ADD(core, files_incomplete, 1u);
        return false;
    }

    core->pcap_handle = handle;
    core->pcap_open = true;
    core->file_index = index;
    core->current_file_bytes = header_length;
    core->session_pcap_bytes += header_length;
    core->file_open_us = core->io.now_us(core->io.ctx);
    strncpy(core->current_path, path, sizeof(core->current_path) - 1u);
    core->current_path[sizeof(core->current_path) - 1u] = '\0';
    lock_core(core);
    core->stats.current_path[0] = '\0';
    strncpy(core->stats.current_path, path,
            sizeof(core->stats.current_path) - 1u);
    core->stats.current_path[sizeof(core->stats.current_path) - 1u] = '\0';
    core->stats.file_index = index;
    unlock_core(core);
    return true;
}

static bool flush_batch(sd_logger_core_t *core, bool sync)
{
    if (core->batch_length > 0u) {
        if (!core->pcap_open ||
            !write_full(core, core->pcap_handle, core->batch,
                        core->batch_length, true)) {
            core->pcap_incomplete = true;
            STAT_ADD(core, files_incomplete, 1u);
            return false;
        }
        STAT_ADD(core, written, core->batch_record_count);
        core->pending_flush_records += core->batch_record_count;
        core->batch_length = 0;
        core->batch_record_count = 0;
    }

    if (sync && core->pcap_open) {
        if (!flush_sync_timed(core, core->pcap_handle)) {
            return false;
        }
        STAT_ADD(core, flushed, core->pending_flush_records);
        core->pending_flush_records = 0;
        core->last_flush_us = core->io.now_us(core->io.ctx);
    }
    return true;
}

static bool close_pcap(sd_logger_core_t *core, bool incomplete_on_failure)
{
    if (!core->pcap_open) {
        return true;
    }
    void *handle = core->pcap_handle;
    core->pcap_handle = NULL;
    core->pcap_open = false;
    const bool ok = close_timed(core, handle);
    if (!ok && incomplete_on_failure) {
        core->pcap_incomplete = true;
        STAT_ADD(core, files_incomplete, 1u);
    }
    return ok;
}

static bool rotate_pcap(sd_logger_core_t *core)
{
    if (!flush_batch(core, true) || !close_pcap(core, true)) {
        return false;
    }
    if (!open_next_pcap(core, false)) {
        return false;
    }
    STAT_ADD(core, file_rotations, 1u);
    return true;
}

static uint64_t session_delta(uint64_t current, uint64_t base)
{
    return current >= base ? current - base : 0u;
}

static bool write_summary(sd_logger_core_t *core)
{
    if (!core->summary_open || core->summary_handle == NULL ||
        core->summary_incomplete) {
        return true;
    }
    sd_logger_stats_t now;
    sd_logger_core_get_stats(core, &now);
    const sd_logger_stats_t *base = &core->session_baseline;
    char summary[SD_LOGGER_SUMMARY_SIZE];
    const int length = snprintf(summary, sizeof(summary),
        "format=pcap-2.4-linktype-127\n"
        "firmware_sha=%s\n"
        "session_id=%016llX\n"
        "time_basis=monotonic_delta_from_rx_anchor;epoch_anchor_us=0;not_utc\n"
        "rx_anchor_us=%llu\n"
        "snaplen=%u\n"
        "fcs=omitted;driver_length_includes_fcs;partial_fcs_not_subtracted_twice\n"
        "filter=MGMT_CTRL_DATA_with_complete_minimum_MAC_header;raw_capture_before_semantic_parse\n"
        "accepted=%llu\nserialized=%llu\nwritten=%llu\nflushed=%llu\n"
        "storage_drop=%llu;queue_full=%llu;not_recording=%llu;io=%llu;limit=%llu\n"
        "pre_session_timestamp=%llu\n"
        "invalid_rejected=%llu\nfiltered_non_data=%llu\nshort_writes=%llu\n"
        "io_errors=%llu\nstorage_full_errors=%llu\npcap_bytes=%llu\n"
        "io_max_open_us=%llu\nio_max_write_us=%llu\nio_max_flush_us=%llu\n"
        "io_max_close_us=%llu\nio_slow_count=%llu\n"
        "rotations=%llu\nfilename_collisions=%llu\n"
        "incomplete_files=%llu\nlimit_reached=%u\n",
        core->firmware_sha,
        (unsigned long long)core->session_id,
        (unsigned long long)core->session_anchor_rx_us,
        (unsigned)PCAP_SERIALIZER_SNAPLEN,
        (unsigned long long)session_delta(now.accepted, base->accepted),
        (unsigned long long)session_delta(now.serialized, base->serialized),
        (unsigned long long)session_delta(now.written, base->written),
        (unsigned long long)session_delta(now.flushed, base->flushed),
        (unsigned long long)session_delta(now.storage_drop, base->storage_drop),
        (unsigned long long)session_delta(now.drop_queue_full, base->drop_queue_full),
        (unsigned long long)session_delta(now.drop_not_recording, base->drop_not_recording),
        (unsigned long long)session_delta(now.drop_io, base->drop_io),
        (unsigned long long)session_delta(now.drop_limit, base->drop_limit),
        (unsigned long long)session_delta(now.drop_pre_session,
                                          base->drop_pre_session),
        (unsigned long long)session_delta(now.rejected_invalid, base->rejected_invalid),
        (unsigned long long)session_delta(now.filtered_non_data, base->filtered_non_data),
        (unsigned long long)session_delta(now.short_writes, base->short_writes),
        (unsigned long long)session_delta(now.io_errors, base->io_errors),
        (unsigned long long)session_delta(now.storage_full_errors,
                                          base->storage_full_errors),
        (unsigned long long)session_delta(now.pcap_bytes, base->pcap_bytes),
        (unsigned long long)now.max_open_us,
        (unsigned long long)now.max_write_us,
        (unsigned long long)now.max_flush_us,
        (unsigned long long)now.max_close_us,
        (unsigned long long)session_delta(now.io_slow_count,
                                          base->io_slow_count),
        (unsigned long long)session_delta(now.file_rotations, base->file_rotations),
        (unsigned long long)session_delta(now.filename_collisions, base->filename_collisions),
        (unsigned long long)session_delta(now.files_incomplete, base->files_incomplete),
        now.limit_reached ? 1u : 0u);
    if (length < 0 || (size_t)length >= sizeof(summary)) {
        return false;
    }
    if (!write_full(core, core->summary_handle, (const uint8_t *)summary,
                    (size_t)length, false) ||
        !flush_sync_timed(core, core->summary_handle)) {
        core->summary_incomplete = true;
        return false;
    }
    void *handle = core->summary_handle;
    core->summary_handle = NULL;
    core->summary_open = false;
    const bool closed = close_timed(core, handle);
    core->summary_incomplete = !closed;
    return closed;
}

static void close_summary_best_effort(sd_logger_core_t *core)
{
    if (core->summary_open) {
        void *handle = core->summary_handle;
        core->summary_handle = NULL;
        core->summary_open = false;
        (void)close_timed(core, handle);
    }
}

static void fail_session(sd_logger_core_t *core, bool io_drop)
{
    lock_core(core);
    core->error_cleanup_pending = true;
    core->state = SD_LOGGER_STOPPING;
    core->accepting = false;
    core->stats.state = SD_LOGGER_STOPPING;
    core->stats.accepting = false;
    unlock_core(core);
    STAT_ADD(core, io_errors, 1u);
    if (core->batch_record_count > 0u) {
        if (io_drop) {
            STAT_ADD(core, storage_drop, core->batch_record_count);
            STAT_ADD(core, drop_io, core->batch_record_count);
        }
        core->batch_record_count = 0;
        core->batch_length = 0;
    }
    if (core->pcap_open) {
        (void)close_pcap(core, true);
    }
    lock_core(core);
    while (core->count > 0u) {
        const uint8_t slot = core->queue[core->head];
        core->head = (uint8_t)((core->head + 1u) % SD_LOGGER_POOL_SIZE);
        core->count--;
        core->slot_state[slot] = SD_LOGGER_SLOT_FREE;
        sat_add(&core->stats.storage_drop, 1u);
        sat_add(&core->stats.drop_io, 1u);
    }
    core->stats.queue_depth = 0;
    for (uint8_t i = 0; i < SD_LOGGER_POOL_SIZE; ++i) {
        if (core->slot_state[i] == SD_LOGGER_SLOT_WRITING) {
            core->slot_state[i] = SD_LOGGER_SLOT_FREE;
        }
    }
    core->stats.limit_reached = core->limit_reached;
    unlock_core(core);
    /* Preserve a best-effort session summary after write/flush/close errors. */
    if (core->summary_incomplete || !write_summary(core)) {
        close_summary_best_effort(core);
    }
    lock_core(core);
    core->error_cleanup_pending = false;
    core->state = SD_LOGGER_ERROR;
    core->stats.state = SD_LOGGER_ERROR;
    core->stats.accepting = false;
    unlock_core(core);
}

static bool open_session(sd_logger_core_t *core)
{
    bool summary_ready = false;
    for (uint32_t attempt = 0; attempt < SD_LOGGER_RETRY_COLLISIONS; ++attempt) {
        char path[SD_LOGGER_PATH_MAX] = {0};
        void *handle = NULL;
        const uint64_t original_id = core->session_id;
        const sd_logger_open_result_t result = open_new_timed(
            core, core->session_id, 0u, true, path, sizeof(path), &handle);
        if (result == SD_LOGGER_OPEN_OK && handle != NULL) {
            core->summary_handle = handle;
            core->summary_open = true;
            strncpy(core->summary_path, path, sizeof(core->summary_path) - 1u);
            core->summary_path[sizeof(core->summary_path) - 1u] = '\0';
            lock_core(core);
            strncpy(core->stats.summary_path, path,
                    sizeof(core->stats.summary_path) - 1u);
            core->stats.summary_path[sizeof(core->stats.summary_path) - 1u] = '\0';
            unlock_core(core);
            summary_ready = true;
            break;
        }
        if (result != SD_LOGGER_OPEN_EXISTS) {
            break;
        }
        STAT_ADD(core, filename_collisions, 1u);
        lock_core(core);
        core->session_id = original_id + UINT64_C(0x9e3779b97f4a7c15);
        if (core->session_id == original_id) {
            ++core->session_id;
        }
        core->stats.session_id = core->session_id;
        unlock_core(core);
    }
    if (!summary_ready || !open_next_pcap(core, true)) {
        close_summary_best_effort(core);
        return false;
    }

    core->last_flush_us = core->io.now_us(core->io.ctx);
    lock_core(core);
    const bool stop_after_start = core->stop_requested;
    core->stats.state = stop_after_start ? SD_LOGGER_STOPPING
                                         : SD_LOGGER_RECORDING;
    core->stats.accepting = !stop_after_start;
    core->state = stop_after_start ? SD_LOGGER_STOPPING
                                   : SD_LOGGER_RECORDING;
    core->accepting = !stop_after_start;
    core->stats.session_id = core->session_id;
    core->stats.session_anchor_rx_us = core->session_anchor_rx_us;
    core->stats.session_start_us = core->session_start_us;
    core->stats.file_index = core->file_index;
    unlock_core(core);
    return true;
}

static step_result_t process_packet(sd_logger_core_t *core, uint8_t slot)
{
    radio_packet_t *packet = &core->packets[slot];
    if (core->limit_reached) {
        count_drop(core, &core->stats.drop_limit);
        return STEP_LIMIT;
    }

    /* The radio queue may contain frames received before this recording was
     * opened. Keep their original timestamps, but omit them rather than
     * feeding a pre-anchor value to the serializer and failing the session. */
    if (packet->rx_timestamp_us < core->session_anchor_rx_us) {
        count_drop(core, &core->stats.drop_pre_session);
        return STEP_NONE;
    }

    rx_capture_view_t view;
    if (!rx_path_make_capture_view(packet, &view)) {
        return STEP_ERROR;
    }
    size_t record_length = 0;
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    const pcap_time_anchor_t anchor = {
        .monotonic_anchor_us = core->session_anchor_rx_us,
        .epoch_anchor_us = 0,
    };
    if (!pcap_serializer_encode_record(&view, &anchor, core->record_scratch,
                                       sizeof(core->record_scratch),
                                       &record_length, &core->serializer_stats,
                                       &reason)) {
        (void)reason;
        return STEP_ERROR;
    }
    STAT_ADD(core, serialized, 1u);

    const uint64_t now = core->io.now_us(core->io.ctx);
    const bool age_rotate = core->current_file_bytes >
                                PCAP_SERIALIZER_FILE_HEADER_LEN &&
                            now >= core->file_open_us &&
                            now - core->file_open_us >= SD_LOGGER_MAX_FILE_AGE_US;
    const bool size_rotate = record_length > SD_LOGGER_MAX_FILE_BYTES ||
        core->current_file_bytes + record_length > SD_LOGGER_MAX_FILE_BYTES;
    const bool rotate = age_rotate || size_rotate;
    const uint64_t extra_header = rotate ? PCAP_SERIALIZER_FILE_HEADER_LEN : 0u;
    const uint64_t total_after = core->session_pcap_bytes + record_length +
                                 extra_header;
    if (total_after > SD_LOGGER_SESSION_MAX_BYTES) {
        core->limit_reached = true;
        lock_core(core);
        core->stats.limit_reached = true;
        core->stats.accepting = false;
        core->stats.state = SD_LOGGER_STOPPING;
        core->state = SD_LOGGER_STOPPING;
        core->accepting = false;
        core->stop_requested = true;
        unlock_core(core);
        count_drop(core, &core->stats.drop_limit);
        return STEP_LIMIT;
    }

    if (rotate && !rotate_pcap(core)) {
        return STEP_ERROR;
    }

    if (record_length > SD_LOGGER_BATCH_SIZE) {
        return STEP_ERROR;
    }
    if (core->batch_length + record_length > SD_LOGGER_BATCH_SIZE &&
        !flush_batch(core, false)) {
        return STEP_ERROR;
    }
    memcpy(core->batch + core->batch_length, core->record_scratch,
           record_length);
    core->current_packet_appended = true;
    core->batch_length += record_length;
    core->batch_record_count++;
    core->current_file_bytes += record_length;
    core->session_pcap_bytes += record_length;
    if (core->batch_length == SD_LOGGER_BATCH_SIZE && !flush_batch(core, false)) {
        return STEP_ERROR;
    }
    return STEP_NONE;
}

static bool finalize_session(sd_logger_core_t *core)
{
    if (!flush_batch(core, true) || !close_pcap(core, true)) {
        return false;
    }
    if (!write_summary(core)) {
        return false;
    }
    lock_core(core);
    core->state = SD_LOGGER_STOPPED;
    core->accepting = false;
    core->stop_requested = false;
    core->stats.state = SD_LOGGER_STOPPED;
    core->stats.accepting = false;
    core->stats.limit_reached = core->limit_reached;
    unlock_core(core);
    return true;
}

bool sd_logger_core_process_one(sd_logger_core_t *core)
{
    if (core == NULL) {
        return false;
    }

    lock_core(core);
    const bool start_pending = core->start_pending;
    if (start_pending) {
        core->start_pending = false;
    }
    unlock_core(core);
    if (start_pending) {
        baseline_session_counters(core);
        if (!open_session(core)) {
            fail_session(core, false);
            return true;
        }
        return true;
    }

    uint8_t slot = SD_LOGGER_POOL_SIZE;
    lock_core(core);
    if (core->count > 0u) {
        slot = core->queue[core->head];
        core->head = (uint8_t)((core->head + 1u) % SD_LOGGER_POOL_SIZE);
        core->count--;
        core->slot_state[slot] = SD_LOGGER_SLOT_WRITING;
        core->stats.queue_depth = core->count;
    }
    const bool stopping = core->state == SD_LOGGER_STOPPING &&
                          core->count == 0u && core->reserved_count == 0u;
    const bool accepting = core->accepting;
    unlock_core(core);

    if (slot < SD_LOGGER_POOL_SIZE) {
        core->current_packet_appended = false;
        const step_result_t result = process_packet(core, slot);
        bool release_slot = true;
        if (result == STEP_ERROR) {
            if (!core->current_packet_appended) {
                count_drop(core, &core->stats.drop_io);
            }
            fail_session(core, true);
            release_slot = false; /* fail_session freed every writer-owned slot */
        }
        if (release_slot) {
            lock_core(core);
            core->slot_state[slot] = SD_LOGGER_SLOT_FREE;
            unlock_core(core);
        }
        return true;
    }

    const uint64_t now = core->io.now_us(core->io.ctx);
    if (accepting && (core->batch_length > 0u ||
                      core->pending_flush_records > 0u) &&
        now >= core->last_flush_us &&
        now - core->last_flush_us >= SD_LOGGER_FLUSH_PERIOD_US) {
        if (!flush_batch(core, true)) {
            fail_session(core, true);
        }
        return true;
    }
    if (stopping) {
        if (!finalize_session(core)) {
            fail_session(core, true);
        }
        return true;
    }
    return false;
}

void sd_logger_core_get_stats(sd_logger_core_t *core,
                              sd_logger_stats_t *out)
{
    if (core == NULL || out == NULL) {
        return;
    }
    lock_core(core);
    *out = core->stats;
    out->queue_depth = core->count;
    out->state = core->state;
    out->accepting = core->accepting;
    out->session_id = core->session_id;
    out->session_anchor_rx_us = core->session_anchor_rx_us;
    out->session_start_us = core->session_start_us;
    out->file_index = core->file_index;
    unlock_core(core);
}
