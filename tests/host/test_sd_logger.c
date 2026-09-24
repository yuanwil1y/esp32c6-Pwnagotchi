#define _POSIX_C_SOURCE 200809L

#include "sd_logger_core.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "runner.h"
#include "ieee80211_parser.h"

#define MOCK_FILES 32u
#define MOCK_FILE_BYTES 4096u

typedef struct {
    bool used;
    bool summary;
    bool closed;
    uint64_t session_id;
    uint32_t index;
    size_t length;
    uint8_t data[MOCK_FILE_BYTES];
} mock_file_t;

typedef struct {
    mock_file_t files[MOCK_FILES];
    uint64_t now_us;
    uint32_t open_calls;
    uint32_t write_calls;
    uint32_t flush_calls;
    uint32_t close_calls;
    uint32_t short_limit;
    size_t fail_at_length;
    bool block_write;
    bool fail_write;
    bool full_card;
    bool fail_flush;
    bool fail_close_pcap;
    bool fail_open;
    bool fail_summary_open;
    bool collide_summary_once;
    uint64_t collision_session_id;
    bool collide_file_zero_once;
} mock_io_t;

static sd_logger_core_t s_core;
static mock_io_t s_mock;
static pthread_mutex_t s_writer_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t s_core_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_writer_cond = PTHREAD_COND_INITIALIZER;
static bool s_writer_blocked;
static bool s_writer_release;

static void mock_core_lock(void *ctx)
{
    (void)ctx;
    (void)pthread_mutex_lock(&s_core_mutex);
}

static void mock_core_unlock(void *ctx)
{
    (void)ctx;
    (void)pthread_mutex_unlock(&s_core_mutex);
}

static void mock_wake_worker(void *ctx)
{
    (void)ctx;
}

static sd_logger_open_result_t mock_open(void *ctx, uint64_t session_id,
                                         uint32_t file_index, bool summary,
                                         char *path, size_t path_capacity,
                                         void **handle)
{
    mock_io_t *mock = (mock_io_t *)ctx;
    mock->open_calls++;
    *handle = NULL;
    if (mock->fail_open || (summary && mock->fail_summary_open)) {
        return SD_LOGGER_OPEN_ERROR;
    }
    if (summary && mock->collide_summary_once &&
        session_id == mock->collision_session_id) {
        mock->collide_summary_once = false;
        return SD_LOGGER_OPEN_EXISTS;
    }
    if (!summary && file_index == 0u && mock->collide_file_zero_once) {
        mock->collide_file_zero_once = false;
        return SD_LOGGER_OPEN_EXISTS;
    }
    for (size_t i = 0; i < MOCK_FILES; ++i) {
        mock_file_t *file = &mock->files[i];
        if (file->used && file->session_id == session_id &&
            file->index == file_index && file->summary == summary) {
            return SD_LOGGER_OPEN_EXISTS;
        }
    }
    for (size_t i = 0; i < MOCK_FILES; ++i) {
        mock_file_t *file = &mock->files[i];
        if (!file->used) {
            memset(file, 0, sizeof(*file));
            file->used = true;
            file->summary = summary;
            file->session_id = session_id;
            file->index = file_index;
            const int n = snprintf(path, path_capacity,
                                   "mock/%016llx-%u.%s",
                                   (unsigned long long)session_id,
                                   (unsigned)file_index,
                                   summary ? "txt" : "pcap");
            if (n < 0 || (size_t)n >= path_capacity) {
                return SD_LOGGER_OPEN_ERROR;
            }
            *handle = file;
            return SD_LOGGER_OPEN_OK;
        }
    }
    return SD_LOGGER_OPEN_ERROR;
}

static size_t mock_write(void *ctx, void *handle, const uint8_t *data,
                         size_t length, bool *error, bool *storage_full)
{
    mock_io_t *mock = (mock_io_t *)ctx;
    mock_file_t *file = (mock_file_t *)handle;
    mock->write_calls++;
    pthread_mutex_lock(&s_writer_mutex);
    if (mock->block_write) {
        s_writer_blocked = true;
        pthread_cond_broadcast(&s_writer_cond);
        while (!s_writer_release) {
            pthread_cond_wait(&s_writer_cond, &s_writer_mutex);
        }
        mock->block_write = false;
    }
    pthread_mutex_unlock(&s_writer_mutex);
    *error = false;
    *storage_full = false;
    if (file == NULL || length > MOCK_FILE_BYTES - file->length) {
        *error = true;
        return 0;
    }
    size_t count = length;
    if (mock->short_limit > 0u && count > mock->short_limit) {
        count = mock->short_limit;
    }
    if (mock->fail_write) {
        if (file->length >= mock->fail_at_length) {
            *error = true;
            *storage_full = mock->full_card;
            return 0;
        }
        const size_t remaining = mock->fail_at_length - file->length;
        if (count > remaining) {
            count = remaining;
        }
    }
    if (count == 0u) {
        *error = true;
        *storage_full = mock->full_card;
        return 0;
    }
    memcpy(file->data + file->length, data, count);
    file->length += count;
    if (file->length < MOCK_FILE_BYTES) {
        file->data[file->length] = 0;
    }
    if (mock->fail_write && file->length >= mock->fail_at_length) {
        *error = true;
        *storage_full = mock->full_card;
    }
    return count;
}

static bool mock_flush(void *ctx, void *handle)
{
    mock_io_t *mock = (mock_io_t *)ctx;
    (void)handle;
    mock->flush_calls++;
    return !mock->fail_flush;
}

static bool mock_close(void *ctx, void *handle)
{
    mock_io_t *mock = (mock_io_t *)ctx;
    mock_file_t *file = (mock_file_t *)handle;
    mock->close_calls++;
    if (file == NULL) {
        return false;
    }
    file->closed = true;
    return !(mock->fail_close_pcap && !file->summary);
}

static uint64_t mock_now(void *ctx)
{
    return ((mock_io_t *)ctx)->now_us;
}

static void setup(bool mounted)
{
    memset(&s_mock, 0, sizeof(s_mock));
    pthread_mutex_lock(&s_writer_mutex);
    s_writer_blocked = false;
    s_writer_release = false;
    pthread_mutex_unlock(&s_writer_mutex);
    const sd_logger_io_t io = {
        .open_new = mock_open,
        .write = mock_write,
        .flush_sync = mock_flush,
        .close = mock_close,
        .now_us = mock_now,
        .ctx = &s_mock,
    };
    const sd_logger_sync_t sync = {
        .lock = mock_core_lock,
        .unlock = mock_core_unlock,
        .wake_worker = mock_wake_worker,
    };
    sd_logger_core_init(&s_core, &io, &sync, mounted);
}

static radio_packet_t make_packet(uint64_t timestamp_us, bool capture_max)
{
    radio_packet_t packet = {0};
    packet.packet_type = RX_PATH_TYPE_DATA;
    packet.channel = 6;
    packet.rssi = -47;
    packet.rx_timestamp_us = timestamp_us;
    packet.length = capture_max ? RADIO_PACKET_MAX_LEN : 28u;
    packet.orig_length = capture_max ? 1024u : 28u;
    packet.data[0] = 0x08; /* ordinary Data */
    packet.data[1] = 0x00;
    memset(&packet.data[2], 0, packet.length - 2u);
    static const uint8_t addr1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t addr2[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    static const uint8_t addr3[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(&packet.data[4], addr1, sizeof(addr1));
    memcpy(&packet.data[10], addr2, sizeof(addr2));
    memcpy(&packet.data[16], addr3, sizeof(addr3));
    if (capture_max) {
        static const uint8_t eapol_start[] = {
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
            0x02, 0x01, 0x00, 0x00,
        };
        memcpy(&packet.data[24], eapol_start, sizeof(eapol_start));
    }
    return packet;
}

static void save_sample_capture(const mock_file_t *pcap,
                                const mock_file_t *summary)
{
    FILE *file = fopen("build/phase3c_logger_sample.pcap", "wb");
    CHECK(file != NULL);
    CHECK(fwrite(pcap->data, 1u, pcap->length, file) == pcap->length);
    CHECK(fclose(file) == 0);
    file = fopen("build/phase3c_logger_sample.summary.txt", "wb");
    CHECK(file != NULL);
    CHECK(fwrite(summary->data, 1u, summary->length, file) == summary->length);
    CHECK(fclose(file) == 0);
}

static mock_file_t *find_file(bool summary, uint64_t session_id,
                              uint32_t index)
{
    for (size_t i = 0; i < MOCK_FILES; ++i) {
        if (s_mock.files[i].used && s_mock.files[i].summary == summary &&
            s_mock.files[i].session_id == session_id &&
            s_mock.files[i].index == index) {
            return &s_mock.files[i];
        }
    }
    return NULL;
}

static void run_worker(void)
{
    unsigned limit = 1000;
    while (limit-- > 0u && sd_logger_core_process_one(&s_core)) {
    }
    CHECK(limit > 0u);
}

static void start_session(uint64_t session_id, uint64_t anchor)
{
    CHECK(sd_logger_core_request_start(&s_core, session_id, anchor,
                                       "host-test-sha"));
    CHECK(sd_logger_core_process_one(&s_core));
}

static void check_pool_conserved(void)
{
    unsigned free_count = 0;
    unsigned reserved_count = 0;
    unsigned queued_count = 0;
    unsigned writing_count = 0;
    for (unsigned i = 0; i < SD_LOGGER_POOL_SIZE; ++i) {
        switch (s_core.slot_state[i]) {
        case SD_LOGGER_SLOT_FREE: free_count++; break;
        case SD_LOGGER_SLOT_RESERVED: reserved_count++; break;
        case SD_LOGGER_SLOT_QUEUED: queued_count++; break;
        case SD_LOGGER_SLOT_WRITING: writing_count++; break;
        default: CHECK(false); break;
        }
    }
    CHECK(free_count + reserved_count + queued_count + writing_count ==
          SD_LOGGER_POOL_SIZE);
    CHECK(reserved_count == s_core.reserved_count);
    CHECK(queued_count == s_core.count);
    CHECK(free_count == SD_LOGGER_POOL_SIZE);
}

static void check_u32le(const uint8_t *bytes, uint32_t expected)
{
    const uint32_t actual = (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
    CHECK(actual == expected);
}

static void test_submit_is_nonblocking_copy_and_stop_syncs(void)
{
    setup(true);
    const uint64_t anchor = UINT64_C(0x100000000) + 1000000u;
    start_session(0x1234u, anchor);
    const uint32_t writes_before = s_mock.write_calls;
    radio_packet_t source = make_packet(anchor + 100u, true);
    const uint8_t original_byte = source.data[7];
    CHECK(sd_logger_core_try_submit(&s_core, &source));
    CHECK(s_mock.write_calls == writes_before);
    memset(source.data, 0, sizeof(source.data));
    s_mock.now_us += 10000000u; /* queue/dequeue delay is not frame time */
    CHECK(sd_logger_core_process_one(&s_core));

    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.accepted == 1u);
    CHECK(stats.serialized == 1u);
    CHECK(stats.written == 0u);
    CHECK(stats.flushed == 0u);

    CHECK(sd_logger_core_request_stop(&s_core));
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPING); /* a bounded wait is pending */
    run_worker();
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.written == 1u);
    CHECK(stats.flushed == 1u);
    CHECK(stats.storage_drop == 0u);
    mock_file_t *pcap = find_file(false, 0x1234u, 0u);
    CHECK(pcap != NULL && pcap->closed);
    CHECK(pcap->length == PCAP_SERIALIZER_FILE_HEADER_LEN +
                              PCAP_SERIALIZER_MAX_RECORD_LEN);
    CHECK(pcap->data[0] == 0xd4u && pcap->data[1] == 0xc3u);
    check_u32le(&pcap->data[24], 0u);
    check_u32le(&pcap->data[28], 100u);
    check_u32le(&pcap->data[32], 527u);
    check_u32le(&pcap->data[36], 1035u);
    CHECK(pcap->data[24 + 16 + 15 + 7] == original_byte);
    mock_file_t *summary = find_file(true, 0x1234u, 0u);
    CHECK(summary != NULL && summary->closed);
    CHECK(strstr((char *)summary->data, "accepted=1\nserialized=1\nwritten=1\nflushed=1") != NULL);
    save_sample_capture(pcap, summary);
    check_pool_conserved();
}

static void test_full_queue_drops_only_new_and_drains_fifo(void)
{
    setup(true);
    start_session(0x200u, 2000000u);
    const uint32_t writes_before = s_mock.write_calls;
    for (uint32_t i = 0; i < SD_LOGGER_POOL_SIZE; ++i) {
        radio_packet_t packet = make_packet(2000100u + i, false);
        CHECK(sd_logger_core_try_submit(&s_core, &packet));
    }
    radio_packet_t overflow = make_packet(2000200u, false);
    CHECK(!sd_logger_core_try_submit(&s_core, &overflow));
    CHECK(s_mock.write_calls == writes_before);
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.accepted == SD_LOGGER_POOL_SIZE);
    CHECK(stats.drop_queue_full == 1u);
    CHECK(stats.storage_drop == 1u);
    CHECK(stats.queue_depth == SD_LOGGER_POOL_SIZE);
    CHECK(s_core.packets[s_core.queue[s_core.head]].rx_timestamp_us == 2000100u);

    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.written == SD_LOGGER_POOL_SIZE);
    CHECK(stats.flushed == SD_LOGGER_POOL_SIZE);
    CHECK(stats.queue_depth == 0u);
    check_pool_conserved();
}

static void test_valid_mgmt_control_and_data_raw_frames_are_kept(void)
{
    setup(true);
    start_session(0x250u, 2500000u);

    radio_packet_t mgmt = make_packet(2500001u, false);
    mgmt.packet_type = RX_PATH_TYPE_MGMT;
    mgmt.data[0] = 0x80u; /* Beacon, even if the later IE walk would fail. */
    CHECK(sd_logger_core_try_submit(&s_core, &mgmt));

    radio_packet_t ctrl = make_packet(2500002u, false);
    ctrl.packet_type = RX_PATH_TYPE_CTRL;
    ctrl.length = 14u;
    ctrl.orig_length = 14u;
    ctrl.data[0] = (uint8_t)((IEEE80211_CTRL_ACK << 4) |
                             (IEEE80211_FC_TYPE_VALUE_CTRL << 2));
    CHECK(sd_logger_core_try_submit(&s_core, &ctrl));

    radio_packet_t data = make_packet(2500003u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &data));
    CHECK(s_core.count == 3u);
    CHECK(s_mock.write_calls == 1u); /* only the logger has written the header */
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();

    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.accepted == 3u);
    CHECK(stats.serialized == 3u);
    CHECK(stats.written == 3u && stats.flushed == 3u);
    CHECK(stats.storage_drop == 0u);
    mock_file_t *pcap = find_file(false, 0x250u, 0u);
    CHECK(pcap != NULL);
    CHECK(pcap->length == PCAP_SERIALIZER_FILE_HEADER_LEN +
                          2u * (PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + 24u) +
                          PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + 10u);
    check_pool_conserved();
}

static void *one_logger_step(void *unused)
{
    (void)unused;
    (void)sd_logger_core_process_one(&s_core);
    return NULL;
}

static void test_slow_writer_does_not_hold_producer_lock(void)
{
    setup(true);
    start_session(0x260u, 2600000u);
    for (uint32_t i = 0; i < SD_LOGGER_POOL_SIZE; ++i) {
        radio_packet_t packet = make_packet(2600100u + i, true);
        CHECK(sd_logger_core_try_submit(&s_core, &packet));
    }
    for (uint32_t i = 0; i < SD_LOGGER_POOL_SIZE - 1u; ++i) {
        CHECK(sd_logger_core_process_one(&s_core));
    }
    /* The host suite scales file size to force rotation after three maximum
     * records; advancing the injected clock forces this next step through the
     * same batch write path so the producer can be tested against slow I/O. */
    s_mock.now_us += SD_LOGGER_MAX_FILE_AGE_US;
    s_mock.block_write = true;
    pthread_t writer;
    CHECK(pthread_create(&writer, NULL, one_logger_step, NULL) == 0);

    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 5;
    pthread_mutex_lock(&s_writer_mutex);
    int wait_result = 0;
    while (!s_writer_blocked && wait_result == 0) {
        wait_result = pthread_cond_timedwait(&s_writer_cond, &s_writer_mutex,
                                             &deadline);
    }
    const bool writer_reached_io = s_writer_blocked;
    if (writer_reached_io) {
        s_mock.now_us += 250000u;
    }
    pthread_mutex_unlock(&s_writer_mutex);

    unsigned accepted_while_writer_blocked = 0;
    if (writer_reached_io) {
        for (uint32_t i = 0; i < SD_LOGGER_POOL_SIZE - 1u; ++i) {
            radio_packet_t packet = make_packet(2600200u + i, false);
            if (sd_logger_core_try_submit(&s_core, &packet)) {
                accepted_while_writer_blocked++;
            }
        }
    }
    radio_packet_t overflow = make_packet(2600300u, false);
    CHECK(!sd_logger_core_try_submit(&s_core, &overflow));
    CHECK(sd_logger_core_request_stop(&s_core));
    sd_logger_stats_t pending;
    sd_logger_core_get_stats(&s_core, &pending);
    CHECK(pending.state == SD_LOGGER_STOPPING && !pending.accepting);
    radio_packet_t rejected_after_stop = make_packet(2600301u, false);
    CHECK(!sd_logger_core_try_submit(&s_core, &rejected_after_stop));

    pthread_mutex_lock(&s_writer_mutex);
    s_writer_release = true;
    pthread_cond_broadcast(&s_writer_cond);
    pthread_mutex_unlock(&s_writer_mutex);
    CHECK(pthread_join(writer, NULL) == 0);
    CHECK(writer_reached_io);
    CHECK(accepted_while_writer_blocked == SD_LOGGER_POOL_SIZE - 1u);

    run_worker();
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.accepted == 15u);
    CHECK(stats.written == 15u && stats.flushed == 15u);
    CHECK(stats.drop_queue_full == 1u);
    CHECK(stats.drop_not_recording == 1u);
    CHECK(stats.storage_drop == 2u);
    CHECK(stats.max_write_us >= 250000u);
    CHECK(stats.io_slow_count > 0u);
    check_pool_conserved();
}

static void test_short_writes_advance_offset_without_duplication(void)
{
    setup(true);
    s_mock.short_limit = 7u;
    start_session(0x300u, 3000000u);
    radio_packet_t packet = make_packet(3000025u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &packet));
    CHECK(sd_logger_core_process_one(&s_core));
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.written == 1u && stats.flushed == 1u);
    CHECK(stats.short_writes > 0u);
    mock_file_t *pcap = find_file(false, 0x300u, 0u);
    CHECK(pcap != NULL);
    CHECK(pcap->length == PCAP_SERIALIZER_FILE_HEADER_LEN +
                              PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + 24u);
    check_pool_conserved();
}

static void test_partial_write_error_marks_file_and_releases_pool(void)
{
    setup(true);
    start_session(0x400u, 4000000u);
    radio_packet_t packet = make_packet(4000001u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &packet));
    CHECK(sd_logger_core_process_one(&s_core));
    s_mock.fail_write = true;
    s_mock.fail_at_length = PCAP_SERIALIZER_FILE_HEADER_LEN + 5u;
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_ERROR);
    CHECK(stats.io_errors > 0u);
    CHECK(stats.files_incomplete > 0u);
    CHECK(stats.storage_drop == 1u && stats.drop_io == 1u);
    check_pool_conserved();
}

static void test_enospc_and_header_flush_failures_are_visible(void)
{
    setup(true);
    start_session(0x500u, 5000000u);
    radio_packet_t packet = make_packet(5000001u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &packet));
    CHECK(sd_logger_core_process_one(&s_core));
    s_mock.fail_write = true;
    s_mock.full_card = true;
    s_mock.fail_at_length = PCAP_SERIALIZER_FILE_HEADER_LEN;
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_ERROR);
    CHECK(stats.storage_full_errors >= 1u);
    CHECK(stats.drop_io == 1u);
    check_pool_conserved();

    setup(true);
    s_mock.fail_flush = true;
    CHECK(sd_logger_core_request_start(&s_core, 0x501u, 5010000u, "sha"));
    CHECK(sd_logger_core_process_one(&s_core));
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_ERROR);
    CHECK(stats.io_errors == 1u);
    check_pool_conserved();
}

static void test_filename_conflict_never_overwrites_and_restart_isolated(void)
{
    setup(true);
    s_mock.collide_summary_once = true;
    s_mock.collision_session_id = 0x600u;
    s_mock.collide_file_zero_once = true;
    start_session(0x600u, 6000000u);
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_RECORDING);
    CHECK(stats.filename_collisions == 2u);
    CHECK(stats.session_id != 0x600u);
    CHECK(stats.file_index == 1u);
    const uint64_t first_id = stats.session_id;
    radio_packet_t first = make_packet(6000001u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &first));
    CHECK(sd_logger_core_process_one(&s_core));
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    mock_file_t *old_file = find_file(false, first_id, 1u);
    CHECK(old_file != NULL && old_file->closed);
    const size_t old_size = old_file->length;

    start_session(0x601u, 7000000u);
    radio_packet_t second = make_packet(7000001u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &second));
    CHECK(sd_logger_core_process_one(&s_core));
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    CHECK(old_file->length == old_size);
    CHECK(find_file(false, 0x601u, 0u) != NULL);
    check_pool_conserved();
}

static void test_size_rotation_session_limit_and_timestamp_anchor(void)
{
    setup(true);
    start_session(0x700u, 7000000u);
    for (uint32_t i = 0; i < 14u; ++i) {
        radio_packet_t packet = make_packet(7000100u + i * 100u, true);
        CHECK(sd_logger_core_try_submit(&s_core, &packet));
        CHECK(sd_logger_core_process_one(&s_core));
    }
    radio_packet_t over_limit = make_packet(7000200u, true);
    CHECK(sd_logger_core_try_submit(&s_core, &over_limit));
    CHECK(sd_logger_core_process_one(&s_core));
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPING);
    CHECK(stats.limit_reached);
    CHECK(stats.drop_limit == 1u);
    CHECK(stats.file_rotations == 4u);
    run_worker();
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.written == 14u);
    CHECK(stats.flushed == 14u);
    unsigned pcap_files = 0;
    for (uint32_t i = 0; i < 8u; ++i) {
        mock_file_t *file = find_file(false, 0x700u, i);
        if (file != NULL) {
            pcap_files++;
            CHECK(file->length <= SD_LOGGER_MAX_FILE_BYTES);
            CHECK(file->closed);
        }
    }
    CHECK(pcap_files == 5u);
    mock_file_t *first = find_file(false, 0x700u, 0u);
    CHECK(first != NULL);
    check_u32le(&first->data[28], 100u);
    check_pool_conserved();
}

static void test_age_rotation_and_filter_accounting(void)
{
    setup(true);
    start_session(0x800u, 8000000u);
    radio_packet_t packet = make_packet(8000100u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &packet));
    CHECK(sd_logger_core_process_one(&s_core));
    s_mock.now_us += SD_LOGGER_MAX_FILE_AGE_US;
    packet = make_packet(8000200u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &packet));
    CHECK(sd_logger_core_process_one(&s_core));
    CHECK(find_file(false, 0x800u, 1u) != NULL);
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.file_rotations == 1u);

    radio_packet_t misc = make_packet(1u, false);
    misc.packet_type = 3u;
    CHECK(!sd_logger_core_try_submit(&s_core, &misc));
    radio_packet_t malformed = make_packet(2u, false);
    malformed.length = 10u;
    malformed.orig_length = 14u;
    CHECK(!sd_logger_core_try_submit(&s_core, &malformed));
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.filtered_non_data == 1u);
    CHECK(stats.rejected_invalid == 1u);
    check_pool_conserved();
}

static void test_pre_session_receive_time_is_counted_without_failing(void)
{
    setup(true);
    start_session(0x880u, 8800000u);
    radio_packet_t stale = make_packet(8799999u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &stale));
    CHECK(sd_logger_core_process_one(&s_core));

    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_RECORDING);
    CHECK(stats.accepted == 1u && stats.serialized == 0u);
    CHECK(stats.storage_drop == 1u && stats.drop_pre_session == 1u);
    check_pool_conserved();

    radio_packet_t current = make_packet(8800001u, false);
    CHECK(sd_logger_core_try_submit(&s_core, &current));
    CHECK(sd_logger_core_process_one(&s_core));
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_STOPPED);
    CHECK(stats.serialized == 1u && stats.written == 1u && stats.flushed == 1u);
    CHECK(stats.drop_pre_session == 1u);
    check_pool_conserved();
}

static void test_open_and_close_failures_leave_recoverable_error(void)
{
    setup(false);
    s_mock.fail_open = true;
    CHECK(sd_logger_core_request_start(&s_core, 0x900u, 9000000u, "sha"));
    CHECK(sd_logger_core_process_one(&s_core));
    sd_logger_stats_t stats;
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_ERROR);
    CHECK(stats.io_errors == 1u);
    CHECK(sd_logger_core_request_start(&s_core, 0x901u, 9100000u, "sha"));
    s_mock.fail_open = false;
    CHECK(sd_logger_core_process_one(&s_core));
    s_mock.fail_close_pcap = true;
    CHECK(sd_logger_core_request_stop(&s_core));
    run_worker();
    sd_logger_core_get_stats(&s_core, &stats);
    CHECK(stats.state == SD_LOGGER_ERROR);
    CHECK(stats.files_incomplete > 0u);
    check_pool_conserved();
}

int main(void)
{
    test_register("submit_copy_and_stop_sync", test_submit_is_nonblocking_copy_and_stop_syncs);
    test_register("queue_full_fifo_and_drain", test_full_queue_drops_only_new_and_drains_fifo);
    test_register("valid_mgmt_control_data", test_valid_mgmt_control_and_data_raw_frames_are_kept);
    test_register("slow_writer_not_producer_lock", test_slow_writer_does_not_hold_producer_lock);
    test_register("partial_write_offset", test_short_writes_advance_offset_without_duplication);
    test_register("partial_write_error_cleanup", test_partial_write_error_marks_file_and_releases_pool);
    test_register("enospc_and_header_flush", test_enospc_and_header_flush_failures_are_visible);
    test_register("filename_conflict_restart", test_filename_conflict_never_overwrites_and_restart_isolated);
    test_register("rotation_session_limit", test_size_rotation_session_limit_and_timestamp_anchor);
    test_register("age_rotation_filtering", test_age_rotation_and_filter_accounting);
    test_register("pre_session_rx_timestamp", test_pre_session_receive_time_is_counted_without_failing);
    test_register("open_close_error_recovery", test_open_and_close_failures_leave_recoverable_error);
    return test_run_all();
}
