#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pcap_serializer.h"

#define SD_LOGGER_POOL_SIZE          8u
#define SD_LOGGER_BATCH_SIZE         4096u
#ifndef SD_LOGGER_MAX_FILE_BYTES
#define SD_LOGGER_MAX_FILE_BYTES     (16u * 1024u * 1024u)
#endif
#ifndef SD_LOGGER_SESSION_MAX_BYTES
#define SD_LOGGER_SESSION_MAX_BYTES  (128u * 1024u * 1024u)
#endif
#ifndef SD_LOGGER_MAX_FILE_AGE_US
#define SD_LOGGER_MAX_FILE_AGE_US    UINT64_C(300000000)
#endif
#ifndef SD_LOGGER_FLUSH_PERIOD_US
#define SD_LOGGER_FLUSH_PERIOD_US    UINT64_C(1000000)
#endif
#define SD_LOGGER_IO_SLOW_THRESHOLD_US UINT64_C(100000)
#define SD_LOGGER_PATH_MAX           96u
#define SD_LOGGER_FW_SHA_MAX         40u

typedef enum {
    SD_LOGGER_DISABLED = 0,
    SD_LOGGER_STARTING,
    SD_LOGGER_RECORDING,
    SD_LOGGER_STOPPING,
    SD_LOGGER_STOPPED,
    SD_LOGGER_ERROR,
} sd_logger_state_t;

typedef enum {
    SD_LOGGER_OPEN_OK = 0,
    SD_LOGGER_OPEN_EXISTS,
    SD_LOGGER_OPEN_ERROR,
} sd_logger_open_result_t;

typedef struct {
    /* An O_EXCL-style create. It must never truncate an existing path. */
    sd_logger_open_result_t (*open_new)(void *ctx, uint64_t session_id,
                                        uint32_t file_index, bool summary,
                                        char *path, size_t path_capacity,
                                        void **handle);
    /* May return a positive short count and an independent error indication. */
    size_t (*write)(void *ctx, void *handle, const uint8_t *data,
                    size_t length, bool *error, bool *storage_full);
    /* fflush + ferror + applicable fsync; true means durably synced. */
    bool (*flush_sync)(void *ctx, void *handle);
    /* Closes and consumes the handle even if it reports failure. */
    bool (*close)(void *ctx, void *handle);
    uint64_t (*now_us)(void *ctx);
    void *ctx;
} sd_logger_io_t;

typedef struct {
    void (*lock)(void *ctx);
    void (*unlock)(void *ctx);
    void (*wake_worker)(void *ctx);
    void *ctx;
} sd_logger_sync_t;

typedef struct {
    uint64_t accepted;
    uint64_t serialized;
    uint64_t written;
    uint64_t flushed;
    uint64_t storage_drop;
    uint64_t drop_queue_full;
    uint64_t drop_not_recording;
    uint64_t drop_pre_session;
    uint64_t drop_io;
    uint64_t drop_limit;
    uint64_t rejected_invalid;
    uint64_t filtered_non_data;
    uint64_t short_writes;
    uint64_t io_errors;
    uint64_t file_rotations;
    uint64_t filename_collisions;
    uint64_t files_incomplete;
    uint64_t storage_full_errors;
    uint64_t max_open_us;
    uint64_t max_write_us;
    uint64_t max_flush_us;
    uint64_t max_close_us;
    uint64_t io_slow_count;
    uint64_t pcap_bytes;
    uint32_t queue_depth;
    uint32_t queue_peak;
    uint32_t logger_stack_hwm;
    uint64_t session_id;
    uint64_t session_anchor_rx_us;
    uint64_t session_start_us;
    uint32_t file_index;
    bool accepting;
    bool limit_reached;
    sd_logger_state_t state;
    char current_path[SD_LOGGER_PATH_MAX];
    char summary_path[SD_LOGGER_PATH_MAX];
} sd_logger_stats_t;

typedef enum {
    SD_LOGGER_SLOT_FREE = 0,
    SD_LOGGER_SLOT_RESERVED,
    SD_LOGGER_SLOT_QUEUED,
    SD_LOGGER_SLOT_WRITING,
} sd_logger_slot_state_t;

typedef struct {
    uint8_t slot_state[SD_LOGGER_POOL_SIZE];
    uint8_t queue[SD_LOGGER_POOL_SIZE];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
    uint8_t reserved_count;
    bool accepting;
    bool start_pending;
    bool stop_requested;
    bool error_cleanup_pending;
    bool limit_reached;
    bool summary_open;
    bool summary_incomplete;
    bool pcap_open;
    bool pcap_incomplete;
    bool current_packet_appended;
    sd_logger_state_t state;

    radio_packet_t packets[SD_LOGGER_POOL_SIZE];
    uint8_t batch[SD_LOGGER_BATCH_SIZE];
    size_t batch_length;
    uint32_t batch_record_count;
    uint32_t pending_flush_records;
    uint8_t record_scratch[PCAP_SERIALIZER_MAX_RECORD_LEN];
    size_t current_file_bytes;
    uint64_t session_pcap_bytes;
    uint64_t session_id;
    uint64_t session_anchor_rx_us;
    uint64_t session_start_us;
    uint64_t file_open_us;
    uint64_t last_flush_us;
    uint32_t file_index;
    sd_logger_stats_t session_baseline;
    char firmware_sha[SD_LOGGER_FW_SHA_MAX + 1u];
    char current_path[SD_LOGGER_PATH_MAX];
    char summary_path[SD_LOGGER_PATH_MAX];
    void *pcap_handle;
    void *summary_handle;
    pcap_serializer_stats_t serializer_stats;
    sd_logger_stats_t stats;
    sd_logger_io_t io;
    sd_logger_sync_t sync;
} sd_logger_core_t;

void sd_logger_core_init(sd_logger_core_t *core, const sd_logger_io_t *io,
                         const sd_logger_sync_t *sync, bool media_mounted);
bool sd_logger_core_request_start(sd_logger_core_t *core, uint64_t session_id,
                                  uint64_t monotonic_now_us,
                                  const char *firmware_sha);
bool sd_logger_core_request_stop(sd_logger_core_t *core);
/* Copies a raw driver packet into the independent logger pool without I/O. */
bool sd_logger_core_try_submit(sd_logger_core_t *core,
                               const radio_packet_t *packet);
/* One logger-task step. All writer callbacks execute on its caller. */
bool sd_logger_core_process_one(sd_logger_core_t *core);
void sd_logger_core_get_stats(sd_logger_core_t *core,
                              sd_logger_stats_t *out);

const char *sd_logger_state_name(sd_logger_state_t state);
const char *sd_logger_state_short_name(sd_logger_state_t state);
