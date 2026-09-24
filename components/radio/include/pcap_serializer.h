#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rx_path.h"

/* Classic pcap 2.4, microsecond timestamps, LINKTYPE_IEEE802_11_RADIOTAP. */
#define PCAP_SERIALIZER_FILE_HEADER_LEN 24u
#define PCAP_SERIALIZER_RECORD_HEADER_LEN 16u
#define PCAP_SERIALIZER_RADIOTAP_MAX_LEN 15u
#define PCAP_SERIALIZER_SNAPLEN \
    (PCAP_SERIALIZER_RADIOTAP_MAX_LEN + RADIO_PACKET_MAX_LEN)
#define PCAP_SERIALIZER_MAX_RECORD_LEN \
    (PCAP_SERIALIZER_RECORD_HEADER_LEN + PCAP_SERIALIZER_SNAPLEN)
#define PCAP_SERIALIZER_LINKTYPE_IEEE802_11_RADIOTAP 127u

/* Fixed, caller-owned session mapping. Keep the same value for all files in a
 * session. epoch_us may be zero; in that case timestamps are relative to the
 * Unix epoch and are not claimed to be UTC. */
typedef struct {
    uint64_t monotonic_anchor_us;
    uint64_t epoch_anchor_us;
} pcap_time_anchor_t;

typedef enum {
    PCAP_REJECT_NONE = 0,
    PCAP_REJECT_INVALID_ARGUMENT,
    PCAP_REJECT_INVALID_ORIGINAL_LENGTH,
    PCAP_REJECT_INCONSISTENT_LENGTHS,
    PCAP_REJECT_CAPTURE_OVER_BOUND,
    PCAP_REJECT_UNSUPPORTED_FCS_POLICY,
    PCAP_REJECT_TIME_BEFORE_ANCHOR,
    PCAP_REJECT_TIME_OUT_OF_RANGE,
    PCAP_REJECT_OUTPUT_CAPACITY,
    PCAP_REJECT_COUNT,
} pcap_reject_reason_t;

/* Caller-owned counters. Updates saturate at UINT32_MAX. The serializer is
 * stateless and does not add locks; serialize calls through the owner. */
typedef struct {
    uint32_t records_encoded;
    uint32_t records_without_channel;
    uint32_t rejected[PCAP_REJECT_COUNT];
} pcap_serializer_stats_t;

/* Write the fixed 24-byte global header. Failure leaves out[] untouched and
 * sets *written to zero when that output is available. */
bool pcap_serializer_write_global_header(uint8_t *out, size_t capacity,
                                         size_t *written);

/* Encode one record into caller-owned storage. The view's mac_bytes remains
 * borrowed until this function returns; no pointer is retained. The output
 * buffer must not overlap mac_bytes. All validation and capacity checks occur
 * before any record byte is written. stats and written are required. */
bool pcap_serializer_encode_record(const rx_capture_view_t *view,
                                   const pcap_time_anchor_t *anchor,
                                   uint8_t *out, size_t capacity,
                                   size_t *written,
                                   pcap_serializer_stats_t *stats,
                                   pcap_reject_reason_t *reason);
