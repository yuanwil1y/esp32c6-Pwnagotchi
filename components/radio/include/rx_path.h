#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * Phase 1.5: host-testable RX front-end core.
 *
 * rx_path_on_frame() contains the whole decision flow of the promiscuous
 * RX callback (type whitelist -> rx_state gate -> bounded copy -> enqueue),
 * expressed over a driver-neutral frame view and injected queue operations.
 * wifi_sniffer.c is the thin ESP-IDF adapter that fills the view from
 * wifi_promiscuous_pkt_t and maps the io hooks onto FreeRTOS queues; the
 * host regression tests drive the same production code with mocks.
 *
 * The core never blocks, never allocates, never logs and never touches
 * LVGL/SD, exactly like the callback it replaces.
 */

/*
 * Phase 1A radio constants.
 *
 * RADIO_PACKET_MAX_LEN: 802.11 management frames (beacon/probe) that matter
 * for later phases stay well below this size. Longer frames are stored
 * truncated and counted in rx_truncated. The bound also caps the static
 * packet pool memory: pool size * (RADIO_PACKET_MAX_LEN + header).
 */
#define RADIO_PACKET_MAX_LEN     512
#define RADIO_PACKET_POOL_SIZE   24

/*
 * Snapshot of one captured frame as handed from the promiscuous RX callback
 * to the consumer task. `length` is the number of bytes actually stored in
 * data[] (<= orig_length); `orig_length` is the on-air frame length
 * including FCS as reported by the Wi-Fi driver.
 */
typedef struct {
    int8_t rssi;
    uint8_t channel;
    uint16_t length;
    uint16_t orig_length;
    uint8_t packet_type; /* wifi_promiscuous_pkt_type_t value */
    uint8_t data[RADIO_PACKET_MAX_LEN];
    /* System-monotonic receive time captured at callback entry, in us. */
    uint64_t rx_timestamp_us;
} radio_packet_t;

/* Counter contract (all monotonic unless noted):
 * - rx_total          : every callback invocation
 * - rx_state_errors   : whitelisted frame with rx_state != 0 (dropped)
 * - rx_misc           : MISC/unknown type (dropped, payload never touched)
 * - rx_dropped_pool   : no free slot available (dropped)
 * - rx_dropped_queue  : consumer queue full, slot returned (dropped)
 * - rx_no_payload     : whitelisted frame with zero payload bytes (queued,
 *                       metadata only); subset of rx_queued
 * - rx_queued         : handed to the consumer queue
 * - rx_processed      : consumed and released by rx_path_slot_release()
 * - rx_truncated      : queued frames copied below orig_length
 * - rx_management/control/data : counted at callback time by type
 * - queue_current/peak : occupancy of the consumer queue
 *
 * Accounting identity:
 *   rx_total == rx_state_errors + rx_misc + rx_dropped_pool
 *             + rx_dropped_queue + rx_queued
 */
typedef struct {
    uint32_t rx_total;
    uint32_t rx_queued;
    uint32_t rx_processed;
    uint32_t rx_dropped_pool;
    uint32_t rx_dropped_queue;
    uint32_t rx_truncated;
    uint32_t rx_state_errors;
    uint32_t rx_misc;
    uint32_t rx_no_payload;

    uint32_t rx_management;
    uint32_t rx_data;
    uint32_t rx_control;

    uint32_t queue_current;
    uint32_t queue_peak;
} rx_path_stats_t;

/* Raw wifi_promiscuous_pkt_type_t values; anything else (including
 * WIFI_PKT_MISC = 3) is whitelisted out of payload handling. */
#define RX_PATH_TYPE_MGMT 0
#define RX_PATH_TYPE_CTRL 1
#define RX_PATH_TYPE_DATA 2

/*
 * Driver-neutral view of one received frame. `type` is the raw
 * wifi_promiscuous_pkt_type_t value (0=MGMT 1=CTRL 2=DATA 3=MISC).
 *
 * IDF v5.4 contract (esp_wifi_types.h): for WIFI_PKT_MISC the payload is
 * zero length even though sig_len may be non-zero, so the adapter must pass
 * payload_len == 0 for MISC. As defense in depth the core additionally
 * refuses to read payload for any non-whitelisted type regardless of the
 * payload_len it was given.
 *
 * sig_len is the on-air length including the 4-byte FCS (12-bit rx_ctrl
 * field per esp_wifi_types_native.h).
 */
typedef struct {
    uint8_t type;
    uint8_t channel;
    int8_t rssi;
    uint16_t rx_state;
    uint16_t sig_len;
    const uint8_t *payload; /* may be NULL when payload_len == 0 */
    uint16_t payload_len;
    uint64_t rx_timestamp_us;
} rx_frame_view_t;

/* FCS policy used by the driver adapter and the bounded pool. */
typedef enum {
    /* Driver length includes a 4-byte FCS; capture views remove it. */
    RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW = 0,
} rx_capture_fcs_policy_t;

/*
 * Unified read-only view for parsers. `mac_bytes` points into a packet-pool
 * slot and is valid only until rx_path_slot_release(); consumers must not
 * retain that pointer. All other fields are copied values. MAC lengths
 * exclude the 4-byte FCS. `capture_truncated` means MAC body bytes are
 * missing; a capture that omitted only some/all FCS bytes is not truncated.
 */
typedef struct {
    const uint8_t *mac_bytes;
    uint16_t captured_mac_length;
    uint16_t original_mac_length;
    bool original_mac_length_valid;
    uint8_t rx_channel;
    int8_t rssi;
    uint64_t rx_timestamp_us;
    rx_capture_fcs_policy_t fcs_policy;
    bool capture_truncated;
} rx_capture_view_t;

/*
 * Queue operations injected by the adapter (FreeRTOS queues on target,
 * mocks in tests). All non-blocking. lock/unlock (optional, may be NULL)
 * guard the stats updates the way the callback guarded its counter
 * critical sections before Phase 1.5.
 */
typedef struct {
    void *ctx;
    bool (*slot_alloc)(void *ctx, radio_packet_t **out);  /* pop free slot */
    bool (*rx_push)(void *ctx, radio_packet_t *slot);     /* enqueue filled */
    bool (*slot_return)(void *ctx, radio_packet_t *slot); /* give back */
    void (*lock)(void *ctx);
    void (*unlock)(void *ctx);
} rx_path_io_t;

/*
 * RX callback flow (Phase 1.5 semantics):
 *   rx_total++ ->
 *   type whitelist: MGMT/CTRL/DATA counted by type; anything else counts
 *     rx_misc and returns WITHOUT reading payload (works even with the
 *     MISC promiscuous filter disabled or re-enabled later) ->
 *   rx_state != 0 counts rx_state_errors and returns BEFORE a slot is
 *     taken (no slot can leak on error frames) ->
 *   slot_alloc fails: rx_dropped_pool++ ->
 *   copy min(sig_len, RADIO_PACKET_MAX_LEN) bytes, set metadata;
 *   sig_len > RADIO_PACKET_MAX_LEN counts rx_truncated ->
 *   rx_push fails: slot returned, rx_dropped_queue++ ->
 *   rx_queued++, queue_current/peak maintained.
 */
void rx_path_on_frame(const rx_path_io_t *io, rx_path_stats_t *stats,
                      const rx_frame_view_t *view);

/*
 * Consumer side: count the frame as processed and return the slot to the
 * free pool. The consumer MUST call this exactly once per received slot,
 * after it is done reading the packet bytes. Never blocks.
 */
void rx_path_slot_release(const rx_path_io_t *io, rx_path_stats_t *stats,
                          radio_packet_t *slot);

/*
 * Bytes of the pooled copy that may be handed to the 802.11 parser,
 * i.e. the MAC body without the FCS.
 *
 *   parse_len = min(captured_length, orig_length - 4)   when orig >= 4
 *   parse_len = captured_length                          when orig <  4
 *
 * captured_length is pkt->length; orig_length - 4 is computed in a wide
 * type after the orig >= 4 check so it cannot underflow. For a truncated
 * copy (length < orig_length) this yields the full copy when the capture
 * ends inside the MAC body, and excludes partially captured FCS bytes
 * otherwise. The FCS is therefore never fed to the IE walk in either case.
 */
uint16_t rx_path_parse_length(const radio_packet_t *pkt);

/*
 * True when MAC body bytes (not just FCS bytes) are missing from the
 * pooled copy. Only then may the parser report its tail as incomplete
 * instead of judging it; see rx_path_parse_length().
 */
bool rx_path_body_truncated(const radio_packet_t *pkt);

/* Build the unified parser view from a live pool slot; no bytes are copied. */
bool rx_path_make_capture_view(const radio_packet_t *pkt,
                               rx_capture_view_t *out);
