#include "pcap_serializer.h"

#include <string.h>

#define PCAP_TIMESTAMP_USEC_PER_SEC UINT64_C(1000000)
#define RADIOTAP_PRESENT_FLAGS      UINT32_C(0x00000002)
#define RADIOTAP_PRESENT_CHANNEL    UINT32_C(0x00000008)
#define RADIOTAP_PRESENT_ANT_SIGNAL UINT32_C(0x00000020)
#define RADIOTAP_CHANNEL_2GHZ       UINT16_C(0x0080)

static void put_le16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value & UINT16_C(0x00ff));
    out[1] = (uint8_t)(value >> 8);
}

static void put_le32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & UINT32_C(0x000000ff));
    out[1] = (uint8_t)((value >> 8) & UINT32_C(0x000000ff));
    out[2] = (uint8_t)((value >> 16) & UINT32_C(0x000000ff));
    out[3] = (uint8_t)(value >> 24);
}

static void saturating_increment(uint32_t *value)
{
    if (value != NULL && *value != UINT32_MAX) {
        ++*value;
    }
}

static bool reject_record(pcap_serializer_stats_t *stats,
                          pcap_reject_reason_t *reason,
                          pcap_reject_reason_t rejected)
{
    if (reason != NULL) {
        *reason = rejected;
    }
    if (stats != NULL && rejected > PCAP_REJECT_NONE &&
        rejected < PCAP_REJECT_COUNT) {
        saturating_increment(&stats->rejected[rejected]);
    }
    return false;
}

bool pcap_serializer_write_global_header(uint8_t *out, size_t capacity,
                                         size_t *written)
{
    static const uint8_t header[PCAP_SERIALIZER_FILE_HEADER_LEN] = {
        /* Little-endian classic pcap with seconds/microseconds timestamps. */
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00, 0x04, 0x00,
        /* Reserved1, Reserved2: zero. */
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        /* SnapLen = max radiotap (15) + bounded no-FCS MAC (512). */
        (uint8_t)(PCAP_SERIALIZER_SNAPLEN & 0xffu),
        (uint8_t)((PCAP_SERIALIZER_SNAPLEN >> 8) & 0xffu),
        0x00, 0x00,
        /* IANA LINKTYPE_IEEE802_11_RADIOTAP (127). */
        (uint8_t)(PCAP_SERIALIZER_LINKTYPE_IEEE802_11_RADIOTAP & 0xffu),
        (uint8_t)((PCAP_SERIALIZER_LINKTYPE_IEEE802_11_RADIOTAP >> 8) & 0xffu),
        0x00, 0x00,
    };

    if (written != NULL) {
        *written = 0;
    }
    if (written == NULL || out == NULL ||
        capacity < PCAP_SERIALIZER_FILE_HEADER_LEN) {
        return false;
    }

    memcpy(out, header, sizeof(header));
    *written = sizeof(header);
    return true;
}

static uint16_t channel_frequency_mhz(uint8_t channel)
{
    if (channel == 14u) {
        return UINT16_C(2484);
    }
    return (uint16_t)(UINT16_C(2412) +
                      UINT16_C(5) * (uint16_t)(channel - 1u));
}

static bool timestamp_from_anchor(const pcap_time_anchor_t *anchor,
                                  uint64_t rx_timestamp_us,
                                  uint32_t *seconds, uint32_t *microseconds,
                                  pcap_serializer_stats_t *stats,
                                  pcap_reject_reason_t *reason)
{
    if (rx_timestamp_us < anchor->monotonic_anchor_us) {
        return reject_record(stats, reason, PCAP_REJECT_TIME_BEFORE_ANCHOR);
    }

    const uint64_t delta_us = rx_timestamp_us - anchor->monotonic_anchor_us;
    if (anchor->epoch_anchor_us > UINT64_MAX - delta_us) {
        return reject_record(stats, reason, PCAP_REJECT_TIME_OUT_OF_RANGE);
    }

    const uint64_t epoch_us = anchor->epoch_anchor_us + delta_us;
    const uint64_t epoch_seconds = epoch_us / PCAP_TIMESTAMP_USEC_PER_SEC;
    if (epoch_seconds > UINT32_MAX) {
        return reject_record(stats, reason, PCAP_REJECT_TIME_OUT_OF_RANGE);
    }

    *seconds = (uint32_t)epoch_seconds;
    *microseconds = (uint32_t)(epoch_us % PCAP_TIMESTAMP_USEC_PER_SEC);
    return true;
}

bool pcap_serializer_encode_record(const rx_capture_view_t *view,
                                   const pcap_time_anchor_t *anchor,
                                   uint8_t *out, size_t capacity,
                                   size_t *written,
                                   pcap_serializer_stats_t *stats,
                                   pcap_reject_reason_t *reason)
{
    if (written != NULL) {
        *written = 0;
    }
    if (reason != NULL) {
        *reason = PCAP_REJECT_NONE;
    }
    if (view == NULL || anchor == NULL || out == NULL || written == NULL ||
        stats == NULL) {
        return reject_record(stats, reason, PCAP_REJECT_INVALID_ARGUMENT);
    }
    if (!view->original_mac_length_valid) {
        return reject_record(stats, reason,
                             PCAP_REJECT_INVALID_ORIGINAL_LENGTH);
    }
    if (view->fcs_policy !=
        RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW) {
        return reject_record(stats, reason,
                             PCAP_REJECT_UNSUPPORTED_FCS_POLICY);
    }
    if (view->captured_mac_length > RADIO_PACKET_MAX_LEN) {
        return reject_record(stats, reason, PCAP_REJECT_CAPTURE_OVER_BOUND);
    }
    if ((view->captured_mac_length > 0u && view->mac_bytes == NULL) ||
        view->captured_mac_length > view->original_mac_length ||
        view->capture_truncated !=
            (view->captured_mac_length < view->original_mac_length)) {
        return reject_record(stats, reason,
                             PCAP_REJECT_INCONSISTENT_LENGTHS);
    }

    /* Both lengths in rx_capture_view_t already exclude the driver's FCS.
     * This min also keeps the serialized prefix bounded by the reported
     * original MAC length if the view contract is extended in the future. */
    const uint16_t mac_captured_length =
        view->captured_mac_length < view->original_mac_length
            ? view->captured_mac_length
            : view->original_mac_length;
    const bool channel_known = view->rx_channel >= 1u && view->rx_channel <= 14u;
    const uint8_t radiotap_length = channel_known ? 15u : 10u;

    const uint64_t incl_len_64 = (uint64_t)radiotap_length +
                                 (uint64_t)mac_captured_length;
    const uint64_t orig_len_64 = (uint64_t)radiotap_length +
                                 (uint64_t)view->original_mac_length;
    if (incl_len_64 > UINT32_MAX || orig_len_64 > UINT32_MAX ||
        incl_len_64 > orig_len_64 ||
        incl_len_64 > PCAP_SERIALIZER_SNAPLEN) {
        return reject_record(stats, reason,
                             PCAP_REJECT_INCONSISTENT_LENGTHS);
    }

    const size_t packet_data_length = (size_t)incl_len_64;
    if (packet_data_length > SIZE_MAX - PCAP_SERIALIZER_RECORD_HEADER_LEN) {
        return reject_record(stats, reason,
                             PCAP_REJECT_INCONSISTENT_LENGTHS);
    }
    const size_t record_length = PCAP_SERIALIZER_RECORD_HEADER_LEN +
                                 packet_data_length;
    if (record_length > PCAP_SERIALIZER_MAX_RECORD_LEN ||
        capacity < record_length) {
        return reject_record(stats, reason, PCAP_REJECT_OUTPUT_CAPACITY);
    }

    uint32_t seconds = 0;
    uint32_t microseconds = 0;
    if (!timestamp_from_anchor(anchor, view->rx_timestamp_us,
                               &seconds, &microseconds, stats, reason)) {
        return false;
    }

    uint8_t record_header[PCAP_SERIALIZER_RECORD_HEADER_LEN] = {0};
    put_le32(&record_header[0], seconds);
    put_le32(&record_header[4], microseconds);
    put_le32(&record_header[8], (uint32_t)incl_len_64);
    put_le32(&record_header[12], (uint32_t)orig_len_64);

    uint8_t radiotap[PCAP_SERIALIZER_RADIOTAP_MAX_LEN] = {0};
    radiotap[2] = radiotap_length;
    const uint32_t present = RADIOTAP_PRESENT_FLAGS |
                             RADIOTAP_PRESENT_ANT_SIGNAL |
                             (channel_known ? RADIOTAP_PRESENT_CHANNEL : 0u);
    put_le32(&radiotap[4], present);
    /* No FCS bytes are emitted and no failed-FCS status is available. */
    radiotap[8] = 0;
    if (channel_known) {
        /* Channel (field 3) is 16-bit aligned relative to radiotap start. */
        radiotap[9] = 0;
        put_le16(&radiotap[10], channel_frequency_mhz(view->rx_channel));
        put_le16(&radiotap[12], RADIOTAP_CHANNEL_2GHZ);
        radiotap[14] = (uint8_t)view->rssi;
    } else {
        /* Explicit unknown channel: omit the whole Channel field. */
        radiotap[9] = (uint8_t)view->rssi;
    }

    /* All failure paths above precede the first write into caller storage. */
    memcpy(out, record_header, sizeof(record_header));
    memcpy(&out[sizeof(record_header)], radiotap, radiotap_length);
    if (mac_captured_length > 0u) {
        memcpy(&out[sizeof(record_header) + radiotap_length],
               view->mac_bytes, mac_captured_length);
    }

    *written = record_length;
    saturating_increment(&stats->records_encoded);
    if (!channel_known) {
        saturating_increment(&stats->records_without_channel);
    }
    return true;
}
