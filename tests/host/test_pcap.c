#include "pcap_serializer.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

#define RECORD_DATA_OFFSET PCAP_SERIALIZER_RECORD_HEADER_LEN
#define RADIO_FRAME_OFFSET \
    (PCAP_SERIALIZER_RECORD_HEADER_LEN + PCAP_SERIALIZER_RADIOTAP_MAX_LEN)

static const pcap_time_anchor_t k_anchor_zero = {0, 0};

static rx_capture_view_t make_view(const uint8_t *mac, uint16_t captured,
                                   uint16_t original, uint8_t channel,
                                   int8_t rssi, uint64_t rx_timestamp_us)
{
    rx_capture_view_t view = {
        .mac_bytes = mac,
        .captured_mac_length = captured,
        .original_mac_length = original,
        .original_mac_length_valid = true,
        .rx_channel = channel,
        .rssi = rssi,
        .rx_timestamp_us = rx_timestamp_us,
        .fcs_policy =
            RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW,
        .capture_truncated = captured < original,
    };
    return view;
}

static uint16_t get_le16(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t get_le32(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_le16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value & UINT16_C(0x00ff));
    out[1] = (uint8_t)(value >> 8);
}

static void put_be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)(value & UINT16_C(0x00ff));
}

static bool encode(const rx_capture_view_t *view,
                   const pcap_time_anchor_t *anchor, uint8_t *out,
                   size_t capacity, size_t *written,
                   pcap_serializer_stats_t *stats,
                   pcap_reject_reason_t *reason)
{
    return pcap_serializer_encode_record(view, anchor, out, capacity,
                                         written, stats, reason);
}

static void test_global_header_golden(void)
{
    static const uint8_t expected[PCAP_SERIALIZER_FILE_HEADER_LEN] = {
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x02, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00,
    };
    uint8_t out[PCAP_SERIALIZER_FILE_HEADER_LEN];
    size_t written = 0;

    CHECK(pcap_serializer_write_global_header(out, sizeof(out), &written));
    CHECK(written == sizeof(expected));
    CHECK(memcmp(out, expected, sizeof(expected)) == 0);
}

static void test_global_header_short_capacity_is_atomic(void)
{
    uint8_t out[PCAP_SERIALIZER_FILE_HEADER_LEN];
    memset(out, 0xa5, sizeof(out));
    size_t written = 123;

    CHECK(!pcap_serializer_write_global_header(out, sizeof(out) - 1u,
                                               &written));
    CHECK(written == 0);
    for (size_t i = 0; i < sizeof(out); ++i) {
        CHECK(out[i] == 0xa5);
    }
}

static void test_channel_radiotap_golden_and_frequencies(void)
{
    static const uint8_t empty_byte = 0;
    static const uint8_t channels[] = {1, 6, 11, 14};
    static const uint16_t frequencies[] = {2412, 2437, 2462, 2484};
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 0;

    for (size_t i = 0; i < sizeof(channels); ++i) {
        rx_capture_view_t view = make_view(&empty_byte, 1, 1,
                                           channels[i], -42, 10);
        CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                     &stats, &reason));
        CHECK(reason == PCAP_REJECT_NONE);
        CHECK(out[RECORD_DATA_OFFSET] == 0);
        CHECK(out[RECORD_DATA_OFFSET + 1u] == 0);
        CHECK(get_le16(&out[RECORD_DATA_OFFSET + 2u]) == 15);
        CHECK(get_le32(&out[RECORD_DATA_OFFSET + 4u]) == 0x2a);
        CHECK(out[RECORD_DATA_OFFSET + 8u] == 0);
        CHECK(out[RECORD_DATA_OFFSET + 9u] == 0); /* alignment pad */
        CHECK(get_le16(&out[RECORD_DATA_OFFSET + 10u]) == frequencies[i]);
        CHECK(get_le16(&out[RECORD_DATA_OFFSET + 12u]) == 0x0080);
        CHECK(out[RECORD_DATA_OFFSET + 14u] == (uint8_t)-42);
        CHECK(written == PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + 1u);
    }
    CHECK(stats.records_encoded == 4);
}

static void test_unknown_channel_omits_channel_field(void)
{
    static const uint8_t b = 0x5a;
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    rx_capture_view_t view = make_view(&b, 1, 1, 0, -91, 1);
    pcap_serializer_stats_t stats = {0};
    size_t written = 0;

    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le16(&out[RECORD_DATA_OFFSET + 2u]) == 10);
    CHECK(get_le32(&out[RECORD_DATA_OFFSET + 4u]) == 0x22);
    CHECK(out[RECORD_DATA_OFFSET + 8u] == 0);
    CHECK(out[RECORD_DATA_OFFSET + 9u] == (uint8_t)-91);
    CHECK(out[RECORD_DATA_OFFSET + 10u] == b);
    CHECK(written == PCAP_SERIALIZER_RECORD_HEADER_LEN + 10u + 1u);
    CHECK(stats.records_without_channel == 1);

    view.rx_channel = 15;
    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le16(&out[RECORD_DATA_OFFSET + 2u]) == 10);
    CHECK(stats.records_without_channel == 2);
}

static void test_record_header_timestamp_boundary_and_payload(void)
{
    static const uint8_t mac[] = {0xde, 0xad, 0xbe};
    const pcap_time_anchor_t anchor = {
        .monotonic_anchor_us = UINT64_C(0x100000000),
        .epoch_anchor_us = UINT64_C(1700000000) * UINT64_C(1000000) + 999900u,
    };
    rx_capture_view_t view = make_view(mac, sizeof(mac), sizeof(mac), 6,
                                       -42, anchor.monotonic_anchor_us + 250u);
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 0;

    CHECK(encode(&view, &anchor, out, sizeof(out), &written, &stats, &reason));
    CHECK(reason == PCAP_REJECT_NONE);
    CHECK(get_le32(&out[0]) == 1700000001u);
    CHECK(get_le32(&out[4]) == 150u);
    CHECK(get_le32(&out[8]) == 18u);
    CHECK(get_le32(&out[12]) == 18u);
    CHECK(written == PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + sizeof(mac));
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], mac, sizeof(mac)) == 0);
    /* The Flags field says FCS absent and does not claim a bad FCS. */
    CHECK((out[RECORD_DATA_OFFSET + 8u] & 0x50u) == 0);
}

static void test_large_monotonic_time_and_epoch_range(void)
{
    static const uint8_t b = 0;
    rx_capture_view_t view = make_view(&b, 1, 1, 1, -20,
                                       UINT64_C(0x100000000) + 123u);
    pcap_time_anchor_t anchor = {0, 0};
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 0;

    CHECK(encode(&view, &anchor, out, sizeof(out), &written, &stats, &reason));
    CHECK(get_le32(&out[0]) == 4294u);
    CHECK(get_le32(&out[4]) == 967419u);

    anchor.monotonic_anchor_us = view.rx_timestamp_us;
    anchor.epoch_anchor_us = ((uint64_t)UINT32_MAX + 1u) * UINT64_C(1000000);
    CHECK(!encode(&view, &anchor, out, sizeof(out), &written, &stats, &reason));
    CHECK(written == 0 && reason == PCAP_REJECT_TIME_OUT_OF_RANGE);
    CHECK(stats.rejected[PCAP_REJECT_TIME_OUT_OF_RANGE] == 1);

    anchor.monotonic_anchor_us = 0;
    anchor.epoch_anchor_us = UINT64_MAX - 10u;
    view.rx_timestamp_us = 11u;
    CHECK(!encode(&view, &anchor, out, sizeof(out), &written, &stats, &reason));
    CHECK(reason == PCAP_REJECT_TIME_OUT_OF_RANGE);
    CHECK(stats.rejected[PCAP_REJECT_TIME_OUT_OF_RANGE] == 2);
}

static void test_timestamp_before_anchor_rejected_atomically(void)
{
    static const uint8_t b = 0;
    rx_capture_view_t view = make_view(&b, 1, 1, 1, -20, 99);
    const pcap_time_anchor_t anchor = {100, 0};
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    memset(out, 0xa5, sizeof(out));
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 8;

    CHECK(!encode(&view, &anchor, out, sizeof(out), &written, &stats, &reason));
    CHECK(written == 0 && reason == PCAP_REJECT_TIME_BEFORE_ANCHOR);
    CHECK(stats.rejected[PCAP_REJECT_TIME_BEFORE_ANCHOR] == 1);
    for (size_t i = 0; i < sizeof(out); ++i) {
        CHECK(out[i] == 0xa5);
    }
}

static void test_empty_and_short_mac_inputs(void)
{
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    size_t written = 0;
    rx_capture_view_t empty = make_view(NULL, 0, 0, 1, -33, 0);

    CHECK(encode(&empty, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le32(&out[8]) == 15u);
    CHECK(get_le32(&out[12]) == 15u);
    CHECK(written == PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u);

    static const uint8_t short_mac[] = {0x08, 0x00, 0x42};
    rx_capture_view_t short_view = make_view(short_mac, sizeof(short_mac),
                                              sizeof(short_mac), 1, -33, 1);
    CHECK(encode(&short_view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le32(&out[8]) == 18u);
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], short_mac, sizeof(short_mac)) == 0);
}

static void test_invalid_original_and_contradictory_lengths_counted(void)
{
    static const uint8_t bytes[] = {1, 2};
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 0;
    rx_capture_view_t view = make_view(bytes, sizeof(bytes), sizeof(bytes),
                                       1, -30, 1);
    view.original_mac_length_valid = false;
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                  &stats, &reason));
    CHECK(reason == PCAP_REJECT_INVALID_ORIGINAL_LENGTH);
    CHECK(stats.rejected[PCAP_REJECT_INVALID_ORIGINAL_LENGTH] == 1);

    view = make_view(bytes, 2, 1, 1, -30, 1);
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                  &stats, &reason));
    CHECK(reason == PCAP_REJECT_INCONSISTENT_LENGTHS);
    CHECK(stats.rejected[PCAP_REJECT_INCONSISTENT_LENGTHS] == 1);

    view = make_view(bytes, 1, 2, 1, -30, 1);
    view.capture_truncated = false;
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                  &stats, &reason));
    CHECK(reason == PCAP_REJECT_INCONSISTENT_LENGTHS);
    CHECK(stats.rejected[PCAP_REJECT_INCONSISTENT_LENGTHS] == 2);

    view = make_view(bytes, 1, 1, 1, -30, 1);
    view.fcs_policy = (rx_capture_fcs_policy_t)1;
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                  &stats, &reason));
    CHECK(reason == PCAP_REJECT_UNSUPPORTED_FCS_POLICY);
    CHECK(stats.rejected[PCAP_REJECT_UNSUPPORTED_FCS_POLICY] == 1);
}

static void test_capacity_failure_is_atomic(void)
{
    static const uint8_t bytes[] = {0xaa, 0xbb, 0xcc, 0xdd};
    rx_capture_view_t view = make_view(bytes, sizeof(bytes), sizeof(bytes),
                                       6, -60, 1);
    uint8_t out[PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + sizeof(bytes)];
    memset(out, 0xa5, sizeof(out));
    pcap_serializer_stats_t stats = {0};
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    size_t written = 0;

    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out) - 1u, &written,
                  &stats, &reason));
    CHECK(written == 0 && reason == PCAP_REJECT_OUTPUT_CAPACITY);
    CHECK(stats.rejected[PCAP_REJECT_OUTPUT_CAPACITY] == 1);
    for (size_t i = 0; i < sizeof(out); ++i) {
        CHECK(out[i] == 0xa5);
    }
}

static void test_fcs_removal_and_truncated_body_integration(void)
{
    radio_packet_t packet = {0};
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    size_t written = 0;
    rx_capture_view_t view;

    for (uint16_t i = 0; i < 40u; ++i) {
        packet.data[i] = (uint8_t)i;
    }
    packet.channel = 11;
    packet.rssi = -50;
    packet.rx_timestamp_us = 100;

    /* Full driver copy: the last four bytes are FCS and never serialized. */
    packet.orig_length = 34;
    packet.length = 34;
    CHECK(rx_path_make_capture_view(&packet, &view));
    CHECK(view.captured_mac_length == 30 && view.original_mac_length == 30);
    CHECK(!view.capture_truncated);
    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le32(&out[8]) == 45u && get_le32(&out[12]) == 45u);
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], packet.data, 30u) == 0);

    /* The copy contains only two FCS bytes; the visible MAC remains whole. */
    packet.length = 32;
    CHECK(rx_path_make_capture_view(&packet, &view));
    CHECK(view.captured_mac_length == 30 && view.original_mac_length == 30);
    CHECK(!view.capture_truncated);
    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le32(&out[8]) == 45u && get_le32(&out[12]) == 45u);
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], packet.data, 30u) == 0);

    /* A body cut is reflected in incl_len/orig_len without zero padding. */
    packet.orig_length = 40; /* 36 MAC bytes + 4-byte FCS */
    packet.length = 32;      /* only 32 MAC bytes captured */
    CHECK(rx_path_make_capture_view(&packet, &view));
    CHECK(view.captured_mac_length == 32 && view.original_mac_length == 36);
    CHECK(view.capture_truncated);
    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(get_le32(&out[8]) == 47u && get_le32(&out[12]) == 51u);
    CHECK(written == PCAP_SERIALIZER_RECORD_HEADER_LEN + 15u + 32u);
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], packet.data, 32u) == 0);

    packet.orig_length = 3;
    packet.length = 3;
    CHECK(rx_path_make_capture_view(&packet, &view));
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                  &stats, &reason));
    CHECK(reason == PCAP_REJECT_INVALID_ORIGINAL_LENGTH);
}

static void test_512_byte_bound_and_maximum_record(void)
{
    uint8_t mac[RADIO_PACKET_MAX_LEN];
    for (size_t i = 0; i < sizeof(mac); ++i) {
        mac[i] = (uint8_t)(i ^ 0x5au);
    }
    rx_capture_view_t view = make_view(mac, sizeof(mac), 896, 1, -31, 1);
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    pcap_serializer_stats_t stats = {0};
    size_t written = 0;

    CHECK(sizeof(out) == 543u);
    CHECK(encode(&view, &k_anchor_zero, out, sizeof(out), &written,
                 &stats, NULL));
    CHECK(written == sizeof(out));
    CHECK(get_le32(&out[8]) == PCAP_SERIALIZER_SNAPLEN);
    CHECK(get_le32(&out[12]) == 911u);
    CHECK(memcmp(&out[RADIO_FRAME_OFFSET], mac, sizeof(mac)) == 0);

    memset(out, 0xa5, sizeof(out));
    pcap_reject_reason_t reason = PCAP_REJECT_NONE;
    CHECK(!encode(&view, &k_anchor_zero, out, sizeof(out) - 1u, &written,
                  &stats, &reason));
    CHECK(written == 0 && reason == PCAP_REJECT_OUTPUT_CAPACITY);
    for (size_t i = 0; i < sizeof(out); ++i) {
        CHECK(out[i] == 0xa5);
    }
}

typedef struct {
    uint8_t mac[160];
    uint16_t captured_length;
    uint16_t original_length;
    uint8_t channel;
    int8_t rssi;
    uint64_t rx_timestamp_us;
} reference_frame_t;

#define REFERENCE_FRAME_COUNT 11u
#define REFERENCE_MONOTONIC_BASE UINT64_C(0x100000000)

static reference_frame_t s_reference_frames[REFERENCE_FRAME_COUNT];

static const uint8_t k_ap[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t k_sta[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
static const uint8_t k_broadcast[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static void init_header(uint8_t *mac, uint16_t frame_control,
                        const uint8_t addr1[6], const uint8_t addr2[6],
                        const uint8_t addr3[6])
{
    put_le16(&mac[0], frame_control);
    put_le16(&mac[2], 0);
    memcpy(&mac[4], addr1, 6);
    memcpy(&mac[10], addr2, 6);
    memcpy(&mac[16], addr3, 6);
    put_le16(&mac[22], 0);
}

static uint16_t append_test_snap(uint8_t *mac, uint16_t offset,
                                 uint16_t ethertype)
{
    static const uint8_t llc_snap_prefix[6] = {
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00,
    };
    memcpy(&mac[offset], llc_snap_prefix, sizeof(llc_snap_prefix));
    put_be16(&mac[offset + 6u], ethertype);
    return (uint16_t)(offset + 8u);
}

static void add_reference_meta(size_t index, uint16_t length,
                               uint16_t original_length, uint8_t channel,
                               int8_t rssi, uint64_t delta_us)
{
    s_reference_frames[index].captured_length = length;
    s_reference_frames[index].original_length = original_length;
    s_reference_frames[index].channel = channel;
    s_reference_frames[index].rssi = rssi;
    s_reference_frames[index].rx_timestamp_us =
        REFERENCE_MONOTONIC_BASE + delta_us;
}

static void build_reference_frames(void)
{
    memset(s_reference_frames, 0, sizeof(s_reference_frames));

    /* Synthetic beacon: fixed fields, SSID, one Supported Rates element. */
    reference_frame_t *frame = &s_reference_frames[0];
    init_header(frame->mac, 0x0080u, k_broadcast, k_ap, k_ap);
    memset(&frame->mac[24], 0, 8); /* TSF */
    put_le16(&frame->mac[32], 100); /* beacon interval */
    put_le16(&frame->mac[34], 0x0431u); /* capabilities */
    frame->mac[36] = 0; frame->mac[37] = 4;
    memcpy(&frame->mac[38], "TST1", 4);
    frame->mac[42] = 1; frame->mac[43] = 1; frame->mac[44] = 0x82;
    add_reference_meta(0, 45, 45, 1, -42, 0);

    /* Synthetic probe request with a wildcard SSID. */
    frame = &s_reference_frames[1];
    init_header(frame->mac, 0x0040u, k_broadcast, k_sta, k_broadcast);
    frame->mac[24] = 0; frame->mac[25] = 0;
    add_reference_meta(1, 26, 26, 6, -65, 50);

    /* Ordinary Data with an unknown SNAP EtherType for a quiet decode. */
    frame = &s_reference_frames[2];
    init_header(frame->mac, 0x0008u, k_ap, k_sta, k_ap);
    (void)append_test_snap(frame->mac, 24, 0x88b5u);
    add_reference_meta(2, 32, 32, 11, -47, 200);

    /* QoS Data; channel zero intentionally exercises omitted channel info. */
    frame = &s_reference_frames[3];
    init_header(frame->mac, 0x0088u, k_ap, k_sta, k_ap);
    put_le16(&frame->mac[24], 0);
    (void)append_test_snap(frame->mac, 26, 0x88b5u);
    add_reference_meta(3, 34, 34, 0, -55, 1100);

    /* Data Null: no LLC/payload follows the 24-byte MAC header. */
    frame = &s_reference_frames[4];
    init_header(frame->mac, 0x0048u, k_ap, k_sta, k_ap);
    add_reference_meta(4, 24, 24, 14, -78, 2100);

    /* QoS Null: 24-byte header plus two-byte QoS Control, no payload. */
    frame = &s_reference_frames[5];
    init_header(frame->mac, 0x00c8u, k_ap, k_sta, k_ap);
    put_le16(&frame->mac[24], 0);
    add_reference_meta(5, 26, 26, 1, -83, 3100);

    /* ACK control frame has a 10-byte MAC header. */
    frame = &s_reference_frames[6];
    put_le16(&frame->mac[0], 0x00d4u);
    put_le16(&frame->mac[2], 0);
    memcpy(&frame->mac[4], k_ap, 6);
    add_reference_meta(6, 10, 10, 6, -90, 1000000);

    /* EAP-Packet with a complete EAP Identity request. */
    frame = &s_reference_frames[7];
    init_header(frame->mac, 0x0108u, k_ap, k_sta, k_ap); /* ToDS */
    uint16_t offset = append_test_snap(frame->mac, 24, 0x888eu);
    frame->mac[offset + 0u] = 2;
    frame->mac[offset + 1u] = 0;
    put_be16(&frame->mac[offset + 2u], 5);
    frame->mac[offset + 4u] = 1; /* EAP Request */
    frame->mac[offset + 5u] = 0x42;
    put_be16(&frame->mac[offset + 6u], 5);
    frame->mac[offset + 8u] = 1; /* Identity */
    add_reference_meta(7, 41, 41, 6, -42, 1000100);

    /* Complete pairwise EAPOL-Key (synthetic RSN descriptor, no key data). */
    frame = &s_reference_frames[8];
    init_header(frame->mac, 0x0208u, k_sta, k_ap, k_ap); /* FromDS */
    offset = append_test_snap(frame->mac, 24, 0x888eu);
    frame->mac[offset + 0u] = 2;
    frame->mac[offset + 1u] = 3;
    put_be16(&frame->mac[offset + 2u], 95);
    uint8_t *key_body = &frame->mac[offset + 4u];
    memset(key_body, 0, 95);
    key_body[0] = 2; /* RSN Key descriptor */
    put_be16(&key_body[1], 0x0089u); /* descriptor v1, pairwise, ACK */
    put_be16(&key_body[93], 0); /* Key Data Length */
    add_reference_meta(8, 24u + 8u + 4u + 95u,
                       24u + 8u + 4u + 95u, 11, -37, 1100000);

    /* Capture-truncated copy of that complete on-air Key frame. */
    frame = &s_reference_frames[9];
    memcpy(frame->mac, s_reference_frames[8].mac,
           s_reference_frames[8].original_length);
    add_reference_meta(9, 24u + 8u + 4u + 12u,
                       24u + 8u + 4u + 95u, 14, -60, 1200000);

    /* Four-address WDS Data frame: retained as bytes, unsupported by EAPOL. */
    frame = &s_reference_frames[10];
    init_header(frame->mac, 0x0308u, k_ap, k_sta, k_ap);
    memcpy(&frame->mac[24], k_broadcast, 6);
    add_reference_meta(10, 30, 30, 15, -80, 1234567);
}

static rx_capture_view_t reference_view(const reference_frame_t *frame)
{
    return make_view(frame->mac, frame->captured_length,
                     frame->original_length, frame->channel, frame->rssi,
                     frame->rx_timestamp_us);
}

static void test_reference_pcap_generated_from_synthetic_fixtures(void)
{
    build_reference_frames();
    const pcap_time_anchor_t anchor = {
        .monotonic_anchor_us = REFERENCE_MONOTONIC_BASE,
        .epoch_anchor_us = UINT64_C(1700000000) * UINT64_C(1000000) + 999900u,
    };
    uint8_t out[PCAP_SERIALIZER_MAX_RECORD_LEN];
    uint8_t global[PCAP_SERIALIZER_FILE_HEADER_LEN];
    size_t written = 0;
    FILE *file = fopen("build/reference.pcap", "wb");
    CHECK(file != NULL);

    CHECK(pcap_serializer_write_global_header(global, sizeof(global), &written));
    CHECK(written == sizeof(global));
    CHECK(fwrite(global, 1, written, file) == written);

    pcap_serializer_stats_t stats = {0};
    for (size_t i = 0; i < REFERENCE_FRAME_COUNT; ++i) {
        rx_capture_view_t view = reference_view(&s_reference_frames[i]);
        CHECK(encode(&view, &anchor, out, sizeof(out), &written, &stats, NULL));
        CHECK(fwrite(out, 1, written, file) == written);
    }
    CHECK(fclose(file) == 0);
    CHECK(stats.records_encoded == REFERENCE_FRAME_COUNT);
    CHECK(stats.records_without_channel == 2);
}

static void register_pcap_tests(void)
{
    test_register("pcap_global_header_golden", test_global_header_golden);
    test_register("pcap_global_header_short_atomic",
                  test_global_header_short_capacity_is_atomic);
    test_register("pcap_channel_radiotap_golden",
                  test_channel_radiotap_golden_and_frequencies);
    test_register("pcap_unknown_channel_omitted",
                  test_unknown_channel_omits_channel_field);
    test_register("pcap_timestamp_boundary_payload",
                  test_record_header_timestamp_boundary_and_payload);
    test_register("pcap_large_monotonic_and_range",
                  test_large_monotonic_time_and_epoch_range);
    test_register("pcap_timestamp_before_anchor_atomic",
                  test_timestamp_before_anchor_rejected_atomically);
    test_register("pcap_empty_short_mac", test_empty_and_short_mac_inputs);
    test_register("pcap_invalid_and_contradictory_lengths",
                  test_invalid_original_and_contradictory_lengths_counted);
    test_register("pcap_capacity_failure_atomic", test_capacity_failure_is_atomic);
    test_register("pcap_fcs_and_capture_truncation",
                  test_fcs_removal_and_truncated_body_integration);
    test_register("pcap_512_bound_max_record",
                  test_512_byte_bound_and_maximum_record);
    test_register("pcap_reference_generate_synthetic",
                  test_reference_pcap_generated_from_synthetic_fixtures);
}

int main(void)
{
    register_pcap_tests();
    return test_run_all() == 0 ? 0 : 1;
}
