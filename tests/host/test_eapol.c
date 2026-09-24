/* Phase 3A host regression tests: production EAPOL envelope parser. */
#include "eapol_parser.h"

#include <string.h>

#include "runner.h"

#define FIXTURE_CAPACITY 1024u
#define MAC_HDR_LEN 24u
#define LLC_LEN 8u

typedef struct {
    uint8_t bytes[FIXTURE_CAPACITY];
    uint16_t length;
} fixture_t;

static const uint8_t s_snap_eapol[LLC_LEN] = {
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};

static void fixture_data(fixture_t *f, uint8_t fc0, uint8_t fc1)
{
    memset(f, 0, sizeof(*f));
    f->bytes[0] = fc0;
    f->bytes[1] = fc1;
    static const uint8_t bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    static const uint8_t sta[6] = {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};
    memcpy(&f->bytes[4], bssid, sizeof(bssid));
    memcpy(&f->bytes[10], sta, sizeof(sta));
    memcpy(&f->bytes[16], bssid, sizeof(bssid));
    f->length = MAC_HDR_LEN;
}

static uint16_t fixture_header_length(const fixture_t *f)
{
    const bool wds = (f->bytes[1] & 0x03u) == 0x03u;
    const bool qos = (f->bytes[0] & 0x80u) != 0;
    const bool order = (f->bytes[1] & 0x80u) != 0;
    return (uint16_t)(MAC_HDR_LEN + (wds ? 6u : 0u) + (qos ? 2u : 0u) +
                      (qos && order ? 4u : 0u));
}

static void fixture_set_qos(fixture_t *f, uint16_t qos_control)
{
    const uint16_t offset = (uint16_t)(MAC_HDR_LEN +
                                       (((f->bytes[1] & 0x03u) == 0x03u) ? 6u : 0u));
    f->bytes[offset] = (uint8_t)qos_control;
    f->bytes[offset + 1] = (uint8_t)(qos_control >> 8);
}

static uint16_t fixture_append_snap(fixture_t *f)
{
    const uint16_t offset = fixture_header_length(f);
    memcpy(&f->bytes[offset], s_snap_eapol, sizeof(s_snap_eapol));
    f->length = (uint16_t)(offset + LLC_LEN);
    return f->length;
}

static uint16_t fixture_append_eapol(fixture_t *f, uint8_t version,
                                     uint8_t type, const uint8_t *body,
                                     uint16_t body_length, uint16_t padding)
{
    const uint16_t offset = fixture_append_snap(f);
    f->bytes[offset] = version;
    f->bytes[offset + 1] = type;
    f->bytes[offset + 2] = (uint8_t)(body_length >> 8);
    f->bytes[offset + 3] = (uint8_t)body_length;
    if (body_length > 0 && body != NULL) {
        memcpy(&f->bytes[offset + 4], body, body_length);
    }
    if (padding > 0) {
        memset(&f->bytes[offset + 4 + body_length], 0xee, padding);
    }
    f->length = (uint16_t)(offset + 4u + body_length + padding);
    return f->length;
}

static void make_key_body(uint8_t *body, uint16_t key_data_length,
                          bool pairwise, uint8_t descriptor,
                          uint8_t descriptor_version)
{
    memset(body, 0, (size_t)95u + key_data_length);
    body[0] = descriptor;
    const uint16_t key_info = (uint16_t)(descriptor_version |
                                         (pairwise ? 0x0008u : 0u));
    body[1] = (uint8_t)(key_info >> 8);
    body[2] = (uint8_t)key_info;
    body[93] = (uint8_t)(key_data_length >> 8);
    body[94] = (uint8_t)key_data_length;
    for (uint16_t i = 0; i < key_data_length; ++i) {
        body[95u + i] = (uint8_t)(0xA0u + (i & 0x1fu));
    }
}

static rx_capture_view_t fixture_view(const fixture_t *f, uint16_t captured,
                                      uint16_t original, bool truncated)
{
    rx_capture_view_t v = {
        .mac_bytes = f->bytes,
        .captured_mac_length = captured,
        .original_mac_length = original,
        .original_mac_length_valid = true,
        .rx_channel = 11,
        .rssi = -47,
        .rx_timestamp_us = UINT64_C(0x100000123),
        .fcs_policy = RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW,
        .capture_truncated = truncated,
    };
    return v;
}

static eapol_observation_t parse_fixture(const fixture_t *f)
{
    rx_capture_view_t v = fixture_view(f, f->length, f->length, false);
    eapol_observation_t out;
    memset(&out, 0, sizeof(out));
    CHECK(eapol_parse_frame(&v, &out));
    return out;
}

static void t_plain_qos_order_and_direction(void)
{
    fixture_t f;
    fixture_data(&f, 0x08, 0x01); /* ordinary Data, ToDS */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE);
    CHECK(out.direction == EAPOL_DIRECTION_STA_TO_AP);
    CHECK(out.bssid_valid && out.sta_valid);
    CHECK(out.bssid[1] == 0x11 && out.sta[1] == 0x66);
    CHECK(out.rx_timestamp_us == UINT64_C(0x100000123));
    CHECK(out.rx_channel == 11 && out.rssi == -47);

    fixture_data(&f, 0x08, 0x02); /* FromDS */
    memcpy(&f.bytes[4], &f.bytes[10], 6); /* Addr1 = destination STA */
    memcpy(&f.bytes[10], &f.bytes[16], 6); /* Addr2 = BSSID */
    fixture_append_eapol(&f, 1, EAPOL_PACKET_LOGOFF, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE);
    CHECK(out.direction == EAPOL_DIRECTION_AP_TO_STA);
    CHECK(out.bssid_valid && out.sta_valid);
    CHECK(out.bssid[1] == 0x11 && out.sta[1] == 0x66);

    fixture_data(&f, 0x88, 0x81); /* QoS Data + Order => HT Control */
    fixture_set_qos(&f, 0);
    CHECK(fixture_header_length(&f) == 30);
    fixture_append_eapol(&f, 3, EAPOL_PACKET_EAP, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE);
    CHECK(out.eapol_type == EAPOL_PACKET_EAP);

    /* Order alone on non-QoS Data adds no HT field in the shared parser. */
    fixture_data(&f, 0x08, 0x81);
    CHECK(fixture_header_length(&f) == MAC_HDR_LEN);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE);

    fixture_data(&f, 0x09, 0x01); /* nonzero 802.11 protocol version */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(!out.raw_eapol_frame);
}

static void t_strict_llc_snap_and_no_byte_search(void)
{
    fixture_t f;
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    f.bytes[MAC_HDR_LEN + 5] = 0x01; /* wrong OUI */
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_NOT_EAPOL);
    CHECK(!out.raw_eapol_frame);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    f.bytes[MAC_HDR_LEN + 6] = 0x08; /* wrong EtherType */
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_NOT_EAPOL);
    CHECK(!out.raw_eapol_frame);

    fixture_data(&f, 0x08, 0x01);
    memset(&f.bytes[MAC_HDR_LEN], 0, 24);
    memcpy(&f.bytes[MAC_HDR_LEN + 12], s_snap_eapol, LLC_LEN);
    f.bytes[MAC_HDR_LEN + 20] = 2;
    f.bytes[MAC_HDR_LEN + 21] = EAPOL_PACKET_START;
    f.length = (uint16_t)(MAC_HDR_LEN + 24u);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_NOT_EAPOL);
    CHECK(!out.raw_eapol_frame);
}

static void t_null_and_protected_never_search_body(void)
{
    fixture_t f;
    fixture_data(&f, 0x48, 0x01); /* Null */
    memcpy(&f.bytes[MAC_HDR_LEN], s_snap_eapol, LLC_LEN);
    f.bytes[MAC_HDR_LEN + LLC_LEN] = 2;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 1] = EAPOL_PACKET_START;
    f.length = 40;
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_NOT_EAPOL);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_NULL_DATA);
    CHECK(!out.raw_eapol_frame);

    fixture_data(&f, 0xC8, 0x81); /* QoS Null + Order */
    fixture_set_qos(&f, 0);
    memcpy(&f.bytes[30], s_snap_eapol, LLC_LEN);
    f.length = 38;
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_NOT_EAPOL);
    CHECK(!out.raw_eapol_frame);

    fixture_data(&f, 0x08, 0x41); /* Protected Data */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_PROTECTED);
    CHECK(!out.raw_eapol_frame);
}

static void t_unsupported_layouts_and_fragments(void)
{
    fixture_t f;
    fixture_data(&f, 0x88, 0x01); /* QoS Data */
    fixture_set_qos(&f, 0x0080); /* A-MSDU present */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_AMSDU);
    CHECK(out.unsupported_mac_layout);
    CHECK(!out.raw_eapol_frame); /* A-MSDU bytes are not searched as LLC */

    fixture_data(&f, 0x88, 0x01);
    fixture_set_qos(&f, 0x0100); /* Mesh Control Present */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_MESH);

    fixture_data(&f, 0x08, 0x00); /* no DS bit */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_NO_DS);
    CHECK(out.raw_eapol_frame && !out.bssid_valid && !out.sta_valid);

    fixture_data(&f, 0x08, 0x03); /* WDS */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_WDS);
    CHECK(out.raw_eapol_frame && !out.bssid_valid && !out.sta_valid);

    fixture_data(&f, 0xD8, 0x01); /* reserved Data+CF subtype, not MSDU */
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_SUBTYPE);
    CHECK(!out.raw_eapol_frame);

    /* First, middle and last fragment: fragment number is checked even
     * when More Fragments is clear on the last piece. */
    fixture_data(&f, 0x08, 0x05); /* ToDS + More Fragments, fragment zero */
    fixture_append_snap(&f);
    f.bytes[22] = 0x10;
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_FRAGMENT);
    CHECK(out.raw_eapol_frame);

    fixture_data(&f, 0x08, 0x05);
    fixture_append_snap(&f);
    f.bytes[22] = 0x11;
    out = parse_fixture(&f);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_FRAGMENT);
    CHECK(!out.raw_eapol_frame);

    fixture_data(&f, 0x08, 0x01); /* final fragment, More Fragments clear */
    fixture_append_snap(&f);
    f.bytes[22] = 0x12;
    out = parse_fixture(&f);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_FRAGMENT);
    CHECK(!out.raw_eapol_frame);
}

static void t_eapol_versions_lengths_padding_and_short_frames(void)
{
    fixture_t f;
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 0, EAPOL_PACKET_START, NULL, 0, 0);
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_VERSION);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 4, EAPOL_PACKET_START, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_VERSION);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, 4, NULL, 0, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_PACKET_TYPE);

    fixture_data(&f, 0x08, 0x01);
    const uint8_t one_byte[1] = {0x55};
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, one_byte, 1, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_MALFORMED); /* Start body must be empty */

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 9);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE); /* MAC padding is outside length */
    CHECK(out.eapol_body_complete);

    fixture_data(&f, 0x08, 0x01);
    const uint8_t eap_body[4] = {2, 1, 0, 4};
    fixture_append_eapol(&f, 2, EAPOL_PACKET_EAP, eap_body, sizeof(eap_body), 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE); /* BE length 4 */

    fixture_data(&f, 0x08, 0x01);
    uint16_t len = fixture_append_eapol(&f, 2, EAPOL_PACKET_EAP,
                                        eap_body, sizeof(eap_body), 0);
    f.bytes[MAC_HDR_LEN + LLC_LEN + 2] = 4;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 3] = 0;
    rx_capture_view_t v = fixture_view(&f, len, len, false);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_MALFORMED); /* BE 0x0400 exceeds full MAC */

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    v = fixture_view(&f, 23, 24, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_TRUNCATED);
    v = fixture_view(&f, 23, 23, false);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_MALFORMED);

    fixture_data(&f, 0x88, 0x81); /* short QoS + Order header */
    fixture_set_qos(&f, 0);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    v = fixture_view(&f, 29, 36, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_TRUNCATED);
    v = fixture_view(&f, 29, 29, false);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_MALFORMED);

    /* A truncated copy still has enough original-length evidence to prove
     * that the declared EAPOL body could never fit in the received frame. */
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_EAP, NULL, 0, 0);
    f.bytes[MAC_HDR_LEN + LLC_LEN + 2] = 0;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 3] = 100;
    v = fixture_view(&f, MAC_HDR_LEN + LLC_LEN + 4,
                     MAC_HDR_LEN + LLC_LEN + 20, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_MALFORMED);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    v = fixture_view(&f, MAC_HDR_LEN + LLC_LEN + 2,
                     MAC_HDR_LEN + LLC_LEN + 4, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.raw_eapol_frame && !out.eapol_header_present);
    CHECK(out.status == EAPOL_OBS_TRUNCATED);
}

static void t_key_bounds_classification_and_unknown_layout(void)
{
    fixture_t f;
    uint8_t body[512];
    make_key_body(body, 3, true, 2, 2);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 98, 5);
    eapol_observation_t out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE && out.complete_key);
    CHECK(out.key_descriptor_type == 2 && out.key_descriptor_version == 2);
    CHECK(out.key_class == EAPOL_KEY_CLASS_PAIRWISE);

    make_key_body(body, 0, false, 254, 3);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_COMPLETE && out.complete_key);
    CHECK(out.key_descriptor_type == 254);
    CHECK(out.key_class == EAPOL_KEY_CLASS_GROUP);

    make_key_body(body, 5, true, 2, 1);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 1, EAPOL_PACKET_KEY, body, 97, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_MALFORMED);
    CHECK(!out.complete_key);

    make_key_body(body, 0, true, 77, 2);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 1, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_KEY_DESCRIPTOR);
    CHECK(!out.complete_key);

    make_key_body(body, 0, true, 2, 0);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    out = parse_fixture(&f);
    CHECK(out.status == EAPOL_OBS_UNSUPPORTED);
    CHECK(out.unsupported_reason == EAPOL_UNSUPPORTED_KEY_MIC_LAYOUT);
    CHECK(!out.complete_key);
}

static void t_capture_truncation_at_snap_header_body_and_key_data(void)
{
    fixture_t f;
    eapol_observation_t out;
    rx_capture_view_t v;

    /* A capture cut inside the SNAP prefix is a truncated candidate, not a
     * confirmed raw EAPOL frame and not a malformed complete frame. */
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    v = fixture_view(&f, MAC_HDR_LEN + 4, 600, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_TRUNCATED);
    CHECK(out.partial_eapol_candidate && !out.raw_eapol_frame);
    eapol_stats_t partial_stats = {0};
    eapol_stats_record(&partial_stats, &out);
    CHECK(partial_stats.raw_eapol_frames == 0);
    CHECK(partial_stats.truncated_eapol_frames == 1);
    CHECK(partial_stats.last_observation_valid);

    /* Cut inside the four-byte EAPOL header. */
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    v = fixture_view(&f, MAC_HDR_LEN + LLC_LEN + 2, 600, true);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.raw_eapol_frame && !out.eapol_header_present);
    CHECK(out.status == EAPOL_OBS_TRUNCATED);

    /* A 512-byte pooled capture cuts an otherwise in-range declared body. */
    fixture_data(&f, 0x08, 0x01);
    const uint16_t body_len = 500;
    uint8_t large_body[500] = {0};
    fixture_append_eapol(&f, 2, EAPOL_PACKET_EAP,
                         large_body, body_len, 0);
    v = fixture_view(&f, RADIO_PACKET_MAX_LEN,
                     (uint16_t)f.length, true);
    CHECK(f.length > RADIO_PACKET_MAX_LEN);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_TRUNCATED);
    CHECK(out.raw_eapol_frame && !out.eapol_body_complete);

    /* 512-byte bound cuts inside key data. No incomplete key is counted. */
    uint8_t key_body[500];
    make_key_body(key_body, 400, true, 2, 2);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, key_body, 495, 0);
    v = fixture_view(&f, RADIO_PACKET_MAX_LEN,
                     (uint16_t)f.length, true);
    CHECK(f.length > RADIO_PACKET_MAX_LEN);
    CHECK(eapol_parse_frame(&v, &out));
    CHECK(out.status == EAPOL_OBS_TRUNCATED && !out.complete_key);
}

static void t_stats_are_bounded_frame_observations_not_handshakes(void)
{
    eapol_stats_t stats = {0};
    fixture_t f;
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_START, NULL, 0, 0);
    eapol_observation_t out = parse_fixture(&f);
    eapol_stats_record(&stats, &out);
    CHECK(stats.raw_eapol_frames == 1);
    CHECK(stats.complete_eapol_envelopes == 1);
    CHECK(stats.start_frames == 1);
    CHECK(stats.complete_key_frames == 0);

    uint8_t body[100];
    make_key_body(body, 0, true, 2, 2);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    out = parse_fixture(&f);
    eapol_stats_record(&stats, &out);
    eapol_stats_record(&stats, &out); /* a retry is another frame, no dedup */
    CHECK(stats.raw_eapol_frames == 3);
    CHECK(stats.complete_key_frames == 2);
    CHECK(stats.pairwise_key_frames == 2);

    make_key_body(body, 0, false, 2, 2);
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    out = parse_fixture(&f);
    eapol_stats_record(&stats, &out);
    CHECK(stats.group_key_frames == 1);
    CHECK(stats.complete_key_frames == 3);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    rx_capture_view_t v = fixture_view(&f, 24 + 8 + 4 + 40,
                                       f.length, true);
    CHECK(eapol_parse_frame(&v, &out));
    eapol_stats_record(&stats, &out);
    CHECK(stats.truncated_eapol_frames == 1);
    CHECK(stats.complete_key_frames == 3);

    uint8_t unknown_body[1] = {77};
    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, unknown_body, 1, 0);
    out = parse_fixture(&f);
    eapol_stats_record(&stats, &out);
    CHECK(stats.unsupported_eapol_frames == 1);
    CHECK(stats.unknown_key_descriptors == 1);
    CHECK(stats.complete_key_frames == 3);

    fixture_data(&f, 0x08, 0x01);
    fixture_append_eapol(&f, 2, EAPOL_PACKET_KEY, body, 95, 0);
    f.bytes[MAC_HDR_LEN + LLC_LEN] = 2;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 1] = EAPOL_PACKET_KEY;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 2] = 0;
    f.bytes[MAC_HDR_LEN + LLC_LEN + 3] = 0;
    out = parse_fixture(&f);
    eapol_stats_record(&stats, &out);
    CHECK(stats.malformed_eapol_frames == 1);
    CHECK(stats.complete_key_frames == 3);
    CHECK(stats.raw_eapol_frames == 7);

    stats.raw_eapol_frames = UINT32_MAX;
    eapol_stats_record(&stats, &out);
    CHECK(stats.raw_eapol_frames == UINT32_MAX); /* saturates, never wraps */
}

int main(void)
{
    test_register("eapol_plain_qos_order_direction", t_plain_qos_order_and_direction);
    test_register("eapol_strict_llc_snap", t_strict_llc_snap_and_no_byte_search);
    test_register("eapol_null_protected", t_null_and_protected_never_search_body);
    test_register("eapol_unsupported_layouts_fragments", t_unsupported_layouts_and_fragments);
    test_register("eapol_versions_lengths_padding_short", t_eapol_versions_lengths_padding_and_short_frames);
    test_register("eapol_key_bounds_classification", t_key_bounds_classification_and_unknown_layout);
    test_register("eapol_capture_truncation", t_capture_truncation_at_snap_header_body_and_key_data);
    test_register("eapol_stats_semantics", t_stats_are_bounded_frame_observations_not_handshakes);
    return test_run_all();
}
