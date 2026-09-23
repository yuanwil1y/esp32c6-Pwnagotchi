/* Phase 1.5 host regression tests: 802.11 parser (production code).
 * Covers Frame Control classification and the beacon/probe IE walk with
 * captured-length / FCS / IE boundary semantics. */
#include "ieee80211_parser.h"
#include "radio_types.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

/*
 * Whether MAC body bytes are missing from the capture (the only case in
 * which the parser may report the tail as incomplete instead of judging
 * it). Mirrors rx_path_body_truncated(); kept local so the parser suite
 * stays focused on parser semantics.
 */
static bool mac_body_cut(const radio_packet_t *pkt)
{
    return pkt->orig_length >= 4 &&
           pkt->length < (uint16_t)(pkt->orig_length - 4);
}

/* ---------------- frame builders ---------------- */

typedef struct {
    uint8_t buf[600];
    uint16_t len; /* total bytes written */
} frame_t;

static void beacon_init(frame_t *f, uint8_t fc0, uint8_t fc1)
{
    memset(f, 0, sizeof(*f));
    f->buf[0] = fc0;
    f->buf[1] = fc1;
    for (int i = 0; i < 6; i++) {
        f->buf[4 + i] = 0xFF;                 /* addr1 broadcast */
        f->buf[10 + i] = (uint8_t)(0x20 + i); /* addr2 transmitter */
        f->buf[16 + i] = (uint8_t)(0x40 + i); /* addr3 = BSSID */
    }
    f->buf[32] = 0x64; /* beacon interval 100 TU */
    f->buf[33] = 0x00;
    f->buf[34] = 0x01; /* capability: no PRIVACY bit */
    f->buf[35] = 0x01;
    f->len = 36;
}

static void beacon_init_default(frame_t *f)
{
    beacon_init(f, 0x80, 0x00); /* mgmt, subtype 8 (beacon) */
}

static void append_ie(frame_t *f, uint8_t id, const uint8_t *data, uint8_t ie_len)
{
    f->buf[f->len++] = id;
    f->buf[f->len++] = ie_len;
    if (ie_len > 0) {
        memcpy(&f->buf[f->len], data, ie_len);
        f->len = (uint16_t)(f->len + ie_len);
    }
}

/* Filler IEs (element id 250, ignored by the parser) until the IE area
 * ends exactly at body_end (assumes body_end is IE-aligned). */
static void beacon_fill_to(frame_t *f, uint16_t body_end)
{
    static uint8_t filler[255]; /* zero bytes, never read by the parser */
    while (f->len + 2 <= body_end) {
        const uint16_t room = (uint16_t)(body_end - f->len);
        const uint8_t ie_len = (uint8_t)((room - 2 > 255) ? 255 : room - 2);
        append_ie(f, 250, filler, ie_len);
    }
}

/* ---------------- Frame Control (Phase 1B, regression guard) -------- */

static void t_parse_fc_basic(void)
{
    const uint8_t frame[] = {0x80, 0x00, 0x00, 0x00};
    ieee80211_frame_info_t info = {0};
    CHECK(ieee80211_parse(frame, sizeof(frame), &info));
    CHECK(info.valid);
    CHECK(info.type == IEEE80211_TYPE_MGMT);
    CHECK(info.fc.type == 0);
    CHECK(info.fc.subtype == 8);
    CHECK(info.fc.protocol_version == 0);
    CHECK(!info.fc.protected_frame);

    const uint8_t qos_data[] = {0x88, 0x01};
    memset(&info, 0, sizeof(info));
    CHECK(ieee80211_parse(qos_data, sizeof(qos_data), &info));
    CHECK(info.valid);
    CHECK(info.type == IEEE80211_TYPE_DATA);
    CHECK(info.fc.subtype == 8);
    CHECK(info.fc.to_ds);

    const uint8_t rts[] = {(uint8_t)((IEEE80211_CTRL_RTS << 4) | (1 << 2)), 0x00};
    memset(&info, 0, sizeof(info));
    CHECK(ieee80211_parse(rts, sizeof(rts), &info));
    CHECK(info.type == IEEE80211_TYPE_CTRL);
    CHECK(info.fc.subtype == IEEE80211_CTRL_RTS);
}

static void t_parse_short_rejected(void)
{
    const uint8_t frame[] = {0x80};
    ieee80211_frame_info_t info;
    CHECK(!ieee80211_parse(frame, 1, &info));
    CHECK(!ieee80211_parse(NULL, 4, &info));
}

/* ---------------- beacon / probe response IE walk ------------------- */

static void t_beacon_minimal_complete(void)
{
    frame_t f;
    beacon_init_default(&f); /* fixed fields only, zero IEs */

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.ie_count == 0);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.ie_walk_incomplete == false);
    CHECK(obs.complete == true);
    CHECK(obs.ssid_len == 0);
    CHECK(obs.hidden_ssid == false);
    CHECK(obs.advertised_channel == 0);
    CHECK(obs.bssid[0] == 0x40);
}

static void t_beacon_typical_fields(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"TEST", 4);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){6}, 1);
    append_ie(&f, IEEE80211_IE_RSN,
              (const uint8_t[]){0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
                                0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x00},
              16);

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.ssid_len == 4);
    CHECK(memcmp(obs.ssid, "TEST", 4) == 0);
    CHECK(!obs.hidden_ssid);
    CHECK(obs.advertised_channel == 6);
    CHECK(obs.ds_param_present);
    CHECK(obs.rsn_present);
    CHECK(obs.privacy == false);
    CHECK(obs.ie_count == 3);
    CHECK(obs.complete == true);
    CHECK(ieee80211_classify_security(&obs) == IEEE80211_SEC_RSN);
}

/* SSID length 0 (hidden) / 32 (max legal) / 33 (illegal). */
static void t_ssid_lengths(void)
{
    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;

    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"", 0);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.hidden_ssid == true);
    CHECK(obs.ssid_len == 0);
    CHECK(obs.malformed_ie == false);

    beacon_init_default(&f);
    uint8_t long_ssid[IEEE80211_SSID_MAX_LEN];
    memset(long_ssid, 'x', sizeof(long_ssid));
    append_ie(&f, IEEE80211_IE_SSID, long_ssid, IEEE80211_SSID_MAX_LEN);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.ssid_len == IEEE80211_SSID_MAX_LEN);
    CHECK(!obs.hidden_ssid);
    CHECK(obs.malformed_ie == false);

    beacon_init_default(&f);
    uint8_t too_long[33];
    memset(too_long, 'y', sizeof(too_long));
    append_ie(&f, IEEE80211_IE_SSID, too_long, 33);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == true);
    CHECK(obs.complete == false);
    CHECK(obs.ssid_len == 0); /* not stored */
}

/* SSID IE whose bytes are all zero is a hidden-SSID representation, not a
 * printable name; raw bytes are never relied on via strlen. */
static void t_ssid_all_zero_is_hidden(void)
{
    frame_t f;
    beacon_init_default(&f);
    const uint8_t zeros[4] = {0, 0, 0, 0};
    append_ie(&f, IEEE80211_IE_SSID, zeros, 4);

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.hidden_ssid == true);
    CHECK(obs.ssid_len == 0);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == true);
}

/* Duplicate critical IEs (SSID): first occurrence wins, observation is
 * flagged and must not be treated as complete/negative evidence. */
static void t_duplicate_ssid_first_wins(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"AAA", 3);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"BBB", 3);

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.ssid_len == 3);
    CHECK(memcmp(obs.ssid, "AAA", 3) == 0);
    CHECK(obs.dup_critical_ie == true);
    CHECK(obs.complete == false);
    CHECK(obs.malformed_ie == false);
}

/* DS Parameter Set: only length==1 with an in-range value may write the
 * advertised channel; rx_channel stays independent of it. */
static void t_ds_param_validation(void)
{
    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;

    /* Valid. */
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){6}, 1);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.advertised_channel == 6);
    CHECK(obs.ds_param_present == true);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == true);

    /* Length 0: malformed, channel not written. */
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_DS_PARAM, NULL, 0);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == true);
    CHECK(obs.advertised_channel == 0);
    CHECK(obs.ds_param_present == false);

    /* Length 2: malformed, channel not written. */
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){6, 6}, 2);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == true);
    CHECK(obs.advertised_channel == 0);
    CHECK(obs.ds_param_present == false);

    /* Value 0: structurally fine but not a valid channel number. */
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){0}, 1);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == false);
    CHECK(obs.ds_param_present == false);
    CHECK(obs.advertised_channel == 0);

    /* Value 200: same treatment. */
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){200}, 1);
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == false);
    CHECK(obs.ds_param_present == false);
    CHECK(obs.advertised_channel == 0);
}

/* A 1-byte tail in a COMPLETE body is trailing garbage: malformed. */
static void t_trailing_byte_in_complete_body(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"AB", 2);
    const uint16_t good_len = f.len;
    f.len = (uint16_t)(good_len + 1); /* one stray byte */
    f.buf[good_len] = 0x00;

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == true);
    CHECK(obs.complete == false);
}

/* IE header present but its declared body runs past the end of a COMPLETE
 * frame: malformed. */
static void t_ie_body_overrun_complete_frame(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"AB", 2);
    /* Claim 40 bytes of vendor data but write only the header + 3. */
    append_ie(&f, IEEE80211_IE_VENDOR, (const uint8_t[]){0, 1, 2}, 3);
    /* Shrink the frame so the last IE's body is truncated on-air... */
    const uint16_t cut = (uint16_t)(f.len - 2);
    f.len = cut;

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
    CHECK(obs.malformed_ie == true);
    CHECK(obs.complete == false);
}

/* The capture (not the air) ends inside an IE body: the tail cannot be
 * judged -> ie_walk_incomplete, explicitly NOT malformed, explicitly not
 * complete. */
static void t_capture_cut_inside_ie_body(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"AB", 2);
    append_ie(&f, IEEE80211_IE_VENDOR,
              (const uint8_t[]){0, 1, 2, 3, 4, 5, 6, 7}, 8);
    const uint16_t full_len = f.len;

    ieee80211_parse_opts_t opts = {.capture_truncated = true};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, (uint16_t)(full_len - 4),
                                               &opts, &obs));
    CHECK(obs.ie_walk_incomplete == true);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == false);
}

/* Capture cut between IEs (IE boundary): the walk is complete up to the
 * boundary and the tail is unknown, not malformed. */
static void t_capture_cut_at_ie_boundary(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"AB", 2);
    append_ie(&f, IEEE80211_IE_DS_PARAM, (const uint8_t[]){11}, 1);
    const uint16_t full_len = f.len;

    ieee80211_parse_opts_t opts = {.capture_truncated = true};
    ieee80211_ap_observation_t obs;
    /* Truncate 2 bytes into the last IE so only full IEs are visible and
     * the DS Parameter body is cut. */
    CHECK(ieee80211_parse_beacon_or_probe_resp(f.buf, (uint16_t)(full_len - 2),
                                               &opts, &obs));
    CHECK(obs.ie_count == 1);
    CHECK(obs.advertised_channel == 0);
    CHECK(obs.ie_walk_incomplete == true);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == false);
}

/* The end-to-end FCS contract: a 513-byte frame stored truncated at 512
 * carries 3 partially-captured FCS bytes at the tail; the parse window
 * must stop at orig_length - 4 so the FCS is never walked as IEs. */
static void t_fcs_never_walked_as_ie_513(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"S26", 3);
    beacon_fill_to(&f, 509); /* IE area ends exactly at body end 509 */
    CHECK(f.len == 509);

    /* Pooled copy: 512 bytes; the 4-byte FCS lives at 509..512 on-air, so
     * bytes 509..511 of the copy are the first three FCS bytes. */
    static uint8_t copy[512];
    memcpy(copy, f.buf, 509);
    copy[509] = 0xDE;
    copy[510] = 0xAD;
    copy[511] = 0xBE;

    radio_packet_t pkt = {0};
    pkt.length = 512;
    pkt.orig_length = 513;
    memcpy(pkt.data, copy, 512);

    const uint16_t parse_len = rx_path_parse_length(&pkt);
    CHECK(parse_len == 509);

    /* Only the FCS was lost, not MAC body bytes: the body is complete. */
    ieee80211_parse_opts_t opts = {.capture_truncated = mac_body_cut(&pkt)};
    CHECK(opts.capture_truncated == false);
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(pkt.data, parse_len, &opts, &obs));
    CHECK(obs.ssid_len == 3);
    CHECK(memcmp(obs.ssid, "S26", 3) == 0);
    CHECK(obs.malformed_ie == false); /* FCS not misread as an IE */
    CHECK(obs.ie_walk_incomplete == false);
    CHECK(obs.complete == true);
}

/* Same contract when only part of the FCS was captured (orig 514, copy
 * 512): two FCS bytes at the tail, still excluded from the window. */
static void t_fcs_never_walked_as_ie_514(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"DUT", 3);
    beacon_fill_to(&f, 510);
    CHECK(f.len == 510);

    static uint8_t copy[512];
    memcpy(copy, f.buf, 510);
    copy[510] = 0xDE;
    copy[511] = 0xAD;

    radio_packet_t pkt = {0};
    pkt.length = 512;
    pkt.orig_length = 514;
    memcpy(pkt.data, copy, 512);

    CHECK(rx_path_parse_length(&pkt) == 510);
    CHECK(mac_body_cut(&pkt) == false);

    ieee80211_parse_opts_t opts = {.capture_truncated = mac_body_cut(&pkt)};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(pkt.data,
                                               rx_path_parse_length(&pkt),
                                               &opts, &obs));
    CHECK(obs.ssid_len == 3);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == true);
}

/* Capture cut deep inside the MAC body (before any IE): the copy is the
 * whole parse window; nothing is malformed, but it is not complete. */
static void t_capture_cut_inside_mac_body(void)
{
    frame_t f;
    beacon_init_default(&f);
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"CUT", 3);
    beacon_fill_to(&f, 200);

    radio_packet_t pkt = {0};
    pkt.length = 100; /* cut at 100 of 200: MAC body bytes are lost */
    pkt.orig_length = 204;
    memcpy(pkt.data, f.buf, 100);

    const uint16_t parse_len = rx_path_parse_length(&pkt);
    CHECK(parse_len == 100);
    CHECK(mac_body_cut(&pkt) == true);

    ieee80211_parse_opts_t opts = {.capture_truncated = mac_body_cut(&pkt)};
    ieee80211_ap_observation_t obs;
    CHECK(ieee80211_parse_beacon_or_probe_resp(pkt.data, parse_len, &opts, &obs));
    CHECK(obs.ie_walk_incomplete == true);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == false);
}

/* ---------------- deep-parse guards (conservative rejection) --------- */

static void t_deep_parse_rejects_protocol_version_1(void)
{
    frame_t f;
    beacon_init(&f, 0x81, 0x00); /* protocol version 1 */

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(!ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
}

/* order=1 management frames carry an HT Control field after the FC: a
 * variable header this parser does not model -> conservative reject. */
static void t_deep_parse_rejects_order_bit(void)
{
    frame_t f;
    beacon_init(&f, 0x80, 0x80); /* order bit set */

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(!ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
}

/* Fragmented management bodies must not be parsed as if complete. */
static void t_deep_parse_rejects_more_fragments(void)
{
    frame_t f;
    beacon_init(&f, 0x80, 0x04); /* More Fragments set */

    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(!ieee80211_parse_beacon_or_probe_resp(f.buf, f.len, &opts, &obs));
}

static void t_deep_parse_rejects_short_fixed_body(void)
{
    frame_t f;
    beacon_init_default(&f);
    /* 24-byte header present but fixed body cut to < 12 bytes. */
    ieee80211_parse_opts_t opts = {0};
    ieee80211_ap_observation_t obs;
    CHECK(!ieee80211_parse_beacon_or_probe_resp(f.buf, 30, &opts, &obs));
    CHECK(!ieee80211_parse_beacon_or_probe_resp(f.buf, 35, &opts, &obs));
}

/* ---------------- probe requests ------------------------------------ */

static void t_probe_req_parse_and_truncation(void)
{
    frame_t f;
    beacon_init(&f, 0x40, 0x00); /* probe request, subtype 4 */
    append_ie(&f, IEEE80211_IE_SSID, (const uint8_t *)"XPL", 3);

    ieee80211_parse_opts_t opts = {0};
    ieee80211_probe_req_observation_t obs;
    CHECK(ieee80211_parse_probe_request(f.buf, f.len, &opts, &obs));
    CHECK(obs.ssid_len == 3);
    CHECK(!obs.wildcard_ssid);
    CHECK(obs.complete == true);
    CHECK(obs.source[0] == 0x20);

    /* Wildcard probe (SSID len 0). */
    frame_t w;
    beacon_init(&w, 0x40, 0x00);
    append_ie(&w, IEEE80211_IE_SSID, (const uint8_t *)"", 0);
    CHECK(ieee80211_parse_probe_request(w.buf, w.len, &opts, &obs));
    CHECK(obs.wildcard_ssid == true);

    /* Truncated capture: incomplete, not malformed. */
    ieee80211_parse_opts_t trunc = {.capture_truncated = true};
    CHECK(ieee80211_parse_probe_request(f.buf, (uint16_t)(f.len - 2), &trunc,
                                        &obs));
    CHECK(obs.ie_walk_incomplete == true);
    CHECK(obs.malformed_ie == false);
    CHECK(obs.complete == false);
}

int main(void)
{
    test_register("parse_fc_basic", t_parse_fc_basic);
    test_register("parse_short_rejected", t_parse_short_rejected);
    test_register("beacon_minimal_complete", t_beacon_minimal_complete);
    test_register("beacon_typical_fields", t_beacon_typical_fields);
    test_register("ssid_lengths", t_ssid_lengths);
    test_register("ssid_all_zero_is_hidden", t_ssid_all_zero_is_hidden);
    test_register("duplicate_ssid_first_wins", t_duplicate_ssid_first_wins);
    test_register("ds_param_validation", t_ds_param_validation);
    test_register("trailing_byte_in_complete_body",
                  t_trailing_byte_in_complete_body);
    test_register("ie_body_overrun_complete_frame",
                  t_ie_body_overrun_complete_frame);
    test_register("capture_cut_inside_ie_body",
                  t_capture_cut_inside_ie_body);
    test_register("capture_cut_at_ie_boundary",
                  t_capture_cut_at_ie_boundary);
    test_register("fcs_never_walked_as_ie_513",
                  t_fcs_never_walked_as_ie_513);
    test_register("fcs_never_walked_as_ie_514",
                  t_fcs_never_walked_as_ie_514);
    test_register("capture_cut_inside_mac_body",
                  t_capture_cut_inside_mac_body);
    test_register("deep_parse_rejects_protocol_version_1",
                  t_deep_parse_rejects_protocol_version_1);
    test_register("deep_parse_rejects_order_bit",
                  t_deep_parse_rejects_order_bit);
    test_register("deep_parse_rejects_more_fragments",
                  t_deep_parse_rejects_more_fragments);
    test_register("deep_parse_rejects_short_fixed_body",
                  t_deep_parse_rejects_short_fixed_body);
    test_register("probe_req_parse_and_truncation",
                  t_probe_req_parse_and_truncation);
    return test_run_all();
}
