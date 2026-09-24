/* Phase 2C host regression tests: strict RSN / WPA suite parsing and the
 * world security merge policy (production code). Fixtures cover the
 * common AKM/cipher sets, malformed structures, optional tails, capture
 * truncation around the RSN IE and the no-downgrade merge rules. */
#include "ieee80211_parser.h"
#include "world.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

/* ---------------- beacon frame builder ---------------- */

typedef struct {
    uint8_t buf[512];
    uint16_t len;
} sec_frame_t;

static const uint8_t BSSID[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x0E};

static void sec_beacon_init(sec_frame_t *f, bool privacy)
{
    memset(f, 0, sizeof(*f));
    f->buf[0] = 0x80; /* mgmt beacon */
    f->buf[1] = 0x00;
    for (int i = 0; i < 6; i++) {
        f->buf[4 + i] = 0xFF;       /* addr1 broadcast */
        f->buf[10 + i] = BSSID[i];  /* addr2 transmitter */
        f->buf[16 + i] = BSSID[i];  /* addr3 BSSID */
    }
    f->buf[32] = 0x64; /* beacon interval */
    f->buf[34] = privacy ? 0x10 : 0x00; /* capability */
    f->buf[35] = 0x00;
    f->len = 36;

    /* SSID */
    f->buf[f->len++] = 0x00;
    f->buf[f->len++] = 0x03;
    memcpy(&f->buf[f->len], "sec", 3);
    f->len += 3;
}

static void sec_append_raw(sec_frame_t *f, uint8_t id, const uint8_t *body,
                           uint8_t body_len)
{
    f->buf[f->len++] = id;
    f->buf[f->len++] = body_len;
    memcpy(&f->buf[f->len], body, body_len);
    f->len = (uint16_t)(f->len + body_len);
}

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

/* Build an RSN IE body. caps < 0: absent. */
static uint8_t build_rsn(uint8_t *body, const uint8_t group[4],
                         const uint8_t pairwise[][4], uint16_t pcount,
                         const uint8_t akm[][4], uint16_t acount,
                         int16_t caps, uint16_t version)
{
    uint8_t n = 0;
    put_le16(&body[n], version);
    n += 2;
    memcpy(&body[n], group, 4);
    n += 4;
    put_le16(&body[n], pcount);
    n += 2;
    for (uint16_t i = 0; i < pcount; i++) {
        memcpy(&body[n], pairwise[i], 4);
        n += 4;
    }
    if (acount > 0 || caps >= 0) {
        put_le16(&body[n], acount);
        n += 2;
        for (uint16_t i = 0; i < acount; i++) {
            memcpy(&body[n], akm[i], 4);
            n += 4;
        }
    }
    if (caps >= 0) {
        put_le16(&body[n], (uint16_t)caps);
        n += 2;
    }
    return n;
}

/* Common RSN suites. */
static const uint8_t SUITE_CCMP[4] = {0x00, 0x0F, 0xAC, 0x04};
static const uint8_t SUITE_TKIP[4] = {0x00, 0x0F, 0xAC, 0x02};
static const uint8_t SUITE_GCMP[4] = {0x00, 0x0F, 0xAC, 0x09};
static const uint8_t AKM_PSK[4] = {0x00, 0x0F, 0xAC, 0x02};
static const uint8_t AKM_1X[4] = {0x00, 0x0F, 0xAC, 0x01};
static const uint8_t AKM_SAE[4] = {0x00, 0x0F, 0xAC, 0x08};
static const uint8_t AKM_OWE[4] = {0x00, 0x0F, 0xAC, 0x12}; /* type 18 */
static const uint8_t AKM_ODD[4] = {0xAA, 0xBB, 0xCC, 0x01}; /* wrong OUI */

static bool parse_beacon(sec_frame_t *f, bool truncated,
                         ieee80211_ap_observation_t *obs)
{
    ieee80211_parse_opts_t opts = {.capture_truncated = truncated};
    return ieee80211_parse_beacon_or_probe_resp(f->buf, f->len, &opts, obs);
}

/* ---------------- parser: common security modes ---------------- */

static void t_rsn_psk(void)
{
    sec_frame_t f;
    sec_beacon_init(&f, true);
    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};
    const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
    sec_append_raw(&f, 48, body, n);

    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    CHECK(obs.complete);
    CHECK(obs.rsn_present && obs.sec.rsn_present && obs.sec.rsn_valid);
    CHECK(!obs.sec.wpa_valid);
    CHECK(obs.sec.version == 1);
    CHECK(obs.sec.group == IEEE80211_CIPHER_CCMP128);
    CHECK(obs.sec.pairwise == IEEE80211_CIPHER_CCMP128);
    CHECK(obs.sec.akm == IEEE80211_AKM_PSK);
    CHECK(!obs.sec.caps_present);
    CHECK(!obs.sec.mfp_capable && !obs.sec.mfp_required);
}

static void t_rsn_enterprise_sae_owe_transition(void)
{
    ieee80211_ap_observation_t obs;
    uint8_t body[64];

    /* 802.1X. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
        const uint8_t akm[1][4] = {{AKM_1X[0], AKM_1X[1], AKM_1X[2], AKM_1X[3]}};
        sec_append_raw(&f, 48, body,
                       build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1));
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid && obs.sec.akm == IEEE80211_AKM_802_1X);
    }

    /* SAE (WPA3-Personal). */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
        const uint8_t akm[1][4] = {{AKM_SAE[0], AKM_SAE[1], AKM_SAE[2], AKM_SAE[3]}};
        sec_append_raw(&f, 48, body,
                       build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, 0x00C0, 1)); /* MFPC+MFPR */
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid && obs.sec.akm == IEEE80211_AKM_SAE);
        CHECK(obs.sec.caps_present);
        CHECK(obs.sec.mfp_capable && obs.sec.mfp_required);
    }

    /* OWE. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
        const uint8_t akm[1][4] = {{AKM_OWE[0], AKM_OWE[1], AKM_OWE[2], AKM_OWE[3]}};
        sec_append_raw(&f, 48, body,
                       build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1));
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid && obs.sec.akm == IEEE80211_AKM_OWE);
    }

    /* PSK + SAE transition. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t pair[2][4] = {
            {SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]},
            {SUITE_TKIP[0], SUITE_TKIP[1], SUITE_TKIP[2], SUITE_TKIP[3]},
        };
        const uint8_t akm[2][4] = {
            {AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]},
            {AKM_SAE[0], AKM_SAE[1], AKM_SAE[2], AKM_SAE[3]},
        };
        sec_append_raw(&f, 48, body,
                       build_rsn(body, SUITE_CCMP, pair, 2, akm, 2, 0x0080, 1));
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid);
        CHECK(obs.sec.pairwise == (IEEE80211_CIPHER_CCMP128 | IEEE80211_CIPHER_TKIP));
        CHECK(obs.sec.akm == (IEEE80211_AKM_PSK | IEEE80211_AKM_SAE));
        CHECK(obs.sec.mfp_capable && !obs.sec.mfp_required);
        CHECK(obs.sec.group == IEEE80211_CIPHER_CCMP128);
    }

    /* GCMP-256 group/pairwise. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t pair[1][4] = {{SUITE_GCMP[0], SUITE_GCMP[1], SUITE_GCMP[2], SUITE_GCMP[3]}};
        const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};
        sec_append_raw(&f, 48, body,
                       build_rsn(body, SUITE_GCMP, pair, 1, akm, 1, -1, 1));
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid);
        CHECK(obs.sec.group == IEEE80211_CIPHER_GCMP256);
        CHECK(obs.sec.pairwise == IEEE80211_CIPHER_GCMP256);
    }
}

static void t_wpa_vendor_psk(void)
{
    sec_frame_t f;
    sec_beacon_init(&f, true);
    uint8_t body[64];
    const uint8_t pair[1][4] = {{0x00, 0x50, 0xF2, 0x02}}; /* TKIP, WPA OUI */
    const uint8_t akm[1][4] = {{0x00, 0x50, 0xF2, 0x02}};  /* PSK, WPA OUI */
    /* body = OUI + type + suites area */
    body[0] = 0x00;
    body[1] = 0x50;
    body[2] = 0xF2;
    body[3] = 0x01;
    const uint8_t n = build_rsn(&body[4], (const uint8_t[4]){0x00, 0x50, 0xF2, 0x02},
                                pair, 1, akm, 1, -1, 1);
    sec_append_raw(&f, 221, body, (uint8_t)(n + 4));

    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    CHECK(obs.complete);
    CHECK(obs.wpa_vendor_present && obs.sec.wpa_present && obs.sec.wpa_valid);
    CHECK(!obs.sec.rsn_present);
    CHECK(obs.sec.version == 1);
    CHECK(obs.sec.group == IEEE80211_CIPHER_TKIP);
    CHECK(obs.sec.pairwise == IEEE80211_CIPHER_TKIP);
    CHECK(obs.sec.akm == IEEE80211_AKM_PSK);
}

static void t_wpa_and_rsn_distinction(void)
{
    sec_frame_t f;
    sec_beacon_init(&f, true);
    uint8_t body[64];

    /* WPA IE whose suites carry the RSN OUI 00:0F:AC: WPA context
     * expects 00:50:F2 -> suites decode UNKNOWN, never mislabeled. */
    {
        const uint8_t pair[1][4] = {{0x00, 0x0F, 0xAC, 0x04}};
        const uint8_t akm[1][4] = {{0x00, 0x0F, 0xAC, 0x02}};
        body[0] = 0x00; body[1] = 0x50; body[2] = 0xF2; body[3] = 0x01;
        const uint8_t n = build_rsn(&body[4], (const uint8_t[4]){0x00, 0x0F, 0xAC, 0x04},
                                    pair, 1, akm, 1, -1, 1);
        sec_append_raw(&f, 221, body, (uint8_t)(n + 4));
    }
    /* RSN IE with WPA-OUI suites: RSN context expects 00:0F:AC. */
    {
        const uint8_t pair[1][4] = {{0x00, 0x50, 0xF2, 0x02}};
        const uint8_t akm[1][4] = {{0x00, 0x50, 0xF2, 0x02}};
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
        sec_append_raw(&f, 48, body, n);
    }

    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    CHECK(obs.sec.wpa_valid && obs.sec.rsn_valid);
    /* All suites have the wrong OUI for their context: unknown, not PSK. */
    CHECK(obs.sec.pairwise == IEEE80211_CIPHER_UNKNOWN);
    CHECK(obs.sec.akm == IEEE80211_AKM_UNKNOWN);
    CHECK(obs.sec.group == IEEE80211_CIPHER_CCMP128); /* RSN group is 00:0F:AC */
}

static void t_unknown_suites_kept_unknown(void)
{
    sec_frame_t f;
    sec_beacon_init(&f, true);
    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_ODD[0], AKM_ODD[1], AKM_ODD[2], AKM_ODD[3]}};
    const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
    sec_append_raw(&f, 48, body, n);

    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    CHECK(obs.complete);
    CHECK(obs.sec.rsn_valid);            /* structure is legal */
    CHECK(obs.sec.akm == IEEE80211_AKM_UNKNOWN); /* never guessed as PSK */
    CHECK(obs.sec.pairwise == IEEE80211_CIPHER_CCMP128);
}

/* ---------------- parser: malformed structures ---------------- */

static void t_count_overflow_malformed(void)
{
    sec_frame_t f;
    sec_beacon_init(&f, true);
    uint8_t body[64];
    /* Declared pairwise count 100 with a single suite present. */
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    uint8_t n = 0;
    put_le16(&body[n], 1);
    n += 2;
    memcpy(&body[n], SUITE_CCMP, 4);
    n += 4;
    put_le16(&body[n], 100);
    n += 2;
    memcpy(&body[n], pair[0], 4);
    n += 4;
    sec_append_raw(&f, 48, body, n);

    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    CHECK(obs.rsn_present && obs.sec.rsn_present);
    CHECK(!obs.sec.rsn_valid);
    CHECK(obs.malformed_ie);
    CHECK(!obs.complete);
}

static void t_bad_version_and_short_bodies(void)
{
    ieee80211_ap_observation_t obs;

    /* Version 2: illegal. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        uint8_t body[64];
        const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
        const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 2);
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(!obs.sec.rsn_valid && obs.malformed_ie);
    }

    /* Empty RSN body. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        sec_append_raw(&f, 48, (const uint8_t *)"", 0);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.rsn_present && !obs.sec.rsn_valid && obs.malformed_ie);
    }

    /* Body cut inside the version field. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t one[1] = {0x01};
        sec_append_raw(&f, 48, one, 1);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.rsn_present && !obs.sec.rsn_valid && obs.malformed_ie);
    }

    /* AKM count lies about its suites (mid-structure overflow). */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        uint8_t body[64];
        const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
        uint8_t n = 0;
        put_le16(&body[n], 1);
        n += 2;
        memcpy(&body[n], SUITE_CCMP, 4);
        n += 4;
        put_le16(&body[n], 1);
        n += 2;
        memcpy(&body[n], pair[0], 4);
        n += 4;
        put_le16(&body[n], 9); /* 9 AKM suites "declared", none present */
        n += 2;
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.rsn_present && !obs.sec.rsn_valid && obs.malformed_ie);
    }
}

static void t_optional_tails(void)
{
    ieee80211_ap_observation_t obs;
    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};

    /* No AKM list, no caps: legal minimal RSN. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        uint8_t n = 0;
        put_le16(&body[n], 1);
        n += 2;
        memcpy(&body[n], SUITE_CCMP, 4);
        n += 4;
        put_le16(&body[n], 1);
        n += 2;
        memcpy(&body[n], pair[0], 4);
        n += 4;
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.complete && obs.sec.rsn_valid);
        CHECK(obs.sec.pairwise == IEEE80211_CIPHER_CCMP128);
        CHECK(obs.sec.akm == 0);
        CHECK(!obs.sec.caps_present);
    }

    /* Caps present and complete (MFPC). */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, 0x0080, 1);
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid && obs.sec.caps_present);
        CHECK(obs.sec.mfp_capable && !obs.sec.mfp_required);
    }

    /* Caps declared by the IE length but the byte cut is a CAPTURE cut:
     * the walk reports incomplete (not malformed), no suites claimed. */
    {
        sec_frame_t f;
        sec_beacon_init(&f, true);
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, 0x0080, 1);
        sec_append_raw(&f, 48, body, n);
        /* Hand the parser 2 bytes less than the declared IE needs. */
        const uint16_t saved = f->len;
        f->len = (uint16_t)(saved - 2);
        CHECK(parse_beacon(&f, true, &obs));
        CHECK(!obs.complete);
        CHECK(obs.ie_walk_incomplete);
        CHECK(!obs.malformed_ie);
        CHECK(!obs.sec.rsn_valid); /* nothing partial claimed */
    }
}

/* ---------------- truncation relative to the RSN IE ---------------- */

static void t_long_beacon_cut_positions(void)
{
    /* Beacon with filler before and after the RSN IE. */
    sec_frame_t full;
    sec_beacon_init(&full, true);
    uint8_t filler[2] = {0xDD, 0x00};
    for (int i = 0; i < 6; i++) {
        sec_append_raw(&full, 250, filler, 0); /* small filler IEs before */
    }
    uint8_t rsn_body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};
    const uint8_t rsn_len = build_rsn(rsn_body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
    const uint16_t rsn_start = full.len;
    sec_append_raw(&full, 48, rsn_body, rsn_len);
    const uint16_t rsn_end = full.len;
    for (int i = 0; i < 6; i++) {
        sec_append_raw(&full, 250, filler, 0); /* filler after */
    }

    ieee80211_ap_observation_t obs;

    /* Cut BEFORE the RSN IE: not present, incomplete walk. */
    {
        sec_frame_t f = full;
        f.len = (uint16_t)(rsn_start - 2);
        CHECK(parse_beacon(&f, true, &obs));
        CHECK(!obs.complete && obs.ie_walk_incomplete);
        CHECK(!obs.rsn_present && !obs.sec.rsn_present && !obs.sec.rsn_valid);
    }

    /* Cut INSIDE the RSN IE: present-at-boundary is unknowable; the walk
     * reports incomplete and no suites are claimed. */
    {
        sec_frame_t f = full;
        f.len = (uint16_t)(rsn_start + 6); /* header + version + part of group */
        CHECK(parse_beacon(&f, true, &obs));
        CHECK(!obs.complete && obs.ie_walk_incomplete && !obs.malformed_ie);
        CHECK(!obs.sec.rsn_valid);
    }

    /* Cut AFTER the RSN IE (inside trailing filler): the RSN IE itself
     * was fully captured and legally structured - positive evidence even
     * though the observation is incomplete. */
    {
        sec_frame_t f = full;
        f.len = (uint16_t)(rsn_end + 2);
        CHECK(parse_beacon(&f, true, &obs));
        CHECK(!obs.complete && obs.ie_walk_incomplete);
        CHECK(obs.sec.rsn_present && obs.sec.rsn_valid);
        CHECK(obs.sec.akm == IEEE80211_AKM_PSK);
        CHECK(obs.sec.pairwise == IEEE80211_CIPHER_CCMP128);
    }

    /* Complete capture: everything valid. */
    CHECK(parse_beacon(&full, false, &obs));
    CHECK(obs.complete && obs.sec.rsn_valid);
}

/* ---------------- world merge policy ---------------- */

static world_t w;

static void t_world_open_and_privacy(void)
{
    world_init(&w);

    /* OPEN requires a COMPLETE observation, privacy=0 and no RSN/WPA. */
    sec_frame_t f;
    sec_beacon_init(&f, false);
    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    world_on_ap_observation(&w, &obs, 1000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_OPEN);
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "OPEN") == 0);
    }

    /* Truncated capture of an open beacon: UNKNOWN stays UNKNOWN (never
     * claims OPEN from an incomplete view). */
    f.len -= 1;
    CHECK(parse_beacon(&f, true, &obs));
    uint8_t other[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x0F};
    ieee80211_ap_observation_t obs2 = obs;
    memcpy(obs2.bssid, other, 6);
    world_on_ap_observation(&w, &obs2, 2000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 1, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_UNKNOWN);
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "UNKNOWN") == 0);
    }

    /* Privacy bit without decodable security IEs: legacy, never WEP. */
    sec_frame_t f3;
    sec_beacon_init(&f3, true);
    CHECK(parse_beacon(&f3, false, &obs));
    uint8_t third[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x10};
    memcpy(obs.bssid, third, 6);
    world_on_ap_observation(&w, &obs, 3000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 2, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_LEGACY_PRIVACY);
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "PRIVACY") == 0);
    }
    CHECK(world_check_invariants(&w));
}

static void t_world_valid_then_malformed_no_downgrade(void)
{
    world_init(&w);

    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};

    /* 1. Valid RSN PSK beacon. */
    sec_frame_t f;
    sec_beacon_init(&f, true);
    const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
    sec_append_raw(&f, 48, body, n);
    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, false, &obs));
    world_on_ap_observation(&w, &obs, 1000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
        CHECK(v.ap.sec.akm == IEEE80211_AKM_PSK);
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "WPA2-PSK") == 0);
    }

    /* 2. Beacon with a structurally broken RSN: KNOWN result survives. */
    sec_frame_t bad;
    sec_beacon_init(&bad, true);
    uint8_t broken[16];
    uint8_t m = 0;
    put_le16(&broken[m], 1);
    m += 2;
    memcpy(&broken[m], SUITE_CCMP, 4);
    m += 4;
    put_le16(&broken[m], 100); /* count overflow */
    m += 2;
    memcpy(&broken[m], pair[0], 4);
    m += 4;
    sec_append_raw(&bad, 48, broken, m);
    CHECK(parse_beacon(&bad, false, &obs));
    CHECK(obs.malformed_ie && !obs.complete);
    world_on_ap_observation(&w, &obs, 2000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
        CHECK(v.ap.sec.akm == IEEE80211_AKM_PSK); /* old suites kept */
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "WPA2-PSK") == 0);
    }

    /* 3. Truncated capture whose RSN was fully inside: refresh, no
     * downgrade (activity + positive evidence only). */
    sec_frame_t trunc = f;
    sec_append_raw(&trunc, 250, (const uint8_t *)"", 0); /* trailing filler */
    trunc.len -= 1; /* cut inside the filler */
    CHECK(parse_beacon(&trunc, true, &obs));
    CHECK(!obs.complete && obs.sec.rsn_valid);
    world_on_ap_observation(&w, &obs, 3000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
        CHECK(v.ap.last_seen_ms == 3000);
    }

    /* 4. COMPLETE clean beacon without RSN: authoritative downgrade. */
    sec_frame_t clean;
    sec_beacon_init(&clean, false);
    CHECK(parse_beacon(&clean, false, &obs));
    world_on_ap_observation(&w, &obs, 4000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_OPEN);
    }
    CHECK(world_check_invariants(&w));
}

static void t_world_truncated_rsn_positive_evidence(void)
{
    world_init(&w);

    /* A first truncated capture with NO RSN inside: UNKNOWN. */
    sec_frame_t f;
    sec_beacon_init(&f, false);
    uint8_t filler[2] = {0, 0};
    sec_append_raw(&f, 250, filler, 0);
    ieee80211_ap_observation_t obs;
    CHECK(parse_beacon(&f, true, &obs)); /* cut inside the filler IE */
    CHECK(!obs.complete);
    world_on_ap_observation(&w, &obs, 1000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_UNKNOWN);
    }

    /* Second truncated capture in which the RSN IE was fully captured:
     * positive evidence applies even though the observation is
     * incomplete - UNKNOWN upgrades to KNOWN without ever claiming OPEN. */
    sec_frame_t f2;
    sec_beacon_init(&f2, false);
    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};
    const uint8_t akm[1][4] = {{AKM_SAE[0], AKM_SAE[1], AKM_SAE[2], AKM_SAE[3]}};
    const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, 0x0080, 1);
    sec_append_raw(&f2, 48, body, n);
    sec_append_raw(&f2, 250, filler, 0);
    f2.len -= 1; /* cut inside the trailing filler */
    CHECK(parse_beacon(&f2, true, &obs));
    CHECK(!obs.complete && obs.sec.rsn_valid);
    world_on_ap_observation(&w, &obs, 2000, true);
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
        CHECK(v.ap.sec.akm == IEEE80211_AKM_SAE);
        char name[32];
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "WPA3-SAE-PMF") == 0);
    }
    CHECK(world_check_invariants(&w));
}

static void t_world_security_names(void)
{
    world_init(&w);
    ieee80211_ap_observation_t obs;
    char name[32];
    sec_frame_t f;
    uint8_t body[64];
    const uint8_t pair[1][4] = {{SUITE_CCMP[0], SUITE_CCMP[1], SUITE_CCMP[2], SUITE_CCMP[3]}};

    struct {
        const uint8_t (*akm)[4];
        uint16_t akm_count;
        int16_t caps;
        const char *expect;
    } cases[] = {
        {&AKM_PSK, 1, -1, "WPA2-PSK"},
        {&AKM_1X, 1, -1, "WPA2-1X"},
        {&AKM_SAE, 1, -1, "WPA3-SAE"},
        {&AKM_OWE, 1, -1, "WPA3-OWE"},
        {&AKM_ODD, 1, -1, "WPA2-?"},
    };
    const uint8_t akms[5][2][4] = {
        {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}, {0}},
        {{AKM_1X[0], AKM_1X[1], AKM_1X[2], AKM_1X[3]}, {0}},
        {{AKM_SAE[0], AKM_SAE[1], AKM_SAE[2], AKM_SAE[3]}, {0}},
        {{AKM_OWE[0], AKM_OWE[1], AKM_OWE[2], AKM_OWE[3]}, {0}},
        {{AKM_ODD[0], AKM_ODD[1], AKM_ODD[2], AKM_ODD[3]}, {0}},
    };

    for (int i = 0; i < 5; i++) {
        sec_beacon_init(&f, true);
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1,
                                    (const uint8_t(*)[4])akms[i], 1, -1, 1);
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        world_init(&w);
        world_on_ap_observation(&w, &obs, 1000, true);
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, cases[i].expect) == 0);
    }

    /* Transition: PSK + SAE => WPA2/WPA3. */
    {
        const uint8_t akm[2][4] = {
            {AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]},
            {AKM_SAE[0], AKM_SAE[1], AKM_SAE[2], AKM_SAE[3]},
        };
        sec_beacon_init(&f, true);
        const uint8_t n = build_rsn(body, SUITE_CCMP, pair, 1, akm, 2, 0x00C0, 1); /* MFPC+MFPR */
        sec_append_raw(&f, 48, body, n);
        CHECK(parse_beacon(&f, false, &obs));
        world_init(&w);
        world_on_ap_observation(&w, &obs, 1000, true);
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "WPA2/WPA3-PMF(req)") == 0);
    }

    /* WPA + RSN (transition AP with both IEs) => WPA/WPA2. */
    {
        sec_beacon_init(&f, true);
        const uint8_t akm[1][4] = {{AKM_PSK[0], AKM_PSK[1], AKM_PSK[2], AKM_PSK[3]}};
        /* RSN */
        const uint8_t rn = build_rsn(body, SUITE_CCMP, pair, 1, akm, 1, -1, 1);
        sec_append_raw(&f, 48, body, rn);
        /* WPA vendor */
        uint8_t vbody[64];
        vbody[0] = 0x00; vbody[1] = 0x50; vbody[2] = 0xF2; vbody[3] = 0x01;
        const uint8_t wpair[1][4] = {{0x00, 0x50, 0xF2, 0x02}};
        const uint8_t wakm[1][4] = {{0x00, 0x50, 0xF2, 0x02}};
        const uint8_t wn = build_rsn(&vbody[4],
                                     (const uint8_t[4]){0x00, 0x50, 0xF2, 0x02},
                                     wpair, 1, wakm, 1, -1, 1);
        sec_append_raw(&f, 221, vbody, (uint8_t)(wn + 4));
        CHECK(parse_beacon(&f, false, &obs));
        CHECK(obs.sec.rsn_valid && obs.sec.wpa_valid);
        world_init(&w);
        world_on_ap_observation(&w, &obs, 1000, true);
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        world_security_name(&v.ap, name, sizeof(name));
        CHECK(strcmp(name, "WPA/WPA2") == 0);
    }

    /* Buffer-size robustness. */
    {
        world_ap_view_t v;
        CHECK(world_get_ap(&w, 0, &v));
        char tiny[4];
        world_security_name(&v.ap, tiny, sizeof(tiny));
        CHECK(strlen(tiny) < sizeof(tiny));
        world_security_name(&v.ap, tiny, 1);
        CHECK(tiny[0] == '\0');
        world_security_name(NULL, name, sizeof(name));
        CHECK(strcmp(name, "UNKNOWN") == 0);
    }
}

int main(void)
{
    test_register("sec_rsn_psk", t_rsn_psk);
    test_register("sec_rsn_enterprise_sae_owe_transition", t_rsn_enterprise_sae_owe_transition);
    test_register("sec_wpa_vendor_psk", t_wpa_vendor_psk);
    test_register("sec_wpa_and_rsn_distinction", t_wpa_and_rsn_distinction);
    test_register("sec_unknown_suites_kept_unknown", t_unknown_suites_kept_unknown);
    test_register("sec_count_overflow_malformed", t_count_overflow_malformed);
    test_register("sec_bad_version_and_short_bodies", t_bad_version_and_short_bodies);
    test_register("sec_optional_tails", t_optional_tails);
    test_register("sec_long_beacon_cut_positions", t_long_beacon_cut_positions);
    test_register("sec_world_open_and_privacy", t_world_open_and_privacy);
    test_register("sec_world_valid_then_malformed_no_downgrade", t_world_valid_then_malformed_no_downgrade);
    test_register("sec_world_truncated_rsn_positive_evidence", t_world_truncated_rsn_positive_evidence);
    test_register("sec_world_security_names", t_world_security_names);
    return test_run_all();
}
