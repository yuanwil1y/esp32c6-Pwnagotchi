/* Phase 2A host regression tests: World Model AP database (production
 * code, virtual clock). Covers creation, merge policy, TTL, deterministic
 * eviction, capacity bounds and invariants. */
#include "ieee80211_parser.h"
#include "world.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

/* ---------------- helpers ---------------- */

static world_t w;

static void reset_world(void)
{
    world_init(&w);
}

/* A minimal COMPLETE beacon observation for `bssid`. */
static ieee80211_ap_observation_t obs_beacon(const uint8_t bssid[6],
                                             const char *ssid, int8_t rssi,
                                             uint8_t channel)
{
    ieee80211_ap_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.bssid, bssid, 6);
    if (ssid != NULL) {
        obs.ssid_len = (uint8_t)strlen(ssid);
        memcpy(obs.ssid, ssid, obs.ssid_len);
    } else {
        obs.hidden_ssid = true;
    }
    obs.rssi = rssi;
    obs.rx_channel = channel;
    obs.advertised_channel = channel;
    obs.ds_param_present = true;
    obs.beacon_interval = 100;
    obs.complete = true;
    return obs;
}

static void set_bssid(uint8_t mac[6], uint8_t last)
{
    mac[0] = 0x00; /* globally-administered-looking unicast test values */
    mac[1] = 0x11;
    mac[2] = 0x22;
    mac[3] = 0x33;
    mac[4] = 0x44;
    mac[5] = last;
}

static bool ap_exists(const uint8_t bssid[6])
{
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        world_ap_view_t v;
        if (world_get_ap(&w, i, &v) && memcmp(v.ap.bssid, bssid, 6) == 0) {
            return true;
        }
    }
    return false;
}

static bool ap_find_view(const uint8_t bssid[6], world_ap_view_t *out)
{
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        world_ap_view_t v;
        if (world_get_ap(&w, i, &v) && memcmp(v.ap.bssid, bssid, 6) == 0) {
            *out = v;
            return true;
        }
    }
    return false;
}

/* ---------------- creation and merge ---------------- */

static void t_create_and_merge(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 1);

    ieee80211_ap_observation_t obs = obs_beacon(b, "home", -55, 6);
    world_on_ap_observation(&w, &obs, 1000, true);
    CHECK(world_check_invariants(&w));

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.ssid_known);
    CHECK(v.ap.ssid_len == 4 && memcmp(v.ap.ssid, "home", 4) == 0);
    CHECK(v.ap.first_seen_ms == 1000 && v.ap.last_seen_ms == 1000);
    CHECK(v.ap.advertised_channel == 6);
    CHECK(v.ap.last_rx_channel == 6);
    CHECK(v.ap.rssi == -55 && v.ap.rssi_valid);
    CHECK(v.ap.beacon_count == 1 && v.ap.probe_resp_count == 0);
    CHECK(v.ap.sec_state == WORLD_SEC_OPEN);
    CHECK(v.ap.station_count == 0);
    CHECK((v.ap.flags & WORLD_AP_F_PROVISIONAL) == 0);

    /* Same BSSID again: one record, activity refreshed, name kept. */
    obs.rssi = -60;
    world_on_ap_observation(&w, &obs, 2000, true);
    CHECK(world_check_invariants(&w));

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 1);
    CHECK(snap.stats.ap_created == 1);
    CHECK(snap.stats.ap_expired == 0 && snap.stats.ap_evicted == 0);

    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.last_seen_ms == 2000);
    CHECK(v.ap.rssi == -60);
    CHECK(v.ap.beacon_count == 2);
    CHECK(v.ap.first_seen_ms == 1000);

    /* Probe response for the same BSSID bumps its own counter. */
    world_on_ap_observation(&w, &obs, 3000, false);
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.probe_resp_count == 1);
    CHECK(v.ap.beacon_count == 2);
}

static void t_hidden_never_clears_name(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 7);

    ieee80211_ap_observation_t obs = obs_beacon(b, "named", -50, 1);
    world_on_ap_observation(&w, &obs, 100, true);

    /* Complete hidden observation (all-zero SSID IE): name preserved. */
    obs = obs_beacon(b, NULL, -52, 1);
    world_on_ap_observation(&w, &obs, 200, true);
    CHECK(world_check_invariants(&w));

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.ssid_known);
    CHECK(v.ap.ssid_len == 5 && memcmp(v.ap.ssid, "named", 5) == 0);

    /* Zero-length SSID IE (also hidden): still preserved. */
    obs.hidden_ssid = true;
    world_on_ap_observation(&w, &obs, 300, true);
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.ssid_known && v.ap.ssid_len == 5);

    /* A complete valid new name DOES replace the learned name. */
    obs = obs_beacon(b, "renamed", -51, 1);
    world_on_ap_observation(&w, &obs, 400, true);
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.ssid_len == 7 && memcmp(v.ap.ssid, "renamed", 7) == 0);
}

static void t_embedded_nul_and_raw_bytes(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 9);

    ieee80211_ap_observation_t obs = obs_beacon(b, NULL, -40, 11);
    obs.hidden_ssid = false;
    obs.ssid_len = 3;
    obs.ssid[0] = 'a';
    obs.ssid[1] = 0x00; /* embedded NUL: raw storage, no strlen semantics */
    obs.ssid[2] = 'z';
    world_on_ap_observation(&w, &obs, 10, true);

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.ssid_len == 3);
    CHECK(v.ap.ssid[0] == 'a' && v.ap.ssid[1] == 0x00 && v.ap.ssid[2] == 'z');
    CHECK(v.ap.ssid_known);
}

static void t_truncated_observation_partial_update(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 3);

    /* Learn a full RSN-classified AP first (Phase 2C: KNOWN requires a
     * fully valid suite parse, not mere presence). */
    ieee80211_ap_observation_t obs = obs_beacon(b, "secure", -50, 6);
    obs.rsn_present = true;
    obs.sec.rsn_present = true;
    obs.sec.rsn_valid = true;
    obs.sec.version = 1;
    obs.sec.group = IEEE80211_CIPHER_CCMP128;
    obs.sec.pairwise = IEEE80211_CIPHER_CCMP128;
    obs.sec.akm = IEEE80211_AKM_PSK;
    world_on_ap_observation(&w, &obs, 1000, true);
    {
        world_ap_view_t v;
        CHECK(ap_find_view(b, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
        CHECK(v.ap.sec.akm == IEEE80211_AKM_PSK);
    }

    /* Truncated capture: activity + rssi + channel refresh, but no field
     * downgrade and no name damage. */
    obs.complete = false;
    obs.ie_walk_incomplete = true;
    obs.rsn_present = false;      /* "not seen" carries no evidence here */
    obs.sec.rsn_present = false;
    obs.sec.rsn_valid = false;    /* no valid parse in this observation */
    obs.sec.akm = 0;
    obs.ssid_len = 0;             /* SSID area cut before the SSID IE */
    obs.hidden_ssid = false;
    obs.ds_param_present = false; /* DS IE not reached */
    obs.advertised_channel = 0;
    obs.rssi = -70;
    obs.rx_channel = 6;
    world_on_ap_observation(&w, &obs, 5000, true);
    CHECK(world_check_invariants(&w));

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.last_seen_ms == 5000);
    CHECK(v.ap.rssi == -70 && v.ap.rssi_valid);
    CHECK(v.ap.ssid_known && v.ap.ssid_len == 6);
    /* Security NOT downgraded to OPEN by a truncated observation. */
    CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
    CHECK(v.ap.sec.akm == IEEE80211_AKM_PSK);
    /* Advertised channel NOT cleared by absence. */
    CHECK(v.ap.advertised_channel == 6);

    /* Malformed walk (complete=false via malformed flag): same rule -
     * activity only. */
    obs.malformed_ie = true;
    obs.ie_walk_incomplete = false;
    world_on_ap_observation(&w, &obs, 6000, true);
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.last_seen_ms == 6000);
    CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
}

static void t_truncated_ds_ie_still_applies(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 5);

    /* Truncated capture in which the (atomic) DS IE was fully parsed. */
    ieee80211_ap_observation_t obs = obs_beacon(b, NULL, -50, 3);
    obs.complete = false;
    obs.ie_walk_incomplete = true;
    obs.hidden_ssid = true;
    obs.ds_param_present = true;
    obs.advertised_channel = 3;
    world_on_ap_observation(&w, &obs, 100, true);

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.advertised_channel == 3);
    CHECK(!v.ap.ssid_known);
}

static void t_complete_observation_is_authoritative(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 11);

    /* RSN-secured (valid suites), then a COMPLETE clean observation
     * without RSN: the complete observation is authoritative and may
     * downgrade. */
    ieee80211_ap_observation_t obs = obs_beacon(b, "x", -50, 6);
    obs.rsn_present = true;
    obs.sec.rsn_present = true;
    obs.sec.rsn_valid = true;
    obs.sec.akm = IEEE80211_AKM_PSK;
    world_on_ap_observation(&w, &obs, 1000, true);
    {
        world_ap_view_t v;
        CHECK(ap_find_view(b, &v));
        CHECK(v.ap.sec_state == WORLD_SEC_KNOWN);
    }

    obs.rsn_present = false;
    memset(&obs.sec, 0, sizeof(obs.sec));
    world_on_ap_observation(&w, &obs, 2000, true);
    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.sec_state == WORLD_SEC_OPEN);

    /* Privacy-only complete observation: LEGACY_PRIVACY, never WEP. */
    obs.privacy = true;
    world_on_ap_observation(&w, &obs, 3000, true);
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.sec_state == WORLD_SEC_LEGACY_PRIVACY);
}

static void t_invalid_bssid_rejected(void)
{
    reset_world();

    ieee80211_ap_observation_t obs = obs_beacon((const uint8_t *)"\x00\x00\x00\x00\x00\x00",
                                                "z", -50, 6);
    world_on_ap_observation(&w, &obs, 10, true);

    uint8_t mcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    obs = obs_beacon(mcast, "z", -50, 6);
    world_on_ap_observation(&w, &obs, 10, true);

    uint8_t group_bit[6] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x01};
    obs = obs_beacon(group_bit, "z", -50, 6);
    world_on_ap_observation(&w, &obs, 10, true);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 0);
    CHECK(snap.stats.obs_invalid == 3);
    CHECK(snap.stats.ap_created == 0);
    CHECK(world_check_invariants(&w));
}

static void t_stale_timestamp_ignored(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 21);

    ieee80211_ap_observation_t obs = obs_beacon(b, "s", -50, 6);
    world_on_ap_observation(&w, &obs, 5000, true);

    /* An observation with an EARLIER timestamp: stale, fully ignored. */
    obs = obs_beacon(b, "other", -90, 1);
    world_on_ap_observation(&w, &obs, 4000, true); /* time went backwards */

    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.last_seen_ms == 5000);
    CHECK(v.ap.rssi == -50);
    CHECK(v.ap.ssid_len == 1 && v.ap.ssid[0] == 's');
    CHECK(v.ap.beacon_count == 1);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.obs_stale == 1);
}

/* ---------------- TTL ---------------- */

static void t_ttl_expiry_edges(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 31);

    ieee80211_ap_observation_t obs = obs_beacon(b, "t", -50, 6);
    world_on_ap_observation(&w, &obs, 1000, true);

    world_maintenance(&w, 1000 + WORLD_AP_TTL_MS);
    CHECK(world_check_invariants(&w));
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 1); /* exactly at TTL: still current */

    world_maintenance(&w, 1000 + WORLD_AP_TTL_MS + 1);
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 0);
    CHECK(snap.stats.ap_expired == 1);
    CHECK(world_check_invariants(&w));

    /* Reappearance after expiry: a fresh create (new first_seen). */
    world_on_ap_observation(&w, &obs, 1000 + WORLD_AP_TTL_MS + 5000, true);
    world_ap_view_t v;
    CHECK(ap_find_view(b, &v));
    CHECK(v.ap.first_seen_ms == 1000 + WORLD_AP_TTL_MS + 5000);
    CHECK(v.ap.beacon_count == 1);
    world_snapshot(&w, &snap);
    CHECK(snap.stats.ap_created == 2);
    CHECK(snap.ap_current == 1);
}

static void t_maintenance_without_traffic(void)
{
    reset_world();
    uint8_t b[6];
    set_bssid(b, 41);

    ieee80211_ap_observation_t obs = obs_beacon(b, "idle", -50, 6);
    world_on_ap_observation(&w, &obs, 100, true);

    /* No packets at all: maintenance alone must age the record out. */
    for (uint64_t t = 1000; t <= 200000; t += 1000) {
        world_maintenance(&w, t);
    }
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 0);
    CHECK(snap.stats.ap_expired == 1);
    CHECK(snap.stats.maint_runs == 200);
}

/* ---------------- capacity and eviction ---------------- */

static void t_capacity_evicts_oldest(void)
{
    reset_world();

    /* Fill the table with distinct BSSIDs, increasing timestamps. */
    for (uint8_t k = 0; k < WORLD_AP_MAX; k++) {
        uint8_t b[6];
        set_bssid(b, k + 1);
        ieee80211_ap_observation_t obs = obs_beacon(b, "ap", -50, (uint8_t)(k % 14 + 1));
        world_on_ap_observation(&w, &obs, 1000 + k, true);
    }
    CHECK(world_check_invariants(&w));
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == WORLD_AP_MAX);

    /* The 65th strong creator evicts the OLDEST (first) AP deterministically. */
    uint8_t extra[6];
    set_bssid(extra, 0xEE);
    ieee80211_ap_observation_t obs = obs_beacon(extra, "new", -50, 6);
    world_on_ap_observation(&w, &obs, 1000 + WORLD_AP_MAX + 100, true);

    uint8_t oldest[6];
    set_bssid(oldest, 1);
    uint8_t second[6];
    set_bssid(second, 2);
    CHECK(!ap_exists(oldest));
    CHECK(ap_exists(second));
    CHECK(ap_exists(extra));

    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == WORLD_AP_MAX);
    CHECK(snap.stats.ap_evicted == 1);
    CHECK(snap.stats.ap_expired == 0);
    CHECK(snap.stats.ap_created == WORLD_AP_MAX + 1);
    CHECK(world_check_invariants(&w));
}

static void t_eviction_tie_breaks_to_lowest_slot(void)
{
    reset_world();

    /* All entries share the same last_seen: the tie must break to the
     * lowest slot index (the first inserted BSSID). */
    for (uint8_t k = 0; k < WORLD_AP_MAX; k++) {
        uint8_t b[6];
        set_bssid(b, k + 1);
        ieee80211_ap_observation_t obs = obs_beacon(b, "ap", -50, 6);
        world_on_ap_observation(&w, &obs, 5000, true);
    }

    uint8_t extra[6];
    set_bssid(extra, 0xDD);
    ieee80211_ap_observation_t obs = obs_beacon(extra, "x", -50, 6);
    world_on_ap_observation(&w, &obs, 5000, true);

    uint8_t first_b[6];
    set_bssid(first_b, 1);
    CHECK(!ap_exists(first_b));

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.ap_evicted == 1);
}

static void t_full_table_sweeps_expired_before_evicting(void)
{
    reset_world();

    /* Fill with 64 APs at t=1000. */
    for (uint8_t k = 0; k < WORLD_AP_MAX; k++) {
        uint8_t b[6];
        set_bssid(b, k + 1);
        ieee80211_ap_observation_t obs = obs_beacon(b, "ap", -50, 6);
        world_on_ap_observation(&w, &obs, 1000, true);
    }

    /* Refresh only the first 32 well past one TTL. */
    const uint64_t later = 1000 + WORLD_AP_TTL_MS + 10000;
    for (uint8_t k = 0; k < 32; k++) {
        uint8_t b[6];
        set_bssid(b, k + 1);
        ieee80211_ap_observation_t obs = obs_beacon(b, "ap", -55, 6);
        world_on_ap_observation(&w, &obs, later, true);
    }

    /* New strong creator: the 32 stale slots are reclaimed by the expiry
     * sweep, no live entry is evicted. */
    uint8_t extra[6];
    set_bssid(extra, 0xCC);
    ieee80211_ap_observation_t obs = obs_beacon(extra, "new", -50, 6);
    world_on_ap_observation(&w, &obs, later + 1, true);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.ap_expired == 32);
    CHECK(snap.stats.ap_evicted == 0);
    CHECK(snap.ap_current == 33);

    /* The refreshed 32 and the new one are alive; the stale 32 are gone. */
    uint8_t kept[6];
    set_bssid(kept, 32);
    CHECK(ap_exists(kept));
    uint8_t gone[6];
    set_bssid(gone, 33);
    CHECK(!ap_exists(gone));
    CHECK(world_check_invariants(&w));
}

static void t_loop_churn_bounded(void)
{
    reset_world();

    /* Massive create/expire/evict churn: occupancy and memory stay
     * bounded and invariants hold throughout. */
    for (uint32_t round = 0; round < 200; round++) {
        const uint64_t base = (uint64_t)round * 400000;
        for (uint8_t k = 0; k < 40; k++) {
            uint8_t b[6];
            set_bssid(b, (uint8_t)(k + 1));
            ieee80211_ap_observation_t obs = obs_beacon(b, "churn", -50, 6);
            world_on_ap_observation(&w, &obs, base + k, true);
        }
        world_maintenance(&w, base + 390000);

        if (round % 25 == 0) {
            world_snapshot_t snap;
            world_snapshot(&w, &snap);
            CHECK(snap.ap_current <= WORLD_AP_MAX);
            CHECK(world_check_invariants(&w));
        }
    }
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current <= WORLD_AP_MAX);
    CHECK(snap.stats.ap_created >= 200 * 40);
    CHECK(world_check_invariants(&w));
}

static void t_page_export_bounds(void)
{
    reset_world();
    world_ap_view_t v;
    CHECK(!world_get_ap(&w, 0, &v) && !v.valid);
    CHECK(!world_get_ap(&w, WORLD_AP_MAX, &v) && !v.valid);
    CHECK(!world_get_ap(&w, 0xFFFF, &v) && !v.valid);

    uint8_t b[6];
    set_bssid(b, 77);
    ieee80211_ap_observation_t obs = obs_beacon(b, "p", -50, 6);
    world_on_ap_observation(&w, &obs, 100, true);
    CHECK(world_get_ap(&w, 0, &v) && v.valid);
    CHECK(memcmp(v.ap.bssid, b, 6) == 0);
}

/* ---------------- end-to-end via the production parser ---------------- */

static void t_parser_to_world_end_to_end(void)
{
    reset_world();

    /* Build a real beacon frame and drive both production layers. */
    uint8_t frame[128];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x80; /* mgmt beacon */
    frame[1] = 0x00;
    for (int i = 0; i < 6; i++) {
        frame[4 + i] = 0xFF;       /* addr1 broadcast */
        frame[10 + i] = 0x0A;      /* addr2 transmitter */
        frame[16 + i] = 0x0C;      /* addr3 BSSID */
    }
    frame[24 + 8] = 0x64; /* beacon interval */
    frame[24 + 10] = 0x00; /* capability: no privacy */

    uint16_t len = 36;
    frame[len++] = 0x00; /* SSID IE */
    frame[len++] = 0x05;
    memcpy(&frame[len], "e2eap", 5);
    len += 5;
    frame[len++] = 0x03; /* DS param */
    frame[len++] = 0x01;
    frame[len++] = 0x06; /* channel 6 */

    ieee80211_ap_observation_t obs;
    ieee80211_parse_opts_t opts = {0};
    CHECK(ieee80211_parse_beacon_or_probe_resp(frame, len, &opts, &obs));
    obs.rssi = -42;
    obs.rx_channel = 6;
    world_on_ap_observation(&w, &obs, 123456, true);
    CHECK(world_check_invariants(&w));

    world_ap_view_t v;
    uint8_t bssid[6] = {0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C};
    CHECK(ap_find_view(bssid, &v));
    CHECK(v.ap.ssid_known && v.ap.ssid_len == 5);
    CHECK(v.ap.advertised_channel == 6);
    CHECK(v.ap.sec_state == WORLD_SEC_OPEN);
    CHECK(v.ap.last_seen_ms == 123456);

    /* Long beacon truncated BEFORE the RSN IE: complete=false, no
     * security downgrade, activity refreshed. */
    frame[len++] = 48; /* RSN IE id */
    frame[len++] = 0x14; /* declared length 20, but the capture cuts here */
    const uint16_t full_len = len + 20;
    ieee80211_parse_opts_t trunc = {.capture_truncated = true};
    CHECK(ieee80211_parse_beacon_or_probe_resp(frame, len, &trunc, &obs));
    CHECK(!obs.complete && obs.ie_walk_incomplete);
    CHECK(!obs.rsn_present);
    (void)full_len;
    world_on_ap_observation(&w, &obs, 124000, true);

    CHECK(ap_find_view(bssid, &v));
    CHECK(v.ap.sec_state == WORLD_SEC_OPEN);
    CHECK(v.ap.last_seen_ms == 124000);
    CHECK(v.ap.beacon_count == 2);
}

/* ---------------- registration ---------------- */

int main(void)
{
    test_register("world_create_and_merge", t_create_and_merge);
    test_register("world_hidden_never_clears_name", t_hidden_never_clears_name);
    test_register("world_embedded_nul_and_raw_bytes", t_embedded_nul_and_raw_bytes);
    test_register("world_truncated_observation_partial_update", t_truncated_observation_partial_update);
    test_register("world_truncated_ds_ie_still_applies", t_truncated_ds_ie_still_applies);
    test_register("world_complete_observation_is_authoritative", t_complete_observation_is_authoritative);
    test_register("world_invalid_bssid_rejected", t_invalid_bssid_rejected);
    test_register("world_stale_timestamp_ignored", t_stale_timestamp_ignored);
    test_register("world_ttl_expiry_edges", t_ttl_expiry_edges);
    test_register("world_maintenance_without_traffic", t_maintenance_without_traffic);
    test_register("world_capacity_evicts_oldest", t_capacity_evicts_oldest);
    test_register("world_eviction_tie_breaks_to_lowest_slot", t_eviction_tie_breaks_to_lowest_slot);
    test_register("world_full_table_sweeps_expired_before_evicting", t_full_table_sweeps_expired_before_evicting);
    test_register("world_loop_churn_bounded", t_loop_churn_bounded);
    test_register("world_page_export_bounds", t_page_export_bounds);
    test_register("world_parser_to_world_end_to_end", t_parser_to_world_end_to_end);
    return test_run_all();
}
