/* Phase 2B host regression tests: World Model STA database and
 * AP<->STA observation relations (production code, virtual clock).
 * Covers RSSI attribution, DS-side address exclusion, evidence strength,
 * relation switching and TTL, slot-reuse safety, capacity bounds and the
 * station_count invariant. */
#include "ieee80211_parser.h"
#include "world.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

static world_t w;

/* MAC helpers: AP_B1/AP_B2 = AP BSSIDs, STA_S1.. = station MACs. */
static const uint8_t AP_B1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x01};
static const uint8_t AP_B2[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x02};
static const uint8_t STA_S1[6] = {0x50, 0x60, 0x70, 0x80, 0x90, 0x01};
static const uint8_t STA_S2[6] = {0x50, 0x60, 0x70, 0x80, 0x90, 0x02};
static const uint8_t STA_RND[6] = {0x52, 0x60, 0x70, 0x80, 0x90, 0x03};
static const uint8_t GW_MAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

static void reset_world(void)
{
    world_init(&w);
}

/* Uplink data frame view: STA transmits through the AP. */
static ieee80211_data_addrs_t uplink(const uint8_t sta[6], const uint8_t bssid[6])
{
    ieee80211_data_addrs_t a;
    memset(&a, 0, sizeof(a));
    a.status = IEEE80211_DATA_ADDRS_OK;
    a.to_ds = true;
    a.from_ds = false;
    memcpy(a.addr1, bssid, 6); /* BSSID */
    memcpy(a.addr2, sta, 6);   /* transmitting STA */
    memcpy(a.addr3, GW_MAC, 6); /* DS-side destination */
    a.header_len = 24;
    return a;
}

/* Downlink data frame view: AP transmits to a unicast STA. */
static ieee80211_data_addrs_t downlink(const uint8_t bssid[6], const uint8_t dest[6])
{
    ieee80211_data_addrs_t a;
    memset(&a, 0, sizeof(a));
    a.status = IEEE80211_DATA_ADDRS_OK;
    a.to_ds = false;
    a.from_ds = true;
    memcpy(a.addr1, dest, 6);  /* destination STA */
    memcpy(a.addr2, bssid, 6); /* transmitting AP */
    memcpy(a.addr3, GW_MAC, 6); /* DS-side source */
    a.header_len = 24;
    return a;
}

static bool sta_view(const uint8_t mac[6], world_sta_view_t *out)
{
    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        world_sta_view_t v;
        if (world_get_sta(&w, i, &v) && memcmp(v.sta.mac, mac, 6) == 0) {
            *out = v;
            return true;
        }
    }
    return false;
}

static bool ap_view(const uint8_t bssid[6], world_ap_view_t *out)
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

static void check_invariants(void)
{
    CHECK(world_check_invariants(&w));
}

/* ---------------- discovery and RSSI attribution ---------------- */

static void t_uplink_discovers_sta_and_provisional_ap(void)
{
    reset_world();

    ieee80211_data_addrs_t a = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &a, 1000, 6, -45);
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 1);
    CHECK(snap.sta_current == 1);
    CHECK(snap.rel_current == 1);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rssi == -45 && sv.sta.rssi_valid);      /* transmitter */
    CHECK(sv.sta.last_tx_ms == 1000 && sv.sta.last_observed_ms == 1000);
    CHECK(sv.sta.tx_count == 1);
    CHECK(sv.sta.rel_ap != 0);
    CHECK(sv.sta.rel_evidence == WORLD_EVIDENCE_UPLINK);

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.flags & WORLD_AP_F_PROVISIONAL);          /* data-inferred */
    CHECK(!av.ap.rssi_valid);                              /* STA's signal */
    CHECK(av.ap.ssid_len == 0 && !av.ap.ssid_known);       /* nothing invented */
    CHECK(av.ap.sec_state == WORLD_SEC_UNKNOWN);
    CHECK(av.ap.data_up_count == 1);
    CHECK(av.ap.station_count == 1);

    /* The DS-side destination (gateway) must NOT be a wireless STA. */
    world_sta_view_t gw;
    CHECK(!sta_view(GW_MAC, &gw));
    CHECK(snap.sta_current == 1);
}

static void t_downlink_rssi_belongs_to_ap(void)
{
    reset_world();

    ieee80211_data_addrs_t a = downlink(AP_B1, STA_S1);
    world_on_data_frame(&w, &a, 2000, 11, -60);
    check_invariants();

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(!sv.sta.rssi_valid);          /* AP's signal: NOT the STA's */
    CHECK(sv.sta.last_tx_ms == 0);      /* never transmitted */
    CHECK(sv.sta.last_observed_ms == 2000);
    CHECK(sv.sta.dl_count == 1);
    CHECK(sv.sta.rel_evidence == WORLD_EVIDENCE_DOWNLINK);

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.rssi == -60 && av.ap.rssi_valid); /* transmitter */
    CHECK(av.ap.last_seen_ms == 2000);            /* AP spoke */
    CHECK(av.ap.flags & WORLD_AP_F_PROVISIONAL);
    CHECK(av.ap.data_down_count == 1);
    CHECK(av.ap.station_count == 1);

    /* The DS-side source (gateway) must NOT be a wireless STA. */
    world_sta_view_t gw;
    CHECK(!sta_view(GW_MAC, &gw));
}

static void t_up_and_down_same_sta_single_record(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);
    ieee80211_data_addrs_t d = downlink(AP_B1, STA_S1);
    world_on_data_frame(&w, &d, 1100, 6, -50);
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1);
    CHECK(snap.ap_current == 1);
    CHECK(snap.rel_current == 1);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.tx_count == 1 && sv.sta.dl_count == 1);
    CHECK(sv.sta.rssi == -45); /* latest TX-side RSSI kept; downlink ignored */
    CHECK(sv.sta.rel_evidence == WORLD_EVIDENCE_UPLINK); /* strength kept */

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.station_count == 1); /* NOT double counted */
}

static void t_beacon_confirms_provisional_ap(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);

    ieee80211_ap_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.bssid, AP_B1, 6);
    obs.ssid_len = 4;
    memcpy(obs.ssid, "conf", 4);
    obs.rssi = -50;
    obs.rx_channel = 6;
    obs.advertised_channel = 6;
    obs.ds_param_present = true;
    obs.complete = true;
    world_on_ap_observation(&w, &obs, 2000, true);
    check_invariants();

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(!(av.ap.flags & WORLD_AP_F_PROVISIONAL)); /* confirmed */
    CHECK(av.ap.ssid_known && av.ap.ssid_len == 4);
    CHECK(av.ap.beacon_count == 1);
    CHECK(av.ap.station_count == 1); /* binding survived confirmation */
    CHECK(av.ap.rssi == -50);        /* beacon RSSI replaces uplink-era */
}

/* ---------------- STA candidates and exclusions ---------------- */

static void t_broadcast_and_invalid_destinations(void)
{
    reset_world();

    /* Broadcast downlink: AP activity only. */
    const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ieee80211_data_addrs_t d = downlink(AP_B1, bcast);
    world_on_data_frame(&w, &d, 1000, 6, -50);

    /* Multicast (I/G bit). */
    const uint8_t mcast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    d = downlink(AP_B1, mcast);
    world_on_data_frame(&w, &d, 1100, 6, -51);

    /* Zero destination. */
    const uint8_t zero[6] = {0};
    d = downlink(AP_B1, zero);
    world_on_data_frame(&w, &d, 1200, 6, -52);

    /* The AP addressing itself: never its own client. */
    d = downlink(AP_B1, AP_B1);
    world_on_data_frame(&w, &d, 1300, 6, -53);

    /* Uplink with STA == BSSID. */
    ieee80211_data_addrs_t u = uplink(AP_B1, AP_B1);
    world_on_data_frame(&w, &u, 1400, 6, -54);

    /* Uplink with group-bit "BSSID". */
    const uint8_t gbssid[6] = {0x03, 0x11, 0x22, 0x33, 0x44, 0x05};
    u = uplink(STA_S1, gbssid);
    world_on_data_frame(&w, &u, 1500, 6, -55);

    check_invariants();
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 0);
    CHECK(snap.rel_current == 0);
    /* The four valid downlinks still refreshed the AP itself. */
    CHECK(snap.ap_current == 1);

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.data_down_count == 4);
    CHECK(av.ap.station_count == 0);
}

static void t_probe_discovers_sta_only(void)
{
    reset_world();

    ieee80211_probe_req_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.source, STA_S1, 6);
    obs.rssi = -65;
    obs.rx_channel = 3;
    obs.complete = true;

    world_on_probe_request(&w, &obs, 1000);
    world_on_probe_request(&w, &obs, 1100); /* repeat: still one record */
    world_on_probe_request(&w, &obs, 1200);
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1);
    CHECK(snap.ap_current == 0);   /* probes never create APs */
    CHECK(snap.rel_current == 0);  /* and never bind relations */

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.probe_count == 3);
    CHECK(sv.sta.tx_count == 3);
    CHECK(sv.sta.rssi == -65 && sv.sta.rssi_valid);
    CHECK(sv.sta.rel_ap == 0);

    /* Randomized (locally administered) MAC: own record, flagged. */
    ieee80211_probe_req_observation_t rnd = obs;
    memcpy(rnd.source, STA_RND, 6);
    world_on_probe_request(&w, &rnd, 1300);
    CHECK(sta_view(STA_RND, &sv));
    CHECK(sv.sta.locally_administered);
    CHECK(sv.sta.flags & WORLD_STA_F_RANDOM_MAC);

    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 2); /* two OBSERVED addresses, no claim
                                    * about physical device count */
}

static void t_mgmt_tx_records_sta(void)
{
    reset_world();

    world_on_sta_mgmt_tx(&w, STA_S2, 5000, 6, -70);
    world_on_sta_mgmt_tx(&w, STA_S2, 5100, 6, -71);
    check_invariants();

    world_sta_view_t sv;
    CHECK(sta_view(STA_S2, &sv));
    CHECK(sv.sta.tx_count == 2);
    CHECK(sv.sta.rssi == -71);
    CHECK(sv.sta.rel_ap == 0);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1 && snap.ap_current == 0 && snap.rel_current == 0);

    /* Invalid SA never creates a record. */
    const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    world_on_sta_mgmt_tx(&w, bcast, 5200, 6, -72);
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1);
    CHECK(snap.stats.obs_invalid == 1);
}

/* ---------------- evidence strength and switching ---------------- */

static void t_uplink_switches_to_newer_ap(void)
{
    reset_world();

    ieee80211_data_addrs_t a = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &a, 1000, 6, -45);
    a = uplink(STA_S1, AP_B2);
    world_on_data_frame(&w, &a, 2000, 1, -50);
    check_invariants();

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    world_ap_view_t av1;
    CHECK(ap_view(AP_B1, &av1));
    world_ap_view_t av2;
    CHECK(ap_view(AP_B2, &av2));
    CHECK(sv.sta.rel_ap != 0);

    /* Bound to AP2 now: station_count moved, not duplicated. */
    CHECK(av1.ap.station_count == 0);
    CHECK(av2.ap.station_count == 1);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.rel_conflicts == 1);
    CHECK(snap.stats.rel_switched == 1);
    CHECK(snap.stats.rel_formed == 2);
    CHECK(snap.rel_current == 1);
}

static void t_weaker_downlink_never_steals_binding(void)
{
    reset_world();

    /* Uplink binds STA to AP1 with the strongest evidence. */
    ieee80211_data_addrs_t a = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &a, 1000, 6, -45);

    /* Downlink from AP2 (weaker, even though newer) must NOT switch. */
    ieee80211_data_addrs_t d = downlink(AP_B2, STA_S1);
    world_on_data_frame(&w, &d, 5000, 1, -50);
    check_invariants();

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    world_ap_view_t av1;
    CHECK(ap_view(AP_B1, &av1));
    world_ap_view_t av2;
    CHECK(ap_view(AP_B2, &av2));
    CHECK(av1.ap.station_count == 1);
    CHECK(av2.ap.station_count == 0);
    CHECK(sv.sta.rel_evidence == WORLD_EVIDENCE_UPLINK);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.rel_conflicts == 1);
    CHECK(snap.stats.rel_switched == 0);

    /* A later UPLINK on AP2 (equal strength, newer) does switch. */
    a = uplink(STA_S1, AP_B2);
    world_on_data_frame(&w, &a, 6000, 1, -55);
    CHECK(ap_view(AP_B1, &av1));
    CHECK(av1.ap.station_count == 0);
    CHECK(ap_view(AP_B2, &av2));
    CHECK(av2.ap.station_count == 1);
    world_snapshot(&w, &snap);
    CHECK(snap.stats.rel_switched == 1);
    CHECK(snap.stats.rel_conflicts == 2);
}

static void t_equal_strength_freshness_wins(void)
{
    reset_world();

    ieee80211_data_addrs_t d = downlink(AP_B1, STA_S1);
    world_on_data_frame(&w, &d, 1000, 6, -50);
    d = downlink(AP_B2, STA_S1);
    world_on_data_frame(&w, &d, 2000, 1, -51);
    check_invariants();

    world_ap_view_t av1;
    CHECK(ap_view(AP_B1, &av1));
    world_ap_view_t av2;
    CHECK(ap_view(AP_B2, &av2));
    CHECK(av1.ap.station_count == 0);
    CHECK(av2.ap.station_count == 1);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.rel_switched == 1);
    CHECK(snap.stats.rel_conflicts == 1);
}

static void t_uplink_upgrades_downlink_evidence(void)
{
    reset_world();

    ieee80211_data_addrs_t d = downlink(AP_B1, STA_S1);
    world_on_data_frame(&w, &d, 1000, 6, -50);

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 2000, 6, -45);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rel_evidence == WORLD_EVIDENCE_UPLINK); /* upgraded */

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.rel_formed == 1);  /* same AP: no re-form */
    CHECK(snap.stats.rel_conflicts == 0);
    CHECK(snap.rel_current == 1);
}

/* ---------------- TTL semantics ---------------- */

static void t_relation_ttl_before_sta_ttl(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);

    /* Relation evidence ages out at 60 s: STA record survives to 120 s. */
    world_maintenance(&w, 1000 + WORLD_REL_TTL_MS);
    check_invariants();
    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.rel_current == 1); /* exactly at TTL: still bound */

    world_maintenance(&w, 1000 + WORLD_REL_TTL_MS + 1);
    check_invariants();
    world_snapshot(&w, &snap);
    CHECK(snap.rel_current == 0);
    CHECK(snap.sta_current == 1);  /* unbound, not "disconnected" */
    CHECK(snap.ap_current == 1);
    CHECK(snap.stats.rel_expired == 1);

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.station_count == 0);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rel_ap == 0);

    /* Later uplink re-binds (observed again). */
    world_on_data_frame(&w, &u, 1000 + WORLD_REL_TTL_MS + 2000, 6, -46);
    world_snapshot(&w, &snap);
    CHECK(snap.rel_current == 1);
    CHECK(snap.stats.rel_formed == 2);
}

static void t_sta_ttl_removes_record(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);
    /* Refresh AP_B1 and STA_S2 (bound via downlink) just before the
     * maintenance pass so both stay inside every TTL. */
    ieee80211_data_addrs_t d = downlink(AP_B1, STA_S2);
    world_on_data_frame(&w, &d, 1000 + WORLD_STA_TTL_MS - 1000, 6, -50);

    world_maintenance(&w, 1000 + WORLD_STA_TTL_MS + 1);
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1); /* only STA_S2 (freshly observed) */
    CHECK(snap.ap_current == 1);
    CHECK(snap.stats.sta_expired == 1);
    CHECK(snap.rel_current == 1);

    world_sta_view_t sv;
    CHECK(!sta_view(STA_S1, &sv));
    CHECK(sta_view(STA_S2, &sv));

    world_ap_view_t av;
    CHECK(ap_view(AP_B1, &av));
    CHECK(av.ap.station_count == 1); /* STA_S2 still bound via downlink */
}

static void t_ap_expiry_unbinds_but_keeps_sta(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);

    /* STA stays freshly observed via probes; the AP never speaks again. */
    ieee80211_probe_req_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.source, STA_S1, 6);
    obs.rssi = -60;
    obs.rx_channel = 6;
    obs.complete = true;
    world_on_probe_request(&w, &obs, 100000);

    world_maintenance(&w, 1000 + WORLD_AP_TTL_MS + 1); /* 121001 */
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == 0);
    CHECK(snap.sta_current == 1); /* unbound, alive on its own TTL */
    CHECK(snap.rel_current == 0);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rel_ap == 0);
}

static void t_stale_data_ignored(void)
{
    reset_world();

    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 5000, 6, -45);
    world_on_data_frame(&w, &u, 4000, 6, -90); /* backwards */

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.last_tx_ms == 5000);
    CHECK(sv.sta.rssi == -45);
    CHECK(sv.sta.tx_count == 1);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.obs_stale == 1);
    check_invariants();
}

/* ---------------- capacity, eviction, slot reuse ---------------- */

static void t_ap_slot_reuse_never_dangles(void)
{
    reset_world();

    /* AP1 in slot 0, bound STA_S1 (uplink at t=1000). */
    ieee80211_data_addrs_t u = uplink(STA_S1, AP_B1);
    world_on_data_frame(&w, &u, 1000, 6, -45);

    /* Fill the remaining 63 slots with beacons (newer last_seen). */
    for (uint8_t k = 1; k < WORLD_AP_MAX; k++) {
        uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, (uint8_t)(0x10 + k)};
        ieee80211_ap_observation_t obs;
        memset(&obs, 0, sizeof(obs));
        memcpy(obs.bssid, b, 6);
        obs.ssid_len = 2;
        memcpy(obs.ssid, "f", 2);
        obs.rssi = -50;
        obs.rx_channel = 6;
        obs.complete = true;
        world_on_ap_observation(&w, &obs, 2000 + k, true);
    }
    check_invariants();

    /* One more strong creator evicts the oldest AP = AP1 (last_seen 1000).
     * The binding must vanish with it; the STA survives unbound. */
    uint8_t extra[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x99};
    ieee80211_ap_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.bssid, extra, 6);
    obs.ssid_len = 1;
    memcpy(obs.ssid, "x", 1);
    obs.rssi = -40;
    obs.rx_channel = 6;
    obs.complete = true;
    world_on_ap_observation(&w, &obs, 9999, true);
    check_invariants();

    world_ap_view_t av;
    CHECK(!ap_view(AP_B1, &av));  /* evicted */

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rel_ap == 0);    /* unbound, no dangling slot reference */

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == WORLD_AP_MAX);
    CHECK(snap.sta_current == 1);
    CHECK(snap.rel_current == 0);
    CHECK(snap.stats.ap_evicted == 1);

    /* The slot AP1 occupied now hosts `extra`: station_count must be 0. */
    CHECK(ap_view(extra, &av));
    CHECK(av.ap.station_count == 0);

    /* A later uplink binds STA_S1 to the NEW AP in that slot. */
    ieee80211_data_addrs_t u2 = uplink(STA_S1, extra);
    world_on_data_frame(&w, &u2, 10500, 6, -47);
    check_invariants();
    CHECK(ap_view(extra, &av));
    CHECK(av.ap.station_count == 1);
}

static void t_weak_creators_never_evict(void)
{
    reset_world();

    /* Fill the STA table with strong creators (uplinks to one AP). */
    for (uint16_t k = 0; k < WORLD_STA_MAX; k++) {
        uint8_t s[6] = {0x50, 0x60, 0x70, 0x80, 0x91, 0x00};
        s[4] = (uint8_t)(0x91 + (k >> 8)); /* stays < 0xFF for k < 256 */
        s[5] = (uint8_t)k;                 /* distinct MACs */
        ieee80211_data_addrs_t u = uplink(s, AP_B1);
        world_on_data_frame(&w, &u, 1000 + k, 6, -45);
    }
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == WORLD_STA_MAX);
    CHECK(snap.stats.sta_created == WORLD_STA_MAX);

    /* Weak creator (downlink destination) with a full table: refused.
     * Timed close to the fill so nothing has aged out yet. */
    const uint8_t weak[6] = {0x50, 0x60, 0x70, 0x80, 0x92, 0x77};
    ieee80211_data_addrs_t d = downlink(AP_B1, weak);
    world_on_data_frame(&w, &d, 2000, 6, -50);
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == WORLD_STA_MAX);
    CHECK(snap.stats.sta_rejected == 1);
    CHECK(snap.stats.sta_evicted == 0);
    world_sta_view_t sv;
    CHECK(!sta_view(weak, &sv));

    /* Strong creator (probe) evicts the oldest STA deterministically. */
    const uint8_t strong[6] = {0x50, 0x60, 0x70, 0x80, 0x93, 0x88};
    ieee80211_probe_req_observation_t obs;
    memset(&obs, 0, sizeof(obs));
    memcpy(obs.source, strong, 6);
    obs.rssi = -50;
    obs.rx_channel = 6;
    obs.complete = true;
    world_on_probe_request(&w, &obs, 2100);
    world_snapshot(&w, &snap);
    CHECK(snap.stats.sta_evicted == 1);
    CHECK(snap.sta_current == WORLD_STA_MAX);
    CHECK(sta_view(strong, &sv));
    /* Oldest = the first-inserted STA (k=0 at t=1000). */
    const uint8_t k0[6] = {0x50, 0x60, 0x70, 0x80, 0x91, 0x00};
    CHECK(!sta_view(k0, &sv));
    check_invariants();

    /* Full-AP variant: data-inferred AP refused when the table is full. */
    for (uint8_t k = 1; k < WORLD_AP_MAX; k++) {
        uint8_t b[6] = {0x00, 0x11, 0x22, 0x33, 0x55, (uint8_t)(0x10 + k)};
        ieee80211_data_addrs_t dd = downlink(b, weak);
        world_on_data_frame(&w, &dd, 2200 + k, 6, -60);
    }
    world_snapshot(&w, &snap);
    CHECK(snap.ap_current == WORLD_AP_MAX); /* AP_B1 + 63 downlink APs */
    const uint8_t late_ap[6] = {0x00, 0x11, 0x22, 0x33, 0x55, 0xEE};
    ieee80211_data_addrs_t dd = downlink(late_ap, weak);
    world_on_data_frame(&w, &dd, 3000, 6, -60);
    world_snapshot(&w, &snap);
    CHECK(snap.stats.ap_rejected == 1);
    world_ap_view_t av;
    CHECK(!ap_view(late_ap, &av));
    check_invariants();
}

static void t_data_ambiguous_and_wds_counted(void)
{
    reset_world();

    ieee80211_data_addrs_t a;
    memset(&a, 0, sizeof(a));
    a.status = IEEE80211_DATA_ADDRS_AMBIGUOUS;
    memcpy(a.addr1, STA_S1, 6);
    memcpy(a.addr2, STA_S2, 6);
    world_on_data_frame(&w, &a, 1000, 6, -40);

    a.status = IEEE80211_DATA_ADDRS_WDS;
    memcpy(a.addr1, STA_S1, 6);
    memcpy(a.addr2, AP_B1, 6);
    memcpy(a.addr4, STA_S2, 6);
    world_on_data_frame(&w, &a, 1100, 6, -41);

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.stats.data_ambiguous == 1);
    CHECK(snap.stats.data_wds == 1);
    /* No infrastructure inference from either. */
    CHECK(snap.ap_current == 0);
    CHECK(snap.sta_current == 0);
    CHECK(snap.rel_current == 0);

    /* structurally unusable input */
    a.status = IEEE80211_DATA_ADDRS_TOO_SHORT;
    world_on_data_frame(&w, &a, 1200, 6, -42);
    world_snapshot(&w, &snap);
    CHECK(snap.stats.data_short == 1);
}

/* ---------------- end-to-end via the production parser ---------------- */

static void t_parser_to_world_data_end_to_end(void)
{
    reset_world();

    /* Real ToDS QoS data frame. */
    uint8_t frame[40];
    memset(frame, 0xAB, sizeof(frame)); /* encrypted-looking body */
    frame[0] = 0x88; /* QoS data */
    frame[1] = 0x41; /* ToDS + protected */
    for (int i = 0; i < 6; i++) {
        frame[IEEE80211_DATA_ADDR1_OFF + i] = AP_B1[i];
        frame[IEEE80211_DATA_ADDR2_OFF + i] = STA_S1[i];
        frame[IEEE80211_DATA_ADDR3_OFF + i] = GW_MAC[i];
    }

    ieee80211_data_addrs_t a;
    CHECK(ieee80211_parse_data_addresses(frame, sizeof(frame), &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    CHECK(a.protected_frame && a.qos && a.header_len == 26);

    world_on_data_frame(&w, &a, 7000, 6, -44);
    check_invariants();

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 1 && snap.ap_current == 1 && snap.rel_current == 1);

    world_sta_view_t sv;
    CHECK(sta_view(STA_S1, &sv));
    CHECK(sv.sta.rssi == -44 && sv.sta.rssi_valid);
}

/* ---------------- churn with invariants ---------------- */

static void t_relation_churn_invariants(void)
{
    reset_world();

    /* Repeated bind/switch/expiry cycles: station_count, rel_used and
     * station_count-per-AP stay exact after every step. Rounds are 30 s
     * apart, so relations (60 s TTL) stay live across consecutive rounds
     * and the rotating AP choice forces conflicts + switches; relations
     * age out every other round once evidence gaps exceed 60 s. */
    const uint8_t aps[3][6] = {
        {0x00, 0x11, 0x22, 0x33, 0x66, 0x01},
        {0x00, 0x11, 0x22, 0x33, 0x66, 0x02},
        {0x00, 0x11, 0x22, 0x33, 0x66, 0x03},
    };
    uint8_t stas[8][6];
    for (int i = 0; i < 8; i++) {
        stas[i][0] = 0x50;
        stas[i][1] = 0x60;
        stas[i][2] = 0x70;
        stas[i][3] = 0x80;
        stas[i][4] = 0x99;
        stas[i][5] = (uint8_t)(0x10 + i);
    }

    uint64_t now = 0;
    for (uint32_t round = 0; round < 60; round++) {
        /* 30 s gaps keep relations live (forcing conflicts + switches on
         * the rotating AP choice); every third round widens the gap past
         * the 60 s relation TTL (forcing expiries). Both stay under the
         * 120 s STA TTL so the STA records survive throughout. */
        now += (round % 3 == 2) ? 90000 : 30000;
        for (int i = 0; i < 8; i++) {
            ieee80211_data_addrs_t u = uplink(stas[i], aps[(round + i) % 3]);
            world_on_data_frame(&w, &u, now + i * 10, 6, -40 - (i % 20));
        }
        world_maintenance(&w, now + 29999);
        check_invariants();
    }

    world_snapshot_t snap;
    world_snapshot(&w, &snap);
    CHECK(snap.sta_current == 8);       /* active every round: alive */
    CHECK(snap.ap_current <= 3);
    CHECK(snap.rel_current <= 8);
    CHECK(snap.stats.rel_switched > 0);
    CHECK(snap.stats.rel_expired > 0);
    CHECK(snap.stats.rel_conflicts > 0);
    /* Bounded after heavy churn. */
    CHECK(snap.sta_current <= WORLD_STA_MAX);
    CHECK(snap.ap_current <= WORLD_AP_MAX);
}

int main(void)
{
    test_register("sta_uplink_discovers_sta_and_provisional_ap", t_uplink_discovers_sta_and_provisional_ap);
    test_register("sta_downlink_rssi_belongs_to_ap", t_downlink_rssi_belongs_to_ap);
    test_register("sta_up_and_down_same_sta_single_record", t_up_and_down_same_sta_single_record);
    test_register("sta_beacon_confirms_provisional_ap", t_beacon_confirms_provisional_ap);
    test_register("sta_broadcast_and_invalid_destinations", t_broadcast_and_invalid_destinations);
    test_register("sta_probe_discovers_sta_only", t_probe_discovers_sta_only);
    test_register("sta_mgmt_tx_records_sta", t_mgmt_tx_records_sta);
    test_register("sta_uplink_switches_to_newer_ap", t_uplink_switches_to_newer_ap);
    test_register("sta_weaker_downlink_never_steals_binding", t_weaker_downlink_never_steals_binding);
    test_register("sta_equal_strength_freshness_wins", t_equal_strength_freshness_wins);
    test_register("sta_uplink_upgrades_downlink_evidence", t_uplink_upgrades_downlink_evidence);
    test_register("sta_relation_ttl_before_sta_ttl", t_relation_ttl_before_sta_ttl);
    test_register("sta_sta_ttl_removes_record", t_sta_ttl_removes_record);
    test_register("sta_ap_expiry_unbinds_but_keeps_sta", t_ap_expiry_unbinds_but_keeps_sta);
    test_register("sta_stale_data_ignored", t_stale_data_ignored);
    test_register("sta_ap_slot_reuse_never_dangles", t_ap_slot_reuse_never_dangles);
    test_register("sta_weak_creators_never_evict", t_weak_creators_never_evict);
    test_register("sta_data_ambiguous_and_wds_counted", t_data_ambiguous_and_wds_counted);
    test_register("sta_parser_to_world_data_end_to_end", t_parser_to_world_data_end_to_end);
    test_register("sta_relation_churn_invariants", t_relation_churn_invariants);
    return test_run_all();
}
