/* Phase 1.5 host regression tests: AP observation dedup cache (production
 * code). Observations are built directly; the merge policy is the unit
 * under test. */
#include "obs_cache.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

static const uint8_t BSS_A[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t BSS_B[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

static ieee80211_ap_observation_t make_obs(const uint8_t bssid[6],
                                           const char *ssid,
                                           bool rsn, uint8_t adv_ch,
                                           bool complete)
{
    ieee80211_ap_observation_t obs = {0};
    memcpy(obs.bssid, bssid, 6);
    if (ssid != NULL) {
        obs.ssid_len = (uint8_t)strlen(ssid);
        memcpy(obs.ssid, ssid, obs.ssid_len);
    }
    obs.rsn_present = rsn;
    obs.advertised_channel = adv_ch;
    obs.ds_param_present = adv_ch != 0;
    obs.complete = complete;
    return obs;
}

static void t_insert_change_unchanged(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    ieee80211_ap_observation_t o1 = make_obs(BSS_A, "Home", true, 6, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &o1, 3 /* RSN */);
    CHECK(r.action == OBS_AP_INSERTED);
    CHECK(r.should_log);
    CHECK(r.occupied == 1);
    CHECK(r.inserts == 1);
    CHECK(r.updates == 0);

    /* Identical repeat: no change, no log. */
    r = obs_ap_cache_update(&c, &o1, 3);
    CHECK(r.action == OBS_AP_UNCHANGED);
    CHECK(!r.should_log);
    CHECK(r.updates == 0);

    /* Attribute change: change counted, log. */
    o1.advertised_channel = 11;
    r = obs_ap_cache_update(&c, &o1, 3);
    CHECK(r.action == OBS_AP_CHANGED);
    CHECK(r.should_log);
    CHECK(r.updates == 1);
    CHECK(r.occupied == 1);

    obs_ap_entry_t e;
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.adv_channel == 11);
    CHECK(e.ssid_len == 4);
    CHECK(e.sec == 3);
}

static void t_eviction_and_reappear(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    for (int i = 0; i < OBS_AP_CACHE_SIZE; i++) {
        uint8_t bssid[6] = {0x02, 0, 0, 0, 0, (uint8_t)i};
        ieee80211_ap_observation_t o = make_obs(bssid, NULL, false, 1, true);
        obs_ap_result_t r = obs_ap_cache_update(&c, &o, 0);
        CHECK(r.action == OBS_AP_INSERTED);
    }
    CHECK(c.evictions == 0);

    /* 33rd BSSID: one eviction, occupied stays at 32. */
    uint8_t b33[6] = {0x02, 0, 0, 0, 0, 32};
    ieee80211_ap_observation_t o33 = make_obs(b33, NULL, false, 1, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &o33, 0);
    CHECK(r.action == OBS_AP_INSERTED);
    CHECK(r.occupied == OBS_AP_CACHE_SIZE);
    CHECK(r.evictions == 1);

    /* The evicted BSSID is gone. */
    CHECK(!obs_ap_cache_find(&c, BSS_A, NULL));

    /* Reappearance is an INSERT (cache change), not a "unique AP". */
    ieee80211_ap_observation_t o1b = make_obs(BSS_A, "Home", false, 6, true);
    r = obs_ap_cache_update(&c, &o1b, 0);
    CHECK(r.action == OBS_AP_INSERTED);
    CHECK(r.inserts == OBS_AP_CACHE_SIZE + 2);
    CHECK(r.evictions == 2);
}

/* Phase 1.5 issue 5: an incomplete observation must not degrade cached
 * knowledge. Conservative policy: skipped entirely (no state change, no
 * log line); only complete observations may update the cache. */
static void t_incomplete_observation_skipped(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    /* Known good: RSN, named, channel 6. */
    ieee80211_ap_observation_t good = make_obs(BSS_A, "Home", true, 6, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &good, 3);
    CHECK(r.action == OBS_AP_INSERTED);

    /* Truncated copy of the same beacon: no SSID, no RSN IE visible. */
    ieee80211_ap_observation_t bad = make_obs(BSS_A, NULL, false, 0, false);
    r = obs_ap_cache_update(&c, &bad, 0);
    CHECK(r.action == OBS_AP_SKIPPED);
    CHECK(r.should_log == false);

    /* The cache must still know everything from the complete observation. */
    obs_ap_entry_t e;
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.ssid_len == 4);
    CHECK(memcmp(e.ssid, "Home", 4) == 0);
    CHECK(e.sec == 3);
    CHECK(e.adv_channel == 6);

    /* A later complete observation still merges normally. */
    ieee80211_ap_observation_t good2 = make_obs(BSS_A, "Home", true, 11, true);
    r = obs_ap_cache_update(&c, &good2, 3);
    CHECK(r.action == OBS_AP_CHANGED);
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.adv_channel == 11);
    CHECK(e.ssid_len == 4);
}

/* Phase 1.5 issue 5: a hidden/missing SSID in a complete observation must
 * not erase a known name. Security/channel may still merge. */
static void t_hidden_ssid_keeps_known_name(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    ieee80211_ap_observation_t named = make_obs(BSS_A, "PwnLab", false, 6, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &named, 0);
    CHECK(r.action == OBS_AP_INSERTED);

    /* Same BSSID now hides its SSID (complete beacon, empty SSID IE). */
    ieee80211_ap_observation_t hidden = make_obs(BSS_A, NULL, true, 6, true);
    r = obs_ap_cache_update(&c, &hidden, 3);
    CHECK(r.action == OBS_AP_CHANGED); /* security changed: still a change */

    obs_ap_entry_t e;
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.ssid_len == 6);
    CHECK(memcmp(e.ssid, "PwnLab", 6) == 0);
    CHECK(e.sec == 3); /* complete observation: negative evidence allowed */
}

/* Phase 1.5 issue 5: an observation without a usable DS Parameter IE must
 * not clear the cached advertised channel. */
static void t_absent_ds_keeps_cached_channel(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    ieee80211_ap_observation_t with_ds = make_obs(BSS_A, "CH", false, 9, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &with_ds, 0);
    CHECK(r.action == OBS_AP_INSERTED);

    ieee80211_ap_observation_t no_ds = make_obs(BSS_A, "CH", false, 0, true);
    r = obs_ap_cache_update(&c, &no_ds, 0);
    CHECK(r.action == OBS_AP_UNCHANGED);

    obs_ap_entry_t e;
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.adv_channel == 9);
}

/* Phase 1.5: coarse security is presence-level; a COMPLETE observation
 * without security IEs is valid negative evidence for OPEN. */
static void t_complete_observation_negative_evidence(void)
{
    obs_ap_cache_t c;
    obs_ap_cache_init(&c);

    ieee80211_ap_observation_t rsn = make_obs(BSS_A, "Net", true, 6, true);
    obs_ap_result_t r = obs_ap_cache_update(&c, &rsn, 3);
    CHECK(r.action == OBS_AP_INSERTED);

    ieee80211_ap_observation_t open = make_obs(BSS_A, "Net", false, 6, true);
    r = obs_ap_cache_update(&c, &open, 0);
    CHECK(r.action == OBS_AP_CHANGED);

    obs_ap_entry_t e;
    CHECK(obs_ap_cache_find(&c, BSS_A, &e));
    CHECK(e.sec == 0); /* OPEN, from a complete observation */
}

int main(void)
{
    test_register("ap_insert_change_unchanged", t_insert_change_unchanged);
    test_register("ap_eviction_and_reappear", t_eviction_and_reappear);
    test_register("ap_incomplete_observation_skipped",
                  t_incomplete_observation_skipped);
    test_register("ap_hidden_ssid_keeps_known_name",
                  t_hidden_ssid_keeps_known_name);
    test_register("ap_absent_ds_keeps_cached_channel",
                  t_absent_ds_keeps_cached_channel);
    test_register("ap_complete_observation_negative_evidence",
                  t_complete_observation_negative_evidence);
    return test_run_all();
}
