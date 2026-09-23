#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ieee80211_parser.h"

/*
 * Phase 1.5: host-testable AP observation dedup cache.
 *
 * Fixed-size (32 entries) round-robin dedup cache over BSSID, extracted
 * from wifi_sniffer.c so the observation merge policy can be regression
 * tested on the host. It is deliberately NOT an AP database: no TTL, no
 * timer, no allocation. Touched only from radio_rx_task on the target.
 */

#define OBS_AP_CACHE_SIZE 32

typedef struct {
    bool used;
    uint8_t bssid[6];
    uint8_t ssid_len;
    char ssid[IEEE80211_SSID_BUF_LEN];
    uint8_t adv_channel;
    uint8_t sec; /* ieee80211_security_t */
} obs_ap_entry_t;

typedef struct {
    obs_ap_entry_t entries[OBS_AP_CACHE_SIZE];
    uint8_t next;      /* round-robin insert cursor */
    uint32_t inserts;  /* new-BSSID insertions (incl. after eviction) */
    uint32_t updates;  /* changes to an already-cached BSSID */
    uint32_t evictions; /* inserts that overwrote a different live BSSID */

    /* Scratch for the most recent update() result (returned by value too).
     * Kept so callers can inspect without extra locking; the cache is only
     * touched from radio_rx_task. */
} obs_ap_cache_t;

/*
 * What the latest update decided:
 * - OBS_AP_INSERTED : first sight of this BSSID (should_log = true)
 * - OBS_AP_CHANGED  : known BSSID, ssid/channel/security changed
 * - OBS_AP_UNCHANGED: known BSSID, nothing changed
 * - OBS_AP_SKIPPED  : observation not reliable enough to touch the cache
 */
typedef enum {
    OBS_AP_INSERTED,
    OBS_AP_CHANGED,
    OBS_AP_UNCHANGED,
    OBS_AP_SKIPPED,
} obs_ap_action_t;

typedef struct {
    obs_ap_action_t action;
    bool should_log;
    uint8_t occupied;   /* live entries after the update (0..32) */
    uint32_t inserts;   /* cache totals after the update */
    uint32_t updates;
    uint32_t evictions;
} obs_ap_result_t;

void obs_ap_cache_init(obs_ap_cache_t *cache);

/*
 * Merge one beacon / probe response observation. `sec` is the coarse
 * presence-level classification for this observation.
 *
 * Semantics guard rails (regression-tested):
 * - occupied never exceeds OBS_AP_CACHE_SIZE; inserting into a full cache
 *   evicts the oldest slot and counts one eviction.
 * - updates counts changes to known BSSIDs only; UNCHANGED observations
 *   never bump change counters (this replaces the pre-1.5 `ap_unique`
 *   counter, which grew on every changed attribute and after every
 *   eviction-reappearance).
 * - The counters are cache-change bookkeeping, NOT "total unique APs" and
 *   not a TTL-based "currently online" count.
 */
obs_ap_result_t obs_ap_cache_update(obs_ap_cache_t *cache,
                                    const ieee80211_ap_observation_t *obs,
                                    uint8_t sec);

/*
 * Test/inspection helper: fetch the cached entry for a BSSID.
 * Returns false when the BSSID is not currently cached.
 */
bool obs_ap_cache_find(const obs_ap_cache_t *cache, const uint8_t bssid[6],
                       obs_ap_entry_t *out);
