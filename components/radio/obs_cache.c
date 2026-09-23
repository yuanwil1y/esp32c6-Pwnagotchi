#include "obs_cache.h"

#include <string.h>

/*
 * INTERMEDIATE Phase 1.5 commit: the merge policy below is the pre-1.5
 * wifi_sniffer.c ap_cache_update() logic verbatim (behind the new API), so
 * the regression tests added next can demonstrate the defects failing:
 *   - observations that are incomplete/malformed still overwrite cached
 *     fields (no OBS_AP_SKIPPED path),
 *   - a hidden/missing SSID erases a previously known SSID,
 *   - an observation without a DS Parameter IE clears the cached
 *     advertised channel.
 * The conservative merge policy lands in a later commit and flips the
 * tests without changing them.
 */

void obs_ap_cache_init(obs_ap_cache_t *cache)
{
    if (cache == NULL) {
        return;
    }
    memset(cache, 0, sizeof(*cache));
}

obs_ap_result_t obs_ap_cache_update(obs_ap_cache_t *cache,
                                    const ieee80211_ap_observation_t *obs,
                                    uint8_t sec)
{
    obs_ap_result_t res = {0};

    if (cache == NULL || obs == NULL) {
        res.action = OBS_AP_SKIPPED;
        return res;
    }

    for (int i = 0; i < OBS_AP_CACHE_SIZE; i++) {
        obs_ap_entry_t *e = &cache->entries[i];
        if (!e->used || memcmp(e->bssid, obs->bssid, sizeof(e->bssid)) != 0) {
            continue;
        }

        const bool changed = e->ssid_len != obs->ssid_len ||
                             memcmp(e->ssid, obs->ssid, obs->ssid_len) != 0 ||
                             e->adv_channel != obs->advertised_channel ||
                             e->sec != sec;

        /* Pre-1.5 defect: unconditional overwrite, including empty/hidden
         * SSID over a known name and zero advertised channel over a known
         * channel. */
        e->ssid_len = obs->ssid_len;
        memcpy(e->ssid, obs->ssid, sizeof(e->ssid));
        e->adv_channel = obs->advertised_channel;
        e->sec = sec;

        res.action = changed ? OBS_AP_CHANGED : OBS_AP_UNCHANGED;
        res.should_log = changed;
        if (changed) {
            cache->updates++;
        }
        goto out;
    }

    obs_ap_entry_t *e = &cache->entries[cache->next % OBS_AP_CACHE_SIZE];
    cache->next++;
    if (e->used) {
        cache->evictions++;
    } else {
        e->used = true;
    }
    cache->inserts++;
    memcpy(e->bssid, obs->bssid, sizeof(e->bssid));
    e->ssid_len = obs->ssid_len;
    memcpy(e->ssid, obs->ssid, sizeof(e->ssid));
    e->adv_channel = obs->advertised_channel;
    e->sec = sec;
    res.action = OBS_AP_INSERTED;
    res.should_log = true;

out:
    res.occupied = 0;
    for (int i = 0; i < OBS_AP_CACHE_SIZE; i++) {
        if (cache->entries[i].used) {
            res.occupied++;
        }
    }
    res.inserts = cache->inserts;
    res.updates = cache->updates;
    res.evictions = cache->evictions;
    return res;
}

bool obs_ap_cache_find(const obs_ap_cache_t *cache, const uint8_t bssid[6],
                       obs_ap_entry_t *out)
{
    if (cache == NULL || bssid == NULL) {
        return false;
    }
    for (int i = 0; i < OBS_AP_CACHE_SIZE; i++) {
        const obs_ap_entry_t *e = &cache->entries[i];
        if (e->used && memcmp(e->bssid, bssid, sizeof(e->bssid)) == 0) {
            if (out != NULL) {
                *out = *e;
            }
            return true;
        }
    }
    return false;
}
