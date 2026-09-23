#include "obs_cache.h"

#include <string.h>

/*
 * Phase 1.5 observation merge policy (issue 5). Coarse presence-level
 * classification only; the full security parser stays Phase 2.
 *
 * Merge policy - an observation is merged only when it is COMPLETE
 * (whole MAC body captured, walk finished cleanly, no malformed /
 * incomplete / duplicated-critical IEs). Anything else is skipped
 * entirely: it can neither confirm nor deny, and "no RSN IE seen" in a
 * truncated capture must never become "OPEN" or erase a known SSID.
 *
 * For complete observations:
 * - security is authoritative (presence-level: RSN > WPA > PRIVACY >
 *   OPEN; a complete frame without security IEs is valid negative
 *   evidence for OPEN),
 * - a missing/hidden SSID never erases a previously known name,
 * - advertised_channel is written only when the observation carries a
 *   valid DS value (0 = absent/invalid keeps the cached channel);
 *   rx_channel is handled by the caller and stays independent.
 */

void obs_ap_cache_init(obs_ap_cache_t *cache)
{
    if (cache == NULL) {
        return;
    }
    memset(cache, 0, sizeof(*cache));
}

static obs_ap_result_t obs_finish(const obs_ap_cache_t *cache,
                                  obs_ap_action_t action, bool should_log)
{
    obs_ap_result_t res = {0};
    res.action = action;
    res.should_log = should_log;
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

obs_ap_result_t obs_ap_cache_update(obs_ap_cache_t *cache,
                                    const ieee80211_ap_observation_t *obs,
                                    uint8_t sec)
{
    if (cache == NULL || obs == NULL) {
        obs_ap_result_t res = {0};
        res.action = OBS_AP_SKIPPED;
        return res;
    }

    if (!obs->complete) {
        /* Incomplete / malformed observation: conservative skip. */
        return obs_finish(cache, OBS_AP_SKIPPED, false);
    }

    for (int i = 0; i < OBS_AP_CACHE_SIZE; i++) {
        obs_ap_entry_t *e = &cache->entries[i];
        if (!e->used || memcmp(e->bssid, obs->bssid, sizeof(e->bssid)) != 0) {
            continue;
        }

        /* Merged view: keep cached knowledge where the observation is
         * silent (hidden/missing SSID, absent/invalid DS channel). */
        const uint8_t new_ssid_len = obs->ssid_len > 0 ? obs->ssid_len
                                                       : e->ssid_len;
        const uint8_t new_adv = obs->advertised_channel != 0
                                    ? obs->advertised_channel
                                    : e->adv_channel;

        const bool changed = e->ssid_len != new_ssid_len ||
                             memcmp(e->ssid, obs->ssid_len > 0 ? obs->ssid : e->ssid,
                                    new_ssid_len) != 0 ||
                             e->adv_channel != new_adv ||
                             e->sec != sec;

        e->ssid_len = new_ssid_len;
        memcpy(e->ssid, obs->ssid_len > 0 ? obs->ssid : e->ssid,
               sizeof(e->ssid));
        e->adv_channel = new_adv;
        e->sec = sec;

        if (changed) {
            cache->updates++;
        }
        return obs_finish(cache, changed ? OBS_AP_CHANGED : OBS_AP_UNCHANGED,
                          changed);
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
    return obs_finish(cache, OBS_AP_INSERTED, true);
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
