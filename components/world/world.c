#include "world.h"

#include <string.h>

/*
 * Phase 2A World Model core: AP database. Fixed-capacity, no allocation,
 * single-writer. All time is caller-supplied monotonic milliseconds.
 *
 * Capacity policy (deterministic and regression-tested):
 * - allocation prefers the LOWEST free slot;
 * - when the table is full, expired entries are swept first ("clear
 *   expired before evicting");
 * - a strong creator (beacon / probe response, i.e. the AP itself spoke)
 *   may then evict the entry with the oldest last_seen; ties break to the
 *   lowest slot index;
 * - a weak creator (Phase 2B data-inferred AP) never evicts: the creation
 *   is refused and counted in ap_rejected instead.
 */

static void sat_inc(uint16_t *v)
{
    if (*v < UINT16_MAX) {
        (*v)++;
    }
}

bool world_mac_is_zero(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    return memcmp(mac, zero, sizeof(zero)) == 0;
}

bool world_mac_is_unicast(const uint8_t mac[6])
{
    /* Nonzero and without the I/G (group) bit. */
    return !world_mac_is_zero(mac) && (mac[0] & 0x01) == 0;
}

void world_init(world_t *w)
{
    if (w == NULL) {
        return;
    }
    memset(w, 0, sizeof(*w));
}

static world_ap_t *find_ap(const world_t *w, const uint8_t bssid[6])
{
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        world_ap_t *ap = (world_ap_t *)&w->ap[i];
        if (ap->used && memcmp(ap->bssid, bssid, sizeof(ap->bssid)) == 0) {
            return ap;
        }
    }
    return NULL;
}

/* True when `ap` is past its observation TTL at `now_ms`. */
static bool ap_expired_at(const world_ap_t *ap, uint64_t now_ms)
{
    return now_ms > ap->last_seen_ms &&
           now_ms - ap->last_seen_ms > WORLD_AP_TTL_MS;
}

static void ap_remove(world_t *w, world_ap_t *ap)
{
    ap->used = false;
    w->ap_used--;
    /* Phase 2B will unbind relations here; no relations exist yet. */
}

/* Sweep every expired AP. Returns the number of removals. */
static uint16_t sweep_expired(world_t *w, uint64_t now_ms)
{
    uint16_t removed = 0;
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        world_ap_t *ap = &w->ap[i];
        if (ap->used && ap_expired_at(ap, now_ms)) {
            ap_remove(w, ap);
            w->stats.ap_expired++;
            removed++;
        }
    }
    return removed;
}

/*
 * Find a free slot, sweeping expired entries and (for strong creators
 * only) evicting the deterministically oldest entry when needed.
 * Returns NULL when the table stays full (counted in ap_rejected).
 */
static world_ap_t *alloc_ap(world_t *w, uint64_t now_ms, bool strong_creator)
{
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        if (!w->ap[i].used) {
            return &w->ap[i];
        }
    }

    (void)sweep_expired(w, now_ms);

    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        if (!w->ap[i].used) {
            return &w->ap[i];
        }
    }

    if (!strong_creator) {
        w->stats.ap_rejected++;
        return NULL;
    }

    /* Oldest last_seen wins; ties break to the lowest slot index. */
    world_ap_t *victim = &w->ap[0];
    for (uint16_t i = 1; i < WORLD_AP_MAX; i++) {
        world_ap_t *cand = &w->ap[i];
        if (cand->last_seen_ms < victim->last_seen_ms) {
            victim = cand;
        }
    }
    ap_remove(w, victim);
    w->stats.ap_evicted++;
    return victim;
}

static world_ap_t *ap_create(world_t *w, const uint8_t bssid[6],
                             uint64_t now_ms, bool strong_creator)
{
    world_ap_t *ap = alloc_ap(w, now_ms, strong_creator);
    if (ap == NULL) {
        return NULL;
    }

    memset(ap, 0, sizeof(*ap));
    ap->used = true;
    memcpy(ap->bssid, bssid, sizeof(ap->bssid));
    ap->first_seen_ms = now_ms;
    ap->last_seen_ms = now_ms;
    ap->sec_state = WORLD_SEC_UNKNOWN;
    w->ap_used++;
    w->stats.ap_created++;
    return ap;
}

void world_on_ap_observation(world_t *w,
                             const ieee80211_ap_observation_t *obs,
                             uint64_t now_ms, bool is_beacon)
{
    if (w == NULL || obs == NULL) {
        return;
    }
    if (!world_mac_is_unicast(obs->bssid)) {
        w->stats.obs_invalid++;
        return;
    }

    world_ap_t *ap = find_ap(w, obs->bssid);
    if (ap == NULL) {
        /* Beacon / probe response: the AP itself spoke, a strong creator. */
        ap = ap_create(w, obs->bssid, now_ms, true);
        if (ap == NULL) {
            return; /* counted in ap_rejected */
        }
    } else if (now_ms < ap->last_seen_ms) {
        /* Monotonic-clock violation: never regress any field. */
        w->stats.obs_stale++;
        return;
    }

    /* Activity refresh: valid for every observation that reached the
     * parser, complete or not (the frame was received; its header was
     * bounds-checked before this point). */
    ap->last_seen_ms = now_ms;
    ap->last_rx_channel = obs->rx_channel;
    ap->rssi = obs->rssi;
    ap->rssi_valid = true;
    sat_inc(is_beacon ? &ap->beacon_count : &ap->probe_resp_count);

    /* Advertised channel: positive evidence from a fully parsed, valid
     * DS Parameter IE. Usable even when the capture was cut later in the
     * frame; never cleared by absence. */
    if (obs->ds_param_present && obs->advertised_channel != 0) {
        ap->advertised_channel = obs->advertised_channel;
    }

    /* SSID: only a COMPLETE observation with a real (non-hidden) name may
     * set or replace the learned name. */
    if (obs->complete && !obs->hidden_ssid && obs->ssid_len > 0) {
        memcpy(ap->ssid, obs->ssid, obs->ssid_len);
        ap->ssid_len = obs->ssid_len;
        ap->ssid_known = true;
    }

    /* Security (Phase 2A: presence level).
     * - positive RSN/WPA presence from a complete observation => KNOWN;
     * - complete without security IEs: privacy bit decides OPEN vs
     *   LEGACY_PRIVACY (never asserted as WEP);
     * - truncated/malformed observations never touch security state. */
    if (obs->complete) {
        if (obs->rsn_present || obs->wpa_vendor_present) {
            memset(&ap->sec, 0, sizeof(ap->sec));
            ap->sec.rsn_present = obs->rsn_present;
            ap->sec.wpa_present = obs->wpa_vendor_present;
            ap->sec.privacy = obs->privacy;
            ap->sec_state = WORLD_SEC_KNOWN;
        } else if (obs->privacy) {
            memset(&ap->sec, 0, sizeof(ap->sec));
            ap->sec.privacy = true;
            ap->sec_state = WORLD_SEC_LEGACY_PRIVACY;
        } else {
            memset(&ap->sec, 0, sizeof(ap->sec));
            ap->sec_state = WORLD_SEC_OPEN;
        }
    }
}

void world_maintenance(world_t *w, uint64_t now_ms)
{
    if (w == NULL) {
        return;
    }
    (void)sweep_expired(w, now_ms);
    w->stats.maint_runs++;
}

void world_snapshot(const world_t *w, world_snapshot_t *out)
{
    if (w == NULL || out == NULL) {
        return;
    }
    out->ap_current = w->ap_used;
    out->stats = w->stats;
}

bool world_get_ap(const world_t *w, uint16_t idx, world_ap_view_t *out)
{
    if (w == NULL || out == NULL || idx >= WORLD_AP_MAX || !w->ap[idx].used) {
        if (out != NULL) {
            out->valid = false;
        }
        return false;
    }
    out->ap = w->ap[idx];
    out->valid = true;
    return true;
}

bool world_check_invariants(const world_t *w)
{
    if (w == NULL) {
        return false;
    }

    uint16_t used = 0;
    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        const world_ap_t *ap = &w->ap[i];
        if (!ap->used) {
            continue;
        }
        used++;
        if (!world_mac_is_unicast(ap->bssid)) {
            return false;
        }
        if (ap->ssid_len > IEEE80211_SSID_MAX_LEN) {
            return false;
        }
        if (ap->ssid_len > 0 && !ap->ssid_known) {
            return false;
        }
        /* No relations exist before Phase 2B. */
        if (ap->station_count != 0) {
            return false;
        }
    }
    return used == w->ap_used;
}
