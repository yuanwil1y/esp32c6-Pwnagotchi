#include "world.h"

#include <string.h>

/*
 * Phase 2 World Model core: AP database (2A) + STA database and
 * conservative AP<->STA relations (2B). Fixed-capacity, no allocation,
 * single-writer. All time is caller-supplied monotonic milliseconds.
 *
 * Capacity policy (deterministic and regression-tested):
 * - allocation prefers the LOWEST free slot (AP and STA tables);
 * - when a table is full, expired entries are swept first ("clear
 *   expired before evicting");
 * - a strong creator (beacon / probe response for APs; any
 *   STA-transmitted frame for STAs) may then evict the entry with the
 *   oldest last activity; ties break to the lowest slot index;
 * - a weak creator (data-inferred AP; downlink-only STA candidate) never
 *   evicts: the creation is refused and counted in *_rejected instead.
 *
 * Relation policy: one current observed AP per STA. Uplink evidence
 * outranks downlink; equal strength is decided by freshness. Switching is
 * counted (rel_switched) and every cross-AP observation of a live binding
 * is visible (rel_conflicts). AP removal / STA removal / relation TTL
 * unbind and maintain AP.station_count, which therefore always equals
 * the number of currently bound STAs.
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

static world_sta_t *find_sta(const world_t *w, const uint8_t mac[6])
{
    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        world_sta_t *sta = (world_sta_t *)&w->sta[i];
        if (sta->used && memcmp(sta->mac, mac, sizeof(sta->mac)) == 0) {
            return sta;
        }
    }
    return NULL;
}

static uint16_t ap_index(const world_t *w, const world_ap_t *ap)
{
    return (uint16_t)(ap - w->ap);
}

static uint16_t sta_index(const world_t *w, const world_sta_t *sta)
{
    return (uint16_t)(sta - w->sta);
}

/* True when `ap` is past its observation TTL at `now_ms`. */
static bool ap_expired_at(const world_ap_t *ap, uint64_t now_ms)
{
    return now_ms > ap->last_seen_ms &&
           now_ms - ap->last_seen_ms > WORLD_AP_TTL_MS;
}

static bool sta_expired_at(const world_sta_t *sta, uint64_t now_ms)
{
    return now_ms > sta->last_observed_ms &&
           now_ms - sta->last_observed_ms > WORLD_STA_TTL_MS;
}

static bool rel_expired_at(const world_sta_t *sta, uint64_t now_ms)
{
    return sta->rel_ap != 0 && now_ms > sta->rel_last_evidence_ms &&
           now_ms - sta->rel_last_evidence_ms > WORLD_REL_TTL_MS;
}

/* Unbind a STA from its current AP, maintaining the counters. */
static void sta_unbind(world_t *w, world_sta_t *sta)
{
    if (sta->rel_ap == 0) {
        return;
    }
    world_ap_t *ap = &w->ap[sta->rel_ap - 1];
    if (ap->used && ap->station_count > 0) {
        ap->station_count--;
    }
    sta->rel_ap = 0;
    sta->rel_evidence = WORLD_EVIDENCE_NONE;
    w->rel_used--;
}

static void sta_bind(world_t *w, world_sta_t *sta, world_ap_t *ap,
                     uint8_t evidence, uint64_t now_ms)
{
    sta->rel_ap = (uint8_t)(ap_index(w, ap) + 1);
    sta->rel_evidence = evidence;
    sta->rel_last_evidence_ms = now_ms;
    ap->station_count++;
    w->rel_used++;
    w->stats.rel_formed++;
}

/*
 * Remove an AP slot: first drop every relation pointing at it (the STAs
 * survive unbound), then free the slot. Slot reuse can therefore never
 * leave an old relation pointing at a new AP.
 */
static void ap_remove(world_t *w, world_ap_t *ap)
{
    if (!ap->used) {
        return;
    }
    const uint16_t idx = ap_index(w, ap);
    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        world_sta_t *sta = &w->sta[i];
        if (sta->used && sta->rel_ap == (uint8_t)(idx + 1)) {
            sta->rel_ap = 0;
            sta->rel_evidence = WORLD_EVIDENCE_NONE;
            w->rel_used--;
        }
    }
    ap->used = false;
    w->ap_used--;
}

/* Remove a STA slot: unbind first so station_count stays exact. */
static void sta_remove(world_t *w, world_sta_t *sta)
{
    if (!sta->used) {
        return;
    }
    sta_unbind(w, sta);
    sta->used = false;
    w->sta_used--;
}

/* Sweep every expired AP. Returns the number of removals. */
static uint16_t sweep_expired_aps(world_t *w, uint64_t now_ms)
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

static uint16_t sweep_expired_stas(world_t *w, uint64_t now_ms)
{
    uint16_t removed = 0;
    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        world_sta_t *sta = &w->sta[i];
        if (sta->used && sta_expired_at(sta, now_ms)) {
            sta_remove(w, sta);
            w->stats.sta_expired++;
            removed++;
        }
    }
    return removed;
}

/*
 * Find a free AP slot, sweeping expired entries and (for strong creators
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

    (void)sweep_expired_aps(w, now_ms);

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

/* Same policy for the STA table; activity = last_observed_ms. */
static world_sta_t *alloc_sta(world_t *w, uint64_t now_ms, bool strong_creator)
{
    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        if (!w->sta[i].used) {
            return &w->sta[i];
        }
    }

    (void)sweep_expired_stas(w, now_ms);

    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        if (!w->sta[i].used) {
            return &w->sta[i];
        }
    }

    if (!strong_creator) {
        w->stats.sta_rejected++;
        return NULL;
    }

    world_sta_t *victim = &w->sta[0];
    for (uint16_t i = 1; i < WORLD_STA_MAX; i++) {
        world_sta_t *cand = &w->sta[i];
        if (cand->last_observed_ms < victim->last_observed_ms) {
            victim = cand;
        }
    }
    sta_remove(w, victim);
    w->stats.sta_evicted++;
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
    if (!strong_creator) {
        ap->flags |= WORLD_AP_F_PROVISIONAL;
    }
    w->ap_used++;
    w->stats.ap_created++;
    return ap;
}

static world_sta_t *sta_create(world_t *w, const uint8_t mac[6],
                               uint64_t now_ms, bool strong_creator)
{
    world_sta_t *sta = alloc_sta(w, now_ms, strong_creator);
    if (sta == NULL) {
        return NULL;
    }

    memset(sta, 0, sizeof(*sta));
    sta->used = true;
    memcpy(sta->mac, mac, sizeof(sta->mac));
    sta->first_seen_ms = now_ms;
    sta->last_observed_ms = now_ms;
    sta->locally_administered = (mac[0] & 0x02) != 0;
    if (sta->locally_administered) {
        sta->flags |= WORLD_STA_F_RANDOM_MAC;
    }
    w->sta_used++;
    w->stats.sta_created++;
    return sta;
}

/*
 * Relation evidence for (sta, ap) at strength `evidence`.
 * Same AP: refresh time, keep the stronger strength.
 * Different AP: a live binding resists weaker-or-stale evidence; stronger
 * or fresher-or-equal evidence switches (both counted visible). An expired
 * binding is dropped first (rel_expired).
 */
static void relation_evidence(world_t *w, world_sta_t *sta, world_ap_t *ap,
                              uint8_t evidence, uint64_t now_ms)
{
    if (sta->rel_ap != 0) {
        if ((uint16_t)(sta->rel_ap - 1) == ap_index(w, ap)) {
            if (evidence > sta->rel_evidence) {
                sta->rel_evidence = evidence;
            }
            if (now_ms >= sta->rel_last_evidence_ms) {
                sta->rel_last_evidence_ms = now_ms;
            }
            return;
        }

        w->stats.rel_conflicts++;

        if (rel_expired_at(sta, now_ms)) {
            w->stats.rel_expired++;
            sta_unbind(w, sta);
        } else {
            const bool wins = evidence > sta->rel_evidence ||
                              (evidence == sta->rel_evidence &&
                               now_ms >= sta->rel_last_evidence_ms);
            if (!wins) {
                return; /* keep the stronger / newer evidence */
            }
            w->stats.rel_switched++;
            sta_unbind(w, sta);
        }
    }
    sta_bind(w, sta, ap, evidence, now_ms);
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

    /* The AP spoke for itself with a management frame: no longer merely
     * data-inferred. */
    ap->flags &= (uint8_t)~WORLD_AP_F_PROVISIONAL;

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

/* Uplink data: STA transmitted through the AP (ToDS=1). */
static void data_uplink(world_t *w, const uint8_t sta_mac[6],
                        const uint8_t bssid[6], uint64_t now_ms,
                        uint8_t rx_channel, int8_t rssi)
{
    if (!world_mac_is_unicast(sta_mac) || !world_mac_is_unicast(bssid) ||
        memcmp(sta_mac, bssid, 6) == 0) {
        w->stats.obs_invalid++;
        return;
    }

    world_sta_t *sta = find_sta(w, sta_mac);
    if (sta == NULL) {
        sta = sta_create(w, sta_mac, now_ms, true);
        if (sta == NULL) {
            return;
        }
    } else if (now_ms < sta->last_observed_ms) {
        w->stats.obs_stale++;
        return;
    }

    /* Transmitter is the STA: its RSSI, its tx bookkeeping. */
    sta->last_tx_ms = now_ms;
    sta->last_observed_ms = now_ms;
    sta->rssi = rssi;
    sta->rssi_valid = true;
    sta->last_rx_channel = rx_channel;
    sat_inc(&sta->tx_count);

    world_ap_t *ap = find_ap(w, bssid);
    if (ap == NULL) {
        /* Weak creator: data-inferred, provisional, never evicts. */
        ap = ap_create(w, bssid, now_ms, false);
        if (ap == NULL) {
            return;
        }
    }
    sat_inc(&ap->data_up_count);

    relation_evidence(w, sta, ap, WORLD_EVIDENCE_UPLINK, now_ms);
}

/* Downlink data: AP transmitted (FromDS=1). The AP is the freshness
 * anchor: a downlink older than the AP's own last sighting is dropped as
 * stale before any update (mirrors the uplink rule). */
static void data_downlink(world_t *w, const uint8_t bssid[6],
                          const uint8_t dest[6], uint64_t now_ms,
                          uint8_t rx_channel, int8_t rssi)
{
    if (!world_mac_is_unicast(bssid)) {
        w->stats.obs_invalid++;
        return;
    }

    world_ap_t *ap = find_ap(w, bssid);
    if (ap == NULL) {
        ap = ap_create(w, bssid, now_ms, false);
        if (ap == NULL) {
            return;
        }
    } else if (now_ms < ap->last_seen_ms) {
        w->stats.obs_stale++;
        return;
    }

    /* Transmitter is the AP: refreshes its own sighting + RSSI. */
    ap->last_seen_ms = now_ms;
    ap->last_rx_channel = rx_channel;
    ap->rssi = rssi;
    ap->rssi_valid = true;
    sat_inc(&ap->data_down_count);

    if (!world_mac_is_unicast(dest) || memcmp(dest, bssid, 6) == 0) {
        /* Broadcast/group/zero destination or the AP addressing itself:
         * AP activity only, never an STA record. */
        return;
    }

    world_sta_t *sta = find_sta(w, dest);
    if (sta == NULL) {
        /* Weak creator: only ever seen as a downlink destination. */
        sta = sta_create(w, dest, now_ms, false);
        if (sta == NULL) {
            return;
        }
    } else if (now_ms < sta->last_observed_ms) {
        /* The STA was seen more recently (e.g. via another AP): keep its
         * newer observation, only the AP-side refresh above applies. */
        return;
    }

    /* Destination-only sighting: NO tx time, NO RSSI for the STA (the
     * signal belongs to the AP; an offline client cannot be confirmed
     * online by AP retransmissions). */
    sta->last_observed_ms = now_ms;
    sta->last_rx_channel = rx_channel;
    sat_inc(&sta->dl_count);

    relation_evidence(w, sta, ap, WORLD_EVIDENCE_DOWNLINK, now_ms);
}

void world_on_data_frame(world_t *w, const ieee80211_data_addrs_t *addrs,
                         uint64_t now_ms, uint8_t rx_channel, int8_t rssi)
{
    if (w == NULL || addrs == NULL) {
        return;
    }

    switch (addrs->status) {
    case IEEE80211_DATA_ADDRS_OK:
        if (addrs->to_ds) {
            /* addr1 = BSSID, addr2 = transmitting STA. addr3 is the DS
             * side destination: never a wireless STA. */
            data_uplink(w, addrs->addr2, addrs->addr1, now_ms, rx_channel, rssi);
        } else {
            /* addr2 = transmitting AP (BSSID), unicast addr1 = STA
             * candidate. addr3 is the DS side source: never a STA. */
            data_downlink(w, addrs->addr2, addrs->addr1, now_ms, rx_channel, rssi);
        }
        break;
    case IEEE80211_DATA_ADDRS_WDS:
        w->stats.data_wds++;
        break;
    case IEEE80211_DATA_ADDRS_AMBIGUOUS:
        w->stats.data_ambiguous++;
        break;
    default:
        w->stats.data_short++;
        break;
    }
}

/* STA-transmitted sighting: probe, auth, (re)association request. */
static world_sta_t *sta_note_tx(world_t *w, const uint8_t mac[6],
                                uint64_t now_ms, uint8_t rx_channel,
                                int8_t rssi, bool strong_creator)
{
    if (!world_mac_is_unicast(mac)) {
        w->stats.obs_invalid++;
        return NULL;
    }

    world_sta_t *sta = find_sta(w, mac);
    if (sta == NULL) {
        sta = sta_create(w, mac, now_ms, strong_creator);
        if (sta == NULL) {
            return NULL;
        }
    } else if (now_ms < sta->last_observed_ms) {
        w->stats.obs_stale++;
        return NULL;
    }

    sta->last_tx_ms = now_ms;
    sta->last_observed_ms = now_ms;
    sta->rssi = rssi;
    sta->rssi_valid = true;
    sta->last_rx_channel = rx_channel;
    sat_inc(&sta->tx_count);
    return sta;
}

void world_on_probe_request(world_t *w,
                            const ieee80211_probe_req_observation_t *obs,
                            uint64_t now_ms)
{
    if (w == NULL || obs == NULL) {
        return;
    }

    world_sta_t *sta = sta_note_tx(w, obs->source, now_ms, obs->rx_channel,
                                   obs->rssi, true);
    if (sta != NULL) {
        sat_inc(&sta->probe_count);
    }
    /* No AP creation, no relation: a probe never implies association. */
}

void world_on_sta_mgmt_tx(world_t *w, const uint8_t mac[6],
                          uint64_t now_ms, uint8_t rx_channel, int8_t rssi)
{
    if (w == NULL) {
        return;
    }
    (void)sta_note_tx(w, mac, now_ms, rx_channel, rssi, true);
}

void world_maintenance(world_t *w, uint64_t now_ms)
{
    if (w == NULL) {
        return;
    }

    /* Order: AP expiry (drops relations pointing at them), relation TTL
     * (unbinds, STAs survive), STA expiry (unbinds on removal). */
    (void)sweep_expired_aps(w, now_ms);

    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        world_sta_t *sta = &w->sta[i];
        if (sta->used && rel_expired_at(sta, now_ms)) {
            w->stats.rel_expired++;
            sta_unbind(w, sta);
        }
    }

    (void)sweep_expired_stas(w, now_ms);
    w->stats.maint_runs++;
}

void world_snapshot(const world_t *w, world_snapshot_t *out)
{
    if (w == NULL || out == NULL) {
        return;
    }
    out->ap_current = w->ap_used;
    out->sta_current = w->sta_used;
    out->rel_current = w->rel_used;
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

bool world_get_sta(const world_t *w, uint16_t idx, world_sta_view_t *out)
{
    if (w == NULL || out == NULL || idx >= WORLD_STA_MAX || !w->sta[idx].used) {
        if (out != NULL) {
            out->valid = false;
        }
        return false;
    }
    out->sta = w->sta[idx];
    out->valid = true;
    return true;
}

bool world_check_invariants(const world_t *w)
{
    if (w == NULL) {
        return false;
    }

    uint16_t ap_used = 0;
    uint16_t sta_used = 0;
    uint16_t bound = 0;
    uint16_t station_counts[WORLD_AP_MAX] = {0};

    for (uint16_t i = 0; i < WORLD_STA_MAX; i++) {
        const world_sta_t *sta = &w->sta[i];
        if (!sta->used) {
            continue;
        }
        sta_used++;
        if (!world_mac_is_unicast(sta->mac)) {
            return false;
        }
        if (sta->rel_ap == 0) {
            continue;
        }
        if (sta->rel_ap > WORLD_AP_MAX) {
            return false;
        }
        if (sta->rel_evidence != WORLD_EVIDENCE_DOWNLINK &&
            sta->rel_evidence != WORLD_EVIDENCE_UPLINK) {
            return false;
        }
        if (!w->ap[sta->rel_ap - 1].used) {
            return false;
        }
        station_counts[sta->rel_ap - 1]++;
        bound++;
    }

    for (uint16_t i = 0; i < WORLD_AP_MAX; i++) {
        const world_ap_t *ap = &w->ap[i];
        if (!ap->used) {
            if (ap->station_count != 0) {
                return false;
            }
            continue;
        }
        ap_used++;
        if (!world_mac_is_unicast(ap->bssid)) {
            return false;
        }
        if (ap->ssid_len > IEEE80211_SSID_MAX_LEN) {
            return false;
        }
        if (ap->ssid_len > 0 && !ap->ssid_known) {
            return false;
        }
        if (ap->station_count != station_counts[i]) {
            return false;
        }
    }

    return ap_used == w->ap_used && sta_used == w->sta_used &&
           bound == w->rel_used;
}
