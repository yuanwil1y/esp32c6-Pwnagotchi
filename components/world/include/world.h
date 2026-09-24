#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ieee80211_parser.h"

/*
 * Phase 2 World Model: host-testable AP database (Phase 2A), STA database
 * and conservative AP<->STA observation relations (Phase 2B).
 *
 * Pure C value-domain code: no FreeRTOS, no LVGL, no driver, no heap, no
 * wall clock. Every entry point takes `now_ms` (a monotonically increasing
 * millisecond count supplied by the caller) so time-driven behaviour (TTL,
 * deterministic eviction) is testable with a virtual clock on the host.
 *
 * Concurrency model: ONE writer (radio_rx_task on the target) plus snapshot
 * readers. The target adapter serializes access with a task-level mutex;
 * the structures below are plain data so a snapshot copy under that mutex
 * is a short, bounded operation. Nothing here disables interrupts.
 *
 * Evidence policy (Phase 2 core semantics):
 * - Observations are value types; no packet-pool pointers are retained.
 * - Only a COMPLETE observation is authoritative for "absence" (e.g. no RSN
 *   IE => the AP is open). A truncated capture may still contribute fields
 *   that were fully parsed before the cut (positive evidence), plus
 *   activity/rssi/channel metadata.
 * - Hidden or missing SSIDs never overwrite a previously learned name.
 * - Transmitter RSSI belongs to the transmitter: STA uplink RSSI is never
 *   written into the AP record and AP downlink RSSI is never written into
 *   the STA record.
 *
 * Relation model (Phase 2B): one current observed AP per STA. Relations
 * are OBSERVED / INFERRED from data frames only; nothing here claims a
 * successful 802.11 association. Uplink (STA transmitted) evidence is
 * stronger than downlink (STA was the unicast destination); equal
 * strengths are decided by freshness. TTL expiry means the OBSERVATION
 * aged out - never that a client was "disconnected".
 */

/* Named configuration constants (starting points, not verified hardware
 * conclusions; see docs/PHASE2_WORLD_MODEL.md for the sizing report). */
#define WORLD_AP_MAX            64
#define WORLD_STA_MAX           128
#define WORLD_AP_TTL_MS         120000u  /* AP observation expiry   */
#define WORLD_STA_TTL_MS        120000u  /* STA observation expiry  */
#define WORLD_REL_TTL_MS        60000u   /* relation evidence expiry */

/* Evidence strength for AP<->STA relations. Higher wins over equal-freshness
 * weaker evidence; freshness breaks ties between equal strength. */
enum {
    WORLD_EVIDENCE_NONE     = 0,
    WORLD_EVIDENCE_DOWNLINK = 1,  /* AP transmitted to the STA address */
    WORLD_EVIDENCE_UPLINK   = 2,  /* STA transmitted through the AP    */
};

/* AP record flags. */
#define WORLD_AP_F_PROVISIONAL  0x01u  /* inferred from data, no beacon */

/* STA record flags. */
#define WORLD_STA_F_RANDOM_MAC  0x01u  /* locally administered bit seen  */

/*
 * One AP. BSSID is the unique key. Raw SSID bytes are stored unsanitized;
 * only output paths sanitize (ieee80211_ssid_to_printable).
 */
typedef struct {
    bool used;
    uint8_t bssid[6];

    uint8_t ssid_len;      /* 0 = no name learned yet */
    bool ssid_known;       /* a real (non-hidden) name was seen */
    char ssid[IEEE80211_SSID_MAX_LEN];

    uint64_t first_seen_ms;
    uint64_t last_seen_ms; /* refreshed by AP-transmitted frames only */

    uint8_t advertised_channel;  /* DS Parameter Set value, 0 = unknown */
    uint8_t last_rx_channel;     /* radio channel of the last sighting */

    /* Security knowledge, merged per the rules in world_on_ap_observation. */
    ieee80211_security_desc_t sec;
    uint8_t sec_state;      /* world_sec_state_t */

    int8_t rssi;            /* transmitter RSSI of the AP's own frames */
    bool rssi_valid;

    /* Saturating activity counters (magnitude, not exact census). */
    uint16_t beacon_count;
    uint16_t probe_resp_count;
    uint16_t data_down_count;  /* AP-transmitted data frames (incl. bcast) */
    uint16_t data_up_count;    /* STA frames relayed through this AP */

    /* Invariant: equals the number of STAs currently bound to this AP
     * (maintained on bind/unbind/removal; checked by
     * world_check_invariants). */
    uint16_t station_count;

    uint8_t flags;
} world_ap_t;

/* Security knowledge state for one AP. */
typedef enum {
    WORLD_SEC_UNKNOWN = 0,     /* nothing reliable seen yet */
    WORLD_SEC_KNOWN,           /* >=1 valid RSN/WPA parse (suites in sec) */
    WORLD_SEC_LEGACY_PRIVACY,  /* complete obs: privacy bit, no RSN/WPA IE */
    WORLD_SEC_OPEN,            /* complete obs: privacy=0, no RSN/WPA IE */
} world_sec_state_t;

/*
 * One observed STA: an OBSERVATION of a MAC address, never a physical
 * device count. A record exists when the MAC transmitted a frame (probe,
 * uplink data, client-initiated management) or was the unicast destination
 * of AP downlink traffic. Randomized MACs (locally administered bit)
 * produce separate records and are flagged, not deduplicated.
 */
typedef struct {
    bool used;
    uint8_t mac[6];

    uint64_t first_seen_ms;
    uint64_t last_tx_ms;       /* STA-transmitted frame (0 = never) */
    uint64_t last_observed_ms; /* any sighting, incl. downlink dest */

    /* Current observed AP relation (one per STA in this phase).
     * rel_ap is a 1-based AP slot index; 0 = unbound. */
    uint8_t rel_ap;
    uint8_t rel_evidence;      /* WORLD_EVIDENCE_* of the binding evidence */
    uint64_t rel_last_evidence_ms;

    int8_t rssi;               /* from STA-transmitted frames only */
    bool rssi_valid;
    uint8_t last_rx_channel;

    bool locally_administered; /* MAC local bit: often randomized */

    /* Saturating activity counters. */
    uint16_t probe_count;
    uint16_t tx_count;
    uint16_t dl_count;

    uint8_t flags;
} world_sta_t;

/* Counters (monotonic) + current occupancies. */
typedef struct {
    uint32_t ap_created;
    uint32_t ap_expired;
    uint32_t ap_evicted;
    uint32_t ap_rejected;   /* new AP refused (weak evidence, table full) */

    uint32_t sta_created;
    uint32_t sta_expired;
    uint32_t sta_evicted;
    uint32_t sta_rejected;  /* new STA refused (weak evidence, table full) */

    uint32_t rel_formed;
    uint32_t rel_expired;
    uint32_t rel_switched;
    uint32_t rel_conflicts;

    uint32_t data_ambiguous; /* ToDS=0/FromDS=0 data frames (skipped) */
    uint32_t data_wds;       /* 4-address data frames (skipped) */
    uint32_t data_short;     /* header not fully captured (skipped) */

    uint32_t obs_stale;     /* updates with now < last_seen (ignored) */
    uint32_t obs_invalid;   /* structurally invalid input (bad mac etc.) */

    uint32_t maint_runs;
} world_stats_t;

/* Small read-only snapshot for UI / serial stats. Copied under the caller's
 * lock; never holds interior pointers. */
typedef struct {
    uint16_t ap_current;
    uint16_t sta_current;
    uint16_t rel_current;
    world_stats_t stats;
} world_snapshot_t;

typedef struct {
    world_ap_t ap[WORLD_AP_MAX];
    world_sta_t sta[WORLD_STA_MAX];
    uint16_t ap_used;
    uint16_t sta_used;
    uint16_t rel_used;
    world_stats_t stats;
} world_t;

/* Read-only view types for bounded page exports. Interior data is copied
 * by value; SSID bytes are raw and must be sanitized at the output edge. */
typedef struct {
    bool valid;
    world_ap_t ap; /* full copy; the view owns no world memory */
} world_ap_view_t;

typedef struct {
    bool valid;
    world_sta_t sta;
} world_sta_view_t;

/* Reset to the empty world. No allocation anywhere in this component. */
void world_init(world_t *w);

/*
 * Time-driven housekeeping: expire AP/STA records past their TTL, expire
 * relations past the relation TTL (unbinding the STA, which itself stays
 * until its own TTL), and maintain station_count / *_current counters.
 * Cheap: O(WORLD_AP_MAX + WORLD_STA_MAX). Call periodically (target: at
 * least once per second, also under continuous traffic) and before any
 * snapshot that must reflect expiry.
 */
void world_maintenance(world_t *w, uint64_t now_ms);

/*
 * Beacon / probe response observation (transmitter = the AP itself).
 * `is_beacon` selects the activity counter. A beacon or probe response
 * clears the PROVISIONAL flag: the AP itself spoke with its BSSID in the
 * management header. Merge rules:
 * - activity: last_seen / last_rx_channel / beacon or probe_resp counter
 *   and transmitter RSSI refresh on EVERY observation, complete or not;
 * - SSID: only a COMPLETE observation with a non-hidden SSID may set or
 *   replace the name. Hidden/missing never clears a learned name.
 * - advertised_channel: any observation whose DS Parameter IE was fully
 *   parsed and valid (atomic 3-byte IE, usable even from a truncated
 *   capture); never cleared by absence.
 * - security: positive evidence (valid RSN/WPA parse) applies from any
 *   observation; OPEN / LEGACY_PRIVACY only from a COMPLETE observation
 *   without those IEs; malformed security IEs never overwrite known
 *   results. (Full suite parsing lands in Phase 2C.)
 * - observations with now_ms < last_seen_ms are stale: counted, ignored.
 * Invalid BSSID (zero or group bit set) counts obs_invalid.
 */
void world_on_ap_observation(world_t *w,
                             const ieee80211_ap_observation_t *obs,
                             uint64_t now_ms, bool is_beacon);

/*
 * Data frame. `addrs` comes from ieee80211_parse_data_addresses (fully
 * bounds-checked MAC header; the protected body is never parsed). The
 * DS-bit mapping (see docs/PHASE2_WORLD_MODEL.md):
 *
 *   ToDS=1 FromDS=0 : BSSID=addr1, STA=addr2 (transmitter). Relation
 *                     evidence UPLINK; frame RSSI belongs to the STA.
 *                     addr3 (DS-side destination) is NOT a wireless STA.
 *   ToDS=0 FromDS=1 : BSSID=addr2 (transmitter). Unicast addr1 is an STA
 *                     candidate with DOWNLINK evidence; frame RSSI belongs
 *                     to the AP. addr3 (DS-side source) is NOT a wireless
 *                     STA. Broadcast/multicast addr1 refreshes AP activity
 *                     only. addr1 == addr2 never becomes an STA (an AP is
 *                     not its own client).
 *   ToDS=0 FromDS=0 : counted (data_ambiguous), no infrastructure
 *                     inference (IBSS / direct link).
 *   ToDS=1 FromDS=1 : counted (data_wds), no ordinary inference.
 *
 * Data-inferred APs are created PROVISIONAL (no SSID/security invented)
 * and are weak creators: they never evict live entries when the table is
 * full (counted in ap_rejected instead). An uplink also creates the STA
 * record (strong creator); a pure downlink destination is a weak creator.
 */
void world_on_data_frame(world_t *w, const ieee80211_data_addrs_t *addrs,
                         uint64_t now_ms, uint8_t rx_channel, int8_t rssi);

/*
 * Probe request: discovers the source STA only (strong creator; the STA
 * transmitted). Never creates an AP and never establishes a relation:
 * wildcard or directed SSID alike carry no association evidence. The same
 * MAC probing repeatedly stays one record.
 */
void world_on_probe_request(world_t *w,
                            const ieee80211_probe_req_observation_t *obs,
                            uint64_t now_ms);

/*
 * STA-transmitted management frame whose SA is a client (auth /
 * (re)association request). Refreshes the STA record (tx evidence) only:
 * no AP creation, no relation effect. Deauth/disassoc/action frames are
 * deliberately NOT fed here (their SA may be the AP itself).
 */
void world_on_sta_mgmt_tx(world_t *w, const uint8_t mac[6],
                          uint64_t now_ms, uint8_t rx_channel, int8_t rssi);

/* Snapshot copy (current occupancies + counters). */
void world_snapshot(const world_t *w, world_snapshot_t *out);

/* Bounded page exports: copies entry `idx` by value. Returns false when
 * the slot is unused or idx is out of range. */
bool world_get_ap(const world_t *w, uint16_t idx, world_ap_view_t *out);
bool world_get_sta(const world_t *w, uint16_t idx, world_sta_view_t *out);

/*
 * Test helper: verify structural invariants after any sequence of calls.
 * Returns true when everything holds (CHECK-friendly):
 * - used counters match the number of used slots (AP and STA);
 * - every used AP's station_count equals the number of STAs bound to it;
 * - rel_used equals the number of bound STAs, and every binding points at
 *   a used AP slot with a sane evidence code.
 * (TTL freshness is NOT checked here: lazy expiry lets an unmaintained
 * stale binding exist legally until the next maintenance clears it.)
 */
bool world_check_invariants(const world_t *w);

/* Address helpers shared by the world and tests. */
bool world_mac_is_zero(const uint8_t mac[6]);
bool world_mac_is_unicast(const uint8_t mac[6]); /* nonzero + no group bit */
