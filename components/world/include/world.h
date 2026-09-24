#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ieee80211_parser.h"

/*
 * Phase 2 World Model: host-testable AP database with TTL ageing and
 * deterministic eviction (STA database and AP<->STA relations follow in
 * Phase 2B).
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
 * - Transmitter RSSI belongs to the transmitter: STA uplink RSSI will never
 *   be written into the AP record (Phase 2B) and AP downlink RSSI will
 *   never be written into the STA record.
 */

/* Named configuration constants (starting points, not verified hardware
 * conclusions; see docs/PHASE2_WORLD_MODEL.md for the sizing report). */
#define WORLD_AP_MAX            64
#define WORLD_AP_TTL_MS         120000u  /* AP observation expiry */

/* AP record flags. */
#define WORLD_AP_F_PROVISIONAL  0x01u  /* inferred from data, no beacon (2B) */

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
    uint16_t data_down_count;  /* AP-transmitted data frames (2B) */
    uint16_t data_up_count;    /* STA frames relayed through this AP (2B) */

    uint16_t station_count;    /* bound relations invariant (Phase 2B) */

    uint8_t flags;
} world_ap_t;

/* Security knowledge state for one AP. */
typedef enum {
    WORLD_SEC_UNKNOWN = 0,     /* nothing reliable seen yet */
    WORLD_SEC_KNOWN,           /* >=1 valid RSN/WPA parse (suites in sec) */
    WORLD_SEC_LEGACY_PRIVACY,  /* complete obs: privacy bit, no RSN/WPA IE */
    WORLD_SEC_OPEN,            /* complete obs: privacy=0, no RSN/WPA IE */
} world_sec_state_t;

/* Counters (monotonic) + current occupancies. */
typedef struct {
    uint32_t ap_created;
    uint32_t ap_expired;
    uint32_t ap_evicted;
    uint32_t ap_rejected;   /* new AP refused (weak evidence, table full) */

    uint32_t obs_stale;     /* updates with now < last_seen (ignored) */
    uint32_t obs_invalid;   /* structurally invalid input (bad mac etc.) */

    uint32_t maint_runs;
} world_stats_t;

/* Small read-only snapshot for UI / serial stats. Copied under the caller's
 * lock; never holds interior pointers. */
typedef struct {
    uint16_t ap_current;
    world_stats_t stats;
} world_snapshot_t;

typedef struct {
    world_ap_t ap[WORLD_AP_MAX];
    uint16_t ap_used;
    world_stats_t stats;
} world_t;

/* Read-only view type for bounded page exports. Interior data is copied
 * by value; SSID bytes are raw and must be sanitized at the output edge. */
typedef struct {
    bool valid;
    world_ap_t ap; /* full copy; the view owns no world memory */
} world_ap_view_t;

/* Reset to the empty world. No allocation anywhere in this component. */
void world_init(world_t *w);

/*
 * Time-driven housekeeping: expire AP records past their TTL and maintain
 * ap_used / ap_current. Cheap: O(WORLD_AP_MAX). Call periodically (target:
 * at least once per second, also under continuous traffic) and before any
 * snapshot that must reflect expiry.
 */
void world_maintenance(world_t *w, uint64_t now_ms);

/*
 * Beacon / probe response observation (transmitter = the AP itself).
 * `is_beacon` selects the activity counter. Merge rules:
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

/* Snapshot copy (current occupancy + counters). */
void world_snapshot(const world_t *w, world_snapshot_t *out);

/* Bounded page export: copies entry `idx` (0..WORLD_AP_MAX-1) by value.
 * Returns false when the slot is unused or idx is out of range. */
bool world_get_ap(const world_t *w, uint16_t idx, world_ap_view_t *out);

/*
 * Test helper: verify structural invariants after any sequence of calls.
 * Returns true when everything holds (CHECK-friendly):
 * - ap_used equals the number of used slots;
 * - no used slot has an invalid BSSID;
 * - station_count is zero (no relations before Phase 2B).
 */
bool world_check_invariants(const world_t *w);

/* Address helpers shared by the world and tests. */
bool world_mac_is_zero(const uint8_t mac[6]);
bool world_mac_is_unicast(const uint8_t mac[6]); /* nonzero + no group bit */
