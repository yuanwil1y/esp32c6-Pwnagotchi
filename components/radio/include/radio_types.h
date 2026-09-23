#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "rx_path.h"

/*
 * Phase 1A radio constants (packet pool constants and radio_packet_t live
 * in rx_path.h; both are part of the RX path).
 */
#define RADIO_DEFAULT_CHANNEL    6

/*
 * Concurrency-safe snapshot via wifi_sniffer_get_stats().
 *
 * Phase 1.5 counter semantics:
 * - `rx` holds the RX front-end counters, including consumer-queue
 *   occupancy (rx.queue_current / rx.queue_peak); see rx_path.h for the
 *   accounting identity.
 * - `ap_cache_*` are cache-change bookkeeping for the 32-slot dedup
 *   cache: inserts/updates/evictions count changes, `ap_cache_occupied`
 *   is the current slot usage (0..32). They are NOT "total unique APs"
 *   and not a TTL-based online count.
 * - `ap_obs_skipped` counts observations that were not merged because
 *   they were incomplete/malformed (diagnostic).
 */
typedef struct {
    rx_path_stats_t rx; /* RX front-end (callback + queue) counters */

    /* Channel hopper (merged into the snapshot). */
    uint32_t hop_count;
    uint32_t hop_errors;
    uint32_t dwell_ms;

    /* Classification from the raw 802.11 Frame Control, counted
     * independently of the driver packet type counters above. */
    uint32_t parser_total;
    uint32_t parser_errors;
    uint32_t invalid_frames;
    uint32_t fc_type_mismatch; /* driver type vs Frame Control type */

    uint32_t mgmt_total;
    uint32_t ctrl_total;
    uint32_t data_total;
    uint32_t ext_total;

    uint32_t beacon_count;
    uint32_t probe_req_count;
    uint32_t probe_resp_count;
    uint32_t auth_count;
    uint32_t assoc_req_count;
    uint32_t assoc_resp_count;
    uint32_t reassoc_req_count;
    uint32_t reassoc_resp_count;
    uint32_t atim_count;
    uint32_t disassoc_count;
    uint32_t deauth_count;
    uint32_t action_count;
    uint32_t mgmt_other_count;

    uint32_t rts_count;
    uint32_t cts_count;
    uint32_t ack_count;
    uint32_t bar_count;
    uint32_t ba_count;
    uint32_t ctrl_other_count;

    uint32_t fc_data_count;
    uint32_t null_count;
    uint32_t qos_data_count;
    uint32_t qos_null_count;
    uint32_t data_other_count;

    /* Beacon/probe observations. Fixed-size fields only. */
    uint32_t beacon_parsed;
    uint32_t beacon_parse_errors;
    uint32_t probe_req_parsed;
    uint32_t probe_req_errors;
    uint32_t probe_resp_parsed;
    uint32_t ie_total;
    uint32_t ie_malformed;
    uint32_t ie_incomplete;
    uint32_t ssid_found;
    uint32_t hidden_ssid_count;
    uint32_t rsn_ie_count;
    uint32_t wpa_vendor_ie_count;
    uint32_t channel_ie_count;

    /* AP dedup cache bookkeeping (0..32 slots), NOT a unique-AP counter. */
    uint32_t ap_cache_inserts;
    uint32_t ap_cache_updates;
    uint32_t ap_cache_evictions;
    uint8_t ap_cache_occupied;
    uint32_t ap_obs_skipped;

    /* Last AP observation, for the UI. 33 = 32 SSID bytes + NUL. */
    char last_ssid[33];
    uint8_t last_ssid_len;
    bool last_ssid_valid;
    uint8_t last_ap_channel;
    int8_t last_ap_rssi;

    /* Last known successful channel: the startup channel until the hopper
     * reports its own, then the hopper's last good channel (also kept
     * after the hopper stops). 0 would mean unknown. */
    uint8_t current_channel;
} radio_stats_t;
