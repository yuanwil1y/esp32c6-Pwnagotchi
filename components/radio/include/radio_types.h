#pragma once

#include <stdint.h>

/*
 * Phase 1A radio constants.
 *
 * RADIO_PACKET_MAX_LEN: 802.11 management frames (beacon/probe) that matter
 * for later phases stay well below this size. Longer frames are stored
 * truncated and counted in rx_truncated. The bound also caps the static
 * packet pool memory: pool size * (RADIO_PACKET_MAX_LEN + header).
 */
#define RADIO_PACKET_MAX_LEN     512
#define RADIO_PACKET_POOL_SIZE   24
#define RADIO_DEFAULT_CHANNEL    6

/*
 * Snapshot of one captured frame as handed from the promiscuous RX callback
 * to the consumer task. `length` is the number of bytes actually stored in
 * data[] (<= orig_length); `orig_length` is the on-air frame length
 * including FCS as reported by the Wi-Fi driver.
 */
typedef struct {
    int8_t rssi;
    uint8_t channel;
    uint16_t length;
    uint16_t orig_length;
    uint8_t packet_type; /* wifi_promiscuous_pkt_type_t value */
    uint8_t data[RADIO_PACKET_MAX_LEN];
} radio_packet_t;

/* Concurrency-safe snapshot via wifi_sniffer_get_stats(). */
typedef struct {
    uint32_t rx_total;
    uint32_t rx_queued;
    uint32_t rx_processed;
    uint32_t rx_dropped;
    uint32_t rx_truncated;

    uint32_t rx_management;
    uint32_t rx_data;
    uint32_t rx_control;
    uint32_t rx_misc;

    uint32_t queue_current;
    uint32_t queue_peak;

    /* Phase 1B: classification from the raw 802.11 Frame Control, counted
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

    /* Phase 1C: beacon/probe observations. Fixed-size fields only. */
    uint32_t beacon_parsed;
    uint32_t beacon_parse_errors;
    uint32_t probe_req_parsed;
    uint32_t probe_req_errors;
    uint32_t probe_resp_parsed;
    uint32_t ie_total;
    uint32_t ie_malformed;
    uint32_t ssid_found;
    uint32_t hidden_ssid_count;
    uint32_t rsn_ie_count;
    uint32_t wpa_vendor_ie_count;
    uint32_t channel_ie_count;
    uint32_t ap_unique;

    /* Last AP observation, for the UI. 33 = 32 SSID bytes + NUL. */
    char last_ssid[33];
    uint8_t last_ssid_len;
    bool last_ssid_valid;
    uint8_t last_ap_channel;
    int8_t last_ap_rssi;

    uint8_t current_channel;
} radio_stats_t;
