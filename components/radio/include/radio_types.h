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

    uint8_t current_channel;
} radio_stats_t;
