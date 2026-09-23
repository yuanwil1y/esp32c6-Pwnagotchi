#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "radio_types.h"

/*
 * Phase 1A Wi-Fi promiscuous RX front end.
 *
 * wifi_sniffer_init() brings up NVS / esp-netif / event loop / Wi-Fi driver
 * and the bounded RX path (static packet pool + queues + consumer task).
 * wifi_sniffer_start() enables promiscuous mode on a fixed channel.
 * No station connection, no TX, no protocol parsing in this phase.
 */

/* One-shot init: safe to call before board UI is up. */
esp_err_t wifi_sniffer_init(void);

/* Start the radio and promiscuous RX on `channel` (1..14). */
esp_err_t wifi_sniffer_start(uint8_t channel);

/* Concurrency-safe counters snapshot for logging / UI. */
void wifi_sniffer_get_stats(radio_stats_t *out);
