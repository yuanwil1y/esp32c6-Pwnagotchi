#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "eapol_parser.h"
#include "radio_types.h"
#include "rx_path.h"

typedef bool (*wifi_capture_sink_fn)(const radio_packet_t *packet);
typedef bool (*wifi_capture_accepting_fn)(void);

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

/* Optional passive capture tap installed before init. The consumer task calls
 * it for a value-copy handoff; it must return promptly and never do I/O. */
void wifi_sniffer_set_capture_sink(wifi_capture_sink_fn sink,
                                   wifi_capture_accepting_fn accepting);

/* Start the radio and promiscuous RX on `channel` (1..14). */
esp_err_t wifi_sniffer_start(uint8_t channel);

/* Concurrency-safe counters snapshot for logging / UI. */
void wifi_sniffer_get_stats(radio_stats_t *out);

/* Fixed-size EAPOL counters and latest value-only observation snapshot. */
void wifi_sniffer_get_eapol_stats(eapol_stats_t *out);
