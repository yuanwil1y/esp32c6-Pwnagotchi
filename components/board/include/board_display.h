#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define BOARD_DISPLAY_WAIT_FOREVER UINT32_MAX

esp_err_t board_display_init(void);
esp_err_t board_display_show_phase0_status(bool touch_ok, bool sd_ok);

/* Phase 1A status screen (Phase 0 lines plus RX/DROP/Wi-Fi sniff state). */
esp_err_t board_display_show_phase1a_status(bool touch_ok, bool sd_ok, bool wifi_ok);
esp_err_t board_display_update_phase1a(uint32_t rx_total, uint32_t rx_dropped);

/* Phase 1B status screen: adds Frame Control classification counters. */
esp_err_t board_display_show_phase1b_status(bool touch_ok, bool sd_ok, bool wifi_ok);
esp_err_t board_display_update_phase1b(uint32_t rx_total, uint32_t mgmt, uint32_t data,
                                       uint32_t ctrl, uint32_t errors);

/* Phase 1C status screen: adds AP observation summary. last_ssid must be
 * pre-sanitized for display (printable, bounded); NULL shows a placeholder. */
esp_err_t board_display_show_phase1c_status(bool touch_ok, bool sd_ok, bool wifi_ok);
esp_err_t board_display_update_phase1c(uint32_t rx_total, uint32_t ap_unique,
                                       uint32_t ie_errors, const char *last_ssid,
                                       uint8_t channel, int8_t rssi);

/* Phase 1 final status screen: channel (hopper), AP cache occupancy
 * (0..32 dedup slots; NOT a total-unique-AP count), RX and drop. */
esp_err_t board_display_show_phase1_status(bool touch_ok, bool sd_ok, bool wifi_ok);
esp_err_t board_display_update_phase1(uint8_t channel, uint32_t ap_cache_occupied,
                                      uint32_t rx_total, uint32_t rx_dropped);

bool board_display_lock(uint32_t timeout_ms);
void board_display_unlock(void);
