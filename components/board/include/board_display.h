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

bool board_display_lock(uint32_t timeout_ms);
void board_display_unlock(void);
