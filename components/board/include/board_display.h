#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define BOARD_DISPLAY_WAIT_FOREVER UINT32_MAX

esp_err_t board_display_init(void);
esp_err_t board_display_show_phase0_status(bool touch_ok, bool sd_ok);
bool board_display_lock(uint32_t timeout_ms);
void board_display_unlock(void);
