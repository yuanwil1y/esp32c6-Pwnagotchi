#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

esp_err_t board_touch_init(void);
bool board_touch_available(void);
esp_err_t board_touch_read(uint16_t *x, uint16_t *y, bool *pressed);
