#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

esp_err_t board_i2c_init(void);
bool board_i2c_is_initialized(void);
esp_err_t board_i2c_write_reg(uint8_t address, uint8_t reg, const uint8_t *data, size_t len);
esp_err_t board_i2c_read_reg(uint8_t address, uint8_t reg, uint8_t *data, size_t len);
