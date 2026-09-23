#include "board_i2c.h"

#include <stdbool.h>

#include "driver/i2c.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

#include "board_pins.h"

static const char *TAG = "board_i2c";
static bool s_initialized;

esp_err_t board_i2c_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    const i2c_config_t config = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = BOARD_PIN_I2C_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = BOARD_PIN_I2C_SCL,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = BOARD_I2C_FREQ_HZ,
        .clk_flags = 0,
    };

    esp_err_t err = i2c_param_config(BOARD_I2C_PORT, &config);
    if (err != ESP_OK) {
        return err;
    }

    err = i2c_driver_install(BOARD_I2C_PORT, config.mode, 0, 0, 0);
    if (err != ESP_OK) {
        return err;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "I2C0 ready: SDA=%d SCL=%d @ %d Hz",
             BOARD_PIN_I2C_SDA, BOARD_PIN_I2C_SCL, BOARD_I2C_FREQ_HZ);
    return ESP_OK;
}

bool board_i2c_is_initialized(void)
{
    return s_initialized;
}

esp_err_t board_i2c_write_reg(uint8_t address, uint8_t reg, const uint8_t *data, size_t len)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if ((len > 0 && data == NULL) || len > 255) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t buffer[1 + 255];
    buffer[0] = reg;
    for (size_t i = 0; i < len; ++i) {
        buffer[i + 1] = data[i];
    }

    return i2c_master_write_to_device(BOARD_I2C_PORT, address, buffer, len + 1,
                                      pdMS_TO_TICKS(1000));
}

esp_err_t board_i2c_read_reg(uint8_t address, uint8_t reg, uint8_t *data, size_t len)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (data == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    return i2c_master_write_read_device(BOARD_I2C_PORT, address, &reg, 1, data, len,
                                        pdMS_TO_TICKS(1000));
}
