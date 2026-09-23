#include "board_touch.h"

#include <stdbool.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "board_i2c.h"
#include "board_pins.h"

static const char *TAG = "board_touch";
static bool s_available;

esp_err_t board_touch_init(void)
{
    if (!board_i2c_is_initialized()) {
        return ESP_ERR_INVALID_STATE;
    }

    const uint8_t normal_mode = 0x00;
    esp_err_t last_error = ESP_FAIL;

    for (int attempt = 0; attempt < 10; ++attempt) {
        last_error = board_i2c_write_reg(BOARD_TOUCH_I2C_ADDRESS, 0x00, &normal_mode, 1);
        if (last_error == ESP_OK) {
            s_available = true;
            ESP_LOGI(TAG, "CST78x touch ready at I2C address 0x%02X", BOARD_TOUCH_I2C_ADDRESS);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    s_available = false;
    return last_error;
}

bool board_touch_available(void)
{
    return s_available;
}

esp_err_t board_touch_read(uint16_t *x, uint16_t *y, bool *pressed)
{
    if (x == NULL || y == NULL || pressed == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_available) {
        *pressed = false;
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t touch_data[7] = {0};
    const esp_err_t err = board_i2c_read_reg(BOARD_TOUCH_I2C_ADDRESS, 0x00,
                                             touch_data, sizeof(touch_data));
    if (err != ESP_OK) {
        *pressed = false;
        return err;
    }

    *pressed = touch_data[2] != 0;
    if (!*pressed) {
        return ESP_OK;
    }

    *x = ((uint16_t)(touch_data[3] & 0x0f) << 8) | touch_data[4];
    *y = ((uint16_t)(touch_data[5] & 0x0f) << 8) | touch_data[6];

    static TickType_t last_log_tick;
    static uint16_t last_x = UINT16_MAX;
    static uint16_t last_y = UINT16_MAX;
    const TickType_t now = xTaskGetTickCount();
    if (*x != last_x || *y != last_y || (now - last_log_tick) >= pdMS_TO_TICKS(100)) {
        ESP_LOGI(TAG, "touch x=%u y=%u", (unsigned)*x, (unsigned)*y);
        last_x = *x;
        last_y = *y;
        last_log_tick = now;
    }

    return ESP_OK;
}
