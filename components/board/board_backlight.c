#include "board_backlight.h"

#include <stdbool.h>

#include "driver/ledc.h"
#include "esp_log.h"

#include "board_pins.h"

static const char *TAG = "board_backlight";
static bool s_initialized;

#define BOARD_BACKLIGHT_LEDC_MODE      LEDC_LOW_SPEED_MODE
#define BOARD_BACKLIGHT_LEDC_TIMER     LEDC_TIMER_3
#define BOARD_BACKLIGHT_LEDC_CHANNEL   LEDC_CHANNEL_1
#define BOARD_BACKLIGHT_PWM_HZ         (50 * 1000)
#define BOARD_BACKLIGHT_MAX_DUTY       255U

esp_err_t board_backlight_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    const ledc_timer_config_t timer_config = {
        .speed_mode = BOARD_BACKLIGHT_LEDC_MODE,
        .duty_resolution = LEDC_TIMER_8_BIT,
        .timer_num = BOARD_BACKLIGHT_LEDC_TIMER,
        .freq_hz = BOARD_BACKLIGHT_PWM_HZ,
        .clk_cfg = LEDC_AUTO_CLK,
    };

    esp_err_t err = ledc_timer_config(&timer_config);
    if (err != ESP_OK) {
        return err;
    }

    const ledc_channel_config_t channel_config = {
        .gpio_num = BOARD_PIN_LCD_BACKLIGHT,
        .speed_mode = BOARD_BACKLIGHT_LEDC_MODE,
        .channel = BOARD_BACKLIGHT_LEDC_CHANNEL,
        .intr_type = LEDC_INTR_DISABLE,
        .timer_sel = BOARD_BACKLIGHT_LEDC_TIMER,
        /* Inverted backlight: duty 0 is fully on, matching the factory
         * program turning the backlight on before anything else. */
        .duty = 0,
        .hpoint = 0,
    };

    err = ledc_channel_config(&channel_config);
    if (err != ESP_OK) {
        return err;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "backlight PWM ready on GPIO%d (inverted, duty 0 = full on)",
             BOARD_PIN_LCD_BACKLIGHT);
    return ESP_OK;
}

esp_err_t board_backlight_set_percent(uint8_t percent)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (percent > 100) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Waveshare drives this backlight with inverted PWM: duty 255 is off. */
    const uint32_t duty = BOARD_BACKLIGHT_MAX_DUTY -
                          ((uint32_t)percent * BOARD_BACKLIGHT_MAX_DUTY / 100U);

    esp_err_t err = ledc_set_duty(BOARD_BACKLIGHT_LEDC_MODE,
                                  BOARD_BACKLIGHT_LEDC_CHANNEL, duty);
    if (err != ESP_OK) {
        return err;
    }
    err = ledc_update_duty(BOARD_BACKLIGHT_LEDC_MODE,
                           BOARD_BACKLIGHT_LEDC_CHANNEL);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "brightness=%u%%", (unsigned)percent);
    }
    return err;
}
