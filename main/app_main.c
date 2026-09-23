#include <stdbool.h>

#include "esp_err.h"
#include "esp_log.h"

#include "board_backlight.h"
#include "board_display.h"
#include "board_i2c.h"
#include "board_sd.h"
#include "board_touch.h"

#if __has_include("build_info.h")
#include "build_info.h"
#else
#define APP_BUILD_GIT_SHA  "unknown"
#define APP_BUILD_GIT_SHORT "unknown"
#endif

static const char *TAG = "phase0";

void app_main(void)
{
    ESP_LOGI(TAG, "esp32c6-Pwnagotchi Phase 0 board bring-up");
    ESP_LOGI(TAG, "firmware git commit: %s (%s)", APP_BUILD_GIT_SHA, APP_BUILD_GIT_SHORT);

    ESP_ERROR_CHECK(board_backlight_init());

    const esp_err_t i2c_result = board_i2c_init();
    if (i2c_result != ESP_OK) {
        ESP_LOGE(TAG, "I2C init failed: %s", esp_err_to_name(i2c_result));
    }

    esp_err_t touch_result = ESP_ERR_INVALID_STATE;
    if (i2c_result == ESP_OK) {
        touch_result = board_touch_init();
        if (touch_result != ESP_OK) {
            ESP_LOGW(TAG, "Touch init failed: %s", esp_err_to_name(touch_result));
        }
    }

    ESP_ERROR_CHECK(board_display_init());

    esp_err_t sd_result = board_sd_init();
    if (sd_result == ESP_OK) {
        sd_result = board_sd_self_test();
    }
    if (sd_result != ESP_OK) {
        ESP_LOGW(TAG, "SD bring-up failed: %s", esp_err_to_name(sd_result));
    }

    ESP_ERROR_CHECK(board_display_show_phase0_status(touch_result == ESP_OK,
                                                     sd_result == ESP_OK));
    ESP_ERROR_CHECK(board_backlight_set_percent(80));

    ESP_LOGI(TAG, "Phase 0 ready: LCD=OK I2C=%s Touch=%s SD=%s",
             i2c_result == ESP_OK ? "OK" : "FAIL",
             touch_result == ESP_OK ? "OK" : "FAIL",
             sd_result == ESP_OK ? "OK" : "FAIL");
}
