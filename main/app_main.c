#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "board_backlight.h"
#include "board_display.h"
#include "board_i2c.h"
#include "board_sd.h"
#include "board_touch.h"
#include "ieee80211_parser.h"
#include "radio_types.h"
#include "wifi_sniffer.h"

#if __has_include("build_info.h")
#include "build_info.h"
#else
#define APP_BUILD_GIT_SHA  "unknown"
#define APP_BUILD_GIT_SHORT "unknown"
#endif

static const char *TAG = "phase1c";

#define PHASE1C_UI_TASK_STACK   4096
#define PHASE1C_UI_TASK_PRIO    3
#define PHASE1C_UI_PERIOD_MS    500 /* 2 Hz, inside the 2-5 Hz budget */
#define PHASE1C_SSID_DISPLAY_MAX 16

/* Refreshes the Phase 1C status lines from a stats snapshot. Never touches
 * the Wi-Fi driver; the promiscuous callback stays free of LVGL work. */
static void phase1c_ui_task(void *arg)
{
    (void)arg;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(PHASE1C_UI_PERIOD_MS));

        radio_stats_t stats;
        wifi_sniffer_get_stats(&stats);

        char ssid_disp[PHASE1C_SSID_DISPLAY_MAX + 1];
        const char *last_ssid = NULL;
        if (stats.last_ssid_valid) {
            if (stats.last_ssid_len == 0) {
                strlcpy(ssid_disp, "<hidden>", sizeof(ssid_disp));
            } else {
                ieee80211_ssid_to_printable(stats.last_ssid, stats.last_ssid_len,
                                            ssid_disp, sizeof(ssid_disp));
            }
            last_ssid = ssid_disp;
        }

        (void)board_display_update_phase1c(stats.rx_total,
                                           stats.ap_unique,
                                           stats.ie_malformed + stats.beacon_parse_errors,
                                           last_ssid,
                                           stats.last_ap_channel,
                                           stats.last_ap_rssi);
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "esp32c6-Pwnagotchi Phase 1C beacon/probe IE parser");
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

    esp_err_t wifi_result = wifi_sniffer_init();
    if (wifi_result == ESP_OK) {
        wifi_result = wifi_sniffer_start(RADIO_DEFAULT_CHANNEL);
    }
    if (wifi_result != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi sniffer bring-up failed: %s", esp_err_to_name(wifi_result));
    }

    ESP_ERROR_CHECK(board_display_show_phase1c_status(touch_result == ESP_OK,
                                                      sd_result == ESP_OK,
                                                      wifi_result == ESP_OK));
    ESP_ERROR_CHECK(board_backlight_set_percent(80));

    if (wifi_result == ESP_OK &&
        xTaskCreate(phase1c_ui_task, "phase1c_ui", PHASE1C_UI_TASK_STACK,
                    NULL, PHASE1C_UI_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "phase1c_ui task creation failed");
    }

    ESP_LOGI(TAG, "Phase 1C ready: LCD=OK I2C=%s Touch=%s SD=%s WiFi=%s",
             i2c_result == ESP_OK ? "OK" : "FAIL",
             touch_result == ESP_OK ? "OK" : "FAIL",
             sd_result == ESP_OK ? "OK" : "FAIL",
             wifi_result == ESP_OK ? "SNIFFING" : "FAIL");
}
