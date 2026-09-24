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
#include "channel_hopper.h"
#include "radio_types.h"
#include "sd_logger.h"
#include "wifi_sniffer.h"

#if __has_include("build_info.h")
#include "build_info.h"
#else
#define APP_BUILD_GIT_SHA  "unknown"
#define APP_BUILD_GIT_SHORT "unknown"
#endif

static const char *TAG = "phase3c";

#define PHASE1_UI_TASK_STACK    4096
#define PHASE1_UI_TASK_PRIO     3
#define PHASE1_UI_PERIOD_MS     500 /* 2 Hz, inside the 2-5 Hz budget */
#define PHASE1_HOPPER_DWELL_MS  300
#define PHASE3C_CONSOLE_STARTUP_STACK 12288u
#define PHASE3C_CONSOLE_STARTUP_PRIO  1u

/* esp_console/linenoise initialization has a deeper stack than app_main's
 * normal board/Wi-Fi bring-up. Keep this temporary setup call off main's
 * bounded startup stack, then release the task stack once the REPL is live. */
static void phase3c_console_startup_task(void *arg)
{
    (void)arg;
    const esp_err_t result = sd_logger_console_start();
    if (result != ESP_OK) {
        ESP_LOGW(TAG, "capture UART commands unavailable: %s",
                 esp_err_to_name(result));
    }
    ESP_LOGI(TAG, "console_startup_stack_hwm=%u",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));
    vTaskDelete(NULL);
}

/* Refreshes the status screen from value snapshots. Never touches the Wi-Fi
 * driver; the promiscuous callback stays free of LVGL and storage work. */
static void phase1_ui_task(void *arg)
{
    (void)arg;
    uint8_t report_counter = 0;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(PHASE1_UI_PERIOD_MS));

        radio_stats_t stats;
        wifi_sniffer_get_stats(&stats);
        sd_logger_stats_t storage;
        sd_logger_get_stats(&storage);
        const uint32_t storage_written = storage.written > UINT32_MAX
                                             ? UINT32_MAX
                                             : (uint32_t)storage.written;
        const uint32_t storage_drop = storage.storage_drop > UINT32_MAX
                                          ? UINT32_MAX
                                          : (uint32_t)storage.storage_drop;
        /* Phase 2: the status screen shows the World Model's TTL-aged
         * current counts (AP records, observed station addresses, valid
         * relations), replacing the Phase 1.5 log-cache occupancy. */
        (void)board_display_update_phase1(stats.current_channel,
                                          stats.ap_db_current,
                                          stats.sta_db_current,
                                          stats.rel_db_current,
                                          stats.rx.rx_total,
                                          stats.rx.rx_dropped_pool +
                                          stats.rx.rx_dropped_queue,
                                          sd_logger_state_short_name(storage.state),
                                          storage_written,
                                          storage_drop);
        if (++report_counter >= 6u) {
            ESP_LOGI(TAG, "ui_stack_hwm=%u",
                     (unsigned)uxTaskGetStackHighWaterMark(NULL));
            report_counter = 0;
        }
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "esp32c6-Pwnagotchi Phase 3C SD capture logger");
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

    esp_err_t logger_result = sd_logger_init(APP_BUILD_GIT_SHA,
                                             sd_result == ESP_OK);
    if (logger_result == ESP_OK) {
        wifi_sniffer_set_capture_sink(sd_logger_try_submit,
                                      sd_logger_is_accepting);
        if (xTaskCreate(phase3c_console_startup_task, "sd_console_init",
                        PHASE3C_CONSOLE_STARTUP_STACK, NULL,
                        PHASE3C_CONSOLE_STARTUP_PRIO, NULL) != pdPASS) {
            ESP_LOGW(TAG, "capture console startup task creation failed");
        }
    } else {
        ESP_LOGE(TAG, "SD logger task unavailable: %s",
                 esp_err_to_name(logger_result));
    }

    esp_err_t wifi_result = wifi_sniffer_init();
    if (wifi_result == ESP_OK) {
        wifi_result = wifi_sniffer_start(RADIO_DEFAULT_CHANNEL);
    }
    if (wifi_result != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi sniffer bring-up failed: %s", esp_err_to_name(wifi_result));
    }

    /* Requires a started driver; hop failures are contained inside the
     * hopper (retire channel, count error), never fatal. */
    esp_err_t hop_result = ESP_ERR_INVALID_STATE;
    if (wifi_result == ESP_OK) {
        hop_result = channel_hopper_start(PHASE1_HOPPER_DWELL_MS);
        if (hop_result != ESP_OK) {
            ESP_LOGE(TAG, "channel hopper start failed: %s", esp_err_to_name(hop_result));
        }
    }

    ESP_ERROR_CHECK(board_display_show_phase1_status(touch_result == ESP_OK,
                                                     sd_result == ESP_OK,
                                                     wifi_result == ESP_OK));
    ESP_ERROR_CHECK(board_backlight_set_percent(80));

    if (wifi_result == ESP_OK &&
        xTaskCreate(phase1_ui_task, "phase1_ui", PHASE1_UI_TASK_STACK,
                    NULL, PHASE1_UI_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "phase1_ui task creation failed");
    }

    ESP_LOGI(TAG, "Phase 3C ready: LCD=OK I2C=%s Touch=%s SD=%s WiFi=%s HOP=%s",
             i2c_result == ESP_OK ? "OK" : "FAIL",
             touch_result == ESP_OK ? "OK" : "FAIL",
             sd_result == ESP_OK ? "OK" : "FAIL",
             wifi_result == ESP_OK ? "SNIFFING" : "FAIL",
             hop_result == ESP_OK ? "ON" : "OFF");
}
