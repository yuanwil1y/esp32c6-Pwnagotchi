#include "channel_hopper.h"

#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "HOP";

#define HOPPER_TASK_STACK      2048
#define HOPPER_TASK_PRIO       3
#define HOPPER_MAX_CHANNELS    14

/* Channel list: built once from the driver's country code. Unknown or
 * world-safe ("01") codes get the conservative 1..11 set; regions whose
 * regulatory table is known to include 12/13 get 1..13. Any channel the
 * driver rejects at runtime is retired from the list, so a wrong guess
 * can never wedge the hopper. */
static uint8_t s_channels[HOPPER_MAX_CHANNELS];
static uint8_t s_channel_count;

static portMUX_TYPE s_hop_mux = portMUX_INITIALIZER_UNLOCKED;
static channel_hopper_stats_t s_stats;

static TaskHandle_t s_task_handle;
static volatile bool s_stop_requested;

/* Requires the hop mux. */
static void retire_channel_at(uint8_t index)
{
    if (index >= s_channel_count) {
        return;
    }
    for (uint8_t i = index; i < (uint8_t)(s_channel_count - 1); i++) {
        s_channels[i] = s_channels[i + 1];
    }
    s_channel_count--;
}

static void build_channel_list(void)
{
    uint8_t last = 11; /* conservative default incl. world-safe "01" */

    char country[3] = {0};
    if (esp_wifi_get_country_code(country) == ESP_OK && country[0] != 0) {
        if ((country[0] == 'U' && country[1] == 'S') ||
            (country[0] == 'C' && country[1] == 'A')) {
            last = 11;
        } else {
            /* CN, JP, EU and most other regulatory domains allow 1..13
             * on 2.4 GHz; runtime retirement covers any mismatch. */
            last = 13;
        }
        ESP_LOGI(TAG, "country code %c%c -> channels 1..%d",
                 country[0], country[1], last);
    } else {
        ESP_LOGW(TAG, "no country code, defaulting to channels 1..%d", last);
    }

    s_channel_count = 0;
    for (uint8_t ch = 1; ch <= last && ch <= HOPPER_MAX_CHANNELS; ch++) {
        s_channels[s_channel_count++] = ch;
    }
}

static void hopper_task(void *arg)
{
    (void)arg;

    while (!s_stop_requested && s_channel_count > 0) {
        for (uint8_t i = 0; i < s_channel_count && !s_stop_requested; i++) {
            const uint8_t ch = s_channels[i];
            const esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

            if (err == ESP_OK) {
                portENTER_CRITICAL(&s_hop_mux);
                s_stats.current_channel = ch;
                s_stats.hop_count++;
                s_stats.last_hop_ms = (uint32_t)(esp_timer_get_time() / 1000);
                portEXIT_CRITICAL(&s_hop_mux);
            } else {
                portENTER_CRITICAL(&s_hop_mux);
                s_stats.hop_errors++;
                portEXIT_CRITICAL(&s_hop_mux);
                ESP_LOGW(TAG, "set_channel(%u) failed: %s, retiring it",
                         ch, esp_err_to_name(err));
                portENTER_CRITICAL(&s_hop_mux);
                retire_channel_at(i);
                portEXIT_CRITICAL(&s_hop_mux);
                i--; /* the list shrank; re-examine this index */
            }

            vTaskDelay(pdMS_TO_TICKS(s_stats.dwell_ms));
        }
    }

    portENTER_CRITICAL(&s_hop_mux);
    s_stats.enabled = false;
    portEXIT_CRITICAL(&s_hop_mux);

    ESP_LOGI(TAG, "hopper task exiting");
    s_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t channel_hopper_start(uint32_t dwell_ms)
{
    if (s_task_handle != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (dwell_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    build_channel_list();
    if (s_channel_count == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    portENTER_CRITICAL(&s_hop_mux);
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.enabled = true;
    s_stats.dwell_ms = dwell_ms;
    s_stats.current_channel = s_channels[0];
    portEXIT_CRITICAL(&s_hop_mux);

    s_stop_requested = false;
    if (xTaskCreate(hopper_task, "hopper", HOPPER_TASK_STACK,
                    NULL, HOPPER_TASK_PRIO, &s_task_handle) != pdPASS) {
        s_task_handle = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "hopping %u channels, dwell=%" PRIu32 " ms",
             s_channel_count, dwell_ms);
    return ESP_OK;
}

void channel_hopper_stop(void)
{
    if (s_task_handle == NULL) {
        return;
    }
    s_stop_requested = true;
    /* The task deletes itself after at most one dwell period. */
}

uint8_t channel_hopper_get_current_channel(void)
{
    portENTER_CRITICAL(&s_hop_mux);
    const uint8_t ch = s_stats.current_channel;
    portEXIT_CRITICAL(&s_hop_mux);
    return ch;
}

void channel_hopper_get_stats(channel_hopper_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    portENTER_CRITICAL(&s_hop_mux);
    *out = s_stats;
    portEXIT_CRITICAL(&s_hop_mux);
}
