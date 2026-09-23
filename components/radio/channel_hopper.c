#include "channel_hopper.h"

#include "hopper_policy.h"

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

/*
 * Channel list: built once from the driver's country table via
 * esp_wifi_get_country() (wifi_country_t.schan = first channel, nchan =
 * channel COUNT). IDF v5.4 defaults to {cc="01", schan=1, nchan=11}, so
 * the world-safe default is 1..11; a region table with 13 channels
 * yields 1..13. No code string mapping, no guessing, no set_country call.
 * A missing or invalid table falls back to the conservative 1..11.
 */
static uint8_t s_channels[HOPPER_MAX_CHANNELS];
static uint8_t s_channel_count;
static hopper_channel_health_t s_health[HOPPER_MAX_CHANNELS];

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
        s_health[i] = s_health[i + 1];
    }
    s_channel_count--;
}

static void build_channel_list(void)
{
    wifi_country_t country = {0};
    esp_err_t err = esp_wifi_get_country(&country);
    const bool table_ok = (err == ESP_OK) &&
                          hopper_build_list_from_country(country.schan,
                                                         country.nchan,
                                                         s_channels,
                                                         HOPPER_MAX_CHANNELS,
                                                         &s_channel_count);
    if (table_ok) {
        ESP_LOGI(TAG, "country %c%c channels %u..%u (%u entries)",
                 country.cc[0], country.cc[1],
                 (unsigned)country.schan,
                 (unsigned)(country.schan + country.nchan - 1),
                 (unsigned)s_channel_count);
        return;
    }

    /* Missing/invalid country info: conservative world-safe fallback. */
    hopper_build_fallback_list(s_channels, HOPPER_MAX_CHANNELS,
                               &s_channel_count);
    ESP_LOGW(TAG, "no usable country table (%s), fallback to channels "
             "%u..%u", esp_err_to_name(err),
             (unsigned)HOPPER_FALLBACK_FIRST,
             (unsigned)HOPPER_FALLBACK_LAST);
}

static void hopper_task(void *arg)
{
    (void)arg;

    while (!s_stop_requested && s_channel_count > 0) {
        for (uint8_t i = 0; i < s_channel_count && !s_stop_requested; i++) {
            const uint8_t ch = s_channels[i];
            const esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

            if (err == ESP_OK) {
                hopper_note_success(&s_health[i]);
                portENTER_CRITICAL(&s_hop_mux);
                /* Report the channel as effective only after a
                 * successful set_channel. */
                s_stats.current_channel = ch;
                s_stats.hop_count++;
                s_stats.last_hop_ms = (uint32_t)(esp_timer_get_time() / 1000);
                portEXIT_CRITICAL(&s_hop_mux);

                vTaskDelay(pdMS_TO_TICKS(s_stats.dwell_ms));
                continue;
            }

            const hopper_err_class_t cls = hopper_err_classify((int)err);
            const hopper_action_t action = hopper_note_failure(&s_health[i], cls);
            const uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);

            if (hopper_log_due(&s_health[i], now_ms)) {
                ESP_LOGW(TAG, "set_channel(%u) failed: %s (%s)", ch,
                         esp_err_to_name(err),
                         action == HOP_ACT_RETIRE ? "retiring" :
                         action == HOP_ACT_STOP ? "stopping" :
                         action == HOP_ACT_SKIP_PASS ? "skipping this pass" :
                         "retrying");
            }

            if (action == HOP_ACT_RETIRE) {
                portENTER_CRITICAL(&s_hop_mux);
                retire_channel_at(i);
                portEXIT_CRITICAL(&s_hop_mux);
                i--; /* the list shrank; re-examine this index */
            } else if (action == HOP_ACT_STOP) {
                s_stop_requested = true;
                break;
            }
            /* CONTINUE / SKIP_PASS: the channel stays in the list and is
             * retried on a later pass; time on channel still elapses. */

            vTaskDelay(pdMS_TO_TICKS(s_stats.dwell_ms));
        }
    }

    portENTER_CRITICAL(&s_hop_mux);
    s_stats.enabled = false;
    /* current_channel keeps the last known good channel (0 = never
     * hopped); it is deliberately not reset to the startup channel. */
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
    s_stats.dwell_ms = dwell_ms;
    /* enabled stays false until the task exists; current_channel stays 0
     * (unknown) until the first successful set_channel. */
    portEXIT_CRITICAL(&s_hop_mux);
    memset(s_health, 0, sizeof(s_health));

    s_stop_requested = false;
    if (xTaskCreate(hopper_task, "hopper", HOPPER_TASK_STACK,
                    NULL, HOPPER_TASK_PRIO, &s_task_handle) != pdPASS) {
        s_task_handle = NULL;
        portENTER_CRITICAL(&s_hop_mux);
        s_stats.enabled = false;
        portEXIT_CRITICAL(&s_hop_mux);
        return ESP_ERR_NO_MEM;
    }

    portENTER_CRITICAL(&s_hop_mux);
    s_stats.enabled = true;
    portEXIT_CRITICAL(&s_hop_mux);

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
