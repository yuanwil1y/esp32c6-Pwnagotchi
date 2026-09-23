#include "wifi_sniffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char *TAG = "RADIO";

#define RADIO_RX_TASK_STACK       2048
#define RADIO_RX_TASK_PRIO        5
#define RADIO_STATS_TASK_STACK    3072
#define RADIO_STATS_TASK_PRIO     2
#define RADIO_STATS_PERIOD_MS     3000

/* Fixed packet pool: no dynamic memory in the RX path. */
static radio_packet_t s_packet_pool[RADIO_PACKET_POOL_SIZE];
static QueueHandle_t s_free_queue; /* radio_packet_t* available for the callback */
static QueueHandle_t s_rx_queue;   /* radio_packet_t* filled by the callback */

static portMUX_TYPE s_stats_mux = portMUX_INITIALIZER_UNLOCKED;
static radio_stats_t s_stats;
static uint8_t s_current_channel;
static bool s_initialized;

/*
 * Promiscuous RX callback. Runs in the Wi-Fi driver task context: only read
 * driver metadata, copy at most RADIO_PACKET_MAX_LEN bytes into a pooled
 * buffer, and hand it to the consumer queue. Never blocks, never logs, never
 * allocates. Drops (with counter) when the bounded queue is full.
 */
static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    portENTER_CRITICAL(&s_stats_mux);
    s_stats.rx_total++;
    portEXIT_CRITICAL(&s_stats_mux);

    radio_packet_t *slot = NULL;
    if (xQueueReceive(s_free_queue, &slot, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_stats_mux);
        s_stats.rx_dropped++;
        portEXIT_CRITICAL(&s_stats_mux);
        return;
    }

    /* rx_ctrl.sig_len is a 12-bit field including FCS, so at most 4095. */
    const uint16_t orig_len = (uint16_t)pkt->rx_ctrl.sig_len;
    const uint16_t copy_len = orig_len > RADIO_PACKET_MAX_LEN
                                  ? RADIO_PACKET_MAX_LEN
                                  : orig_len;

    slot->rssi = (int8_t)pkt->rx_ctrl.rssi;
    slot->channel = (uint8_t)pkt->rx_ctrl.channel;
    slot->orig_length = orig_len;
    slot->length = copy_len;
    slot->packet_type = (uint8_t)type;
    memcpy(slot->data, pkt->payload, copy_len);

    if (xQueueSend(s_rx_queue, &slot, 0) != pdTRUE) {
        (void)xQueueSend(s_free_queue, &slot, 0);
        portENTER_CRITICAL(&s_stats_mux);
        s_stats.rx_dropped++;
        portEXIT_CRITICAL(&s_stats_mux);
        return;
    }

    portENTER_CRITICAL(&s_stats_mux);
    s_stats.rx_queued++;
    if (orig_len > RADIO_PACKET_MAX_LEN) {
        s_stats.rx_truncated++;
    }
    s_stats.queue_current++;
    if (s_stats.queue_current > s_stats.queue_peak) {
        s_stats.queue_peak = s_stats.queue_current;
    }
    portEXIT_CRITICAL(&s_stats_mux);
}

/*
 * Consumer task. Phase 1A does no 802.11 parsing: it only counts frames by
 * the type the driver already classified and recycles the buffer.
 */
static void radio_rx_task(void *arg)
{
    (void)arg;

    while (true) {
        radio_packet_t *pkt = NULL;
        if (xQueueReceive(s_rx_queue, &pkt, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        portENTER_CRITICAL(&s_stats_mux);
        switch ((wifi_promiscuous_pkt_type_t)pkt->packet_type) {
        case WIFI_PKT_MGMT:
            s_stats.rx_management++;
            break;
        case WIFI_PKT_CTRL:
            s_stats.rx_control++;
            break;
        case WIFI_PKT_DATA:
            s_stats.rx_data++;
            break;
        default:
            s_stats.rx_misc++;
            break;
        }
        s_stats.rx_processed++;
        s_stats.queue_current--;
        portEXIT_CRITICAL(&s_stats_mux);

        (void)xQueueSend(s_free_queue, &pkt, 0);
    }
}

static void radio_stats_task(void *arg)
{
    (void)arg;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(RADIO_STATS_PERIOD_MS));

        radio_stats_t stats;
        wifi_sniffer_get_stats(&stats);

        ESP_LOGI(TAG,
                 "rx=%" PRIu32 " queued=%" PRIu32 " processed=%" PRIu32
                 " drop=%" PRIu32 " trunc=%" PRIu32
                 " mgmt=%" PRIu32 " data=%" PRIu32 " ctrl=%" PRIu32
                 " misc=%" PRIu32 " q=%" PRIu32 "/%" PRIu32
                 " heap=%" PRIu32 " min_heap=%" PRIu32,
                 stats.rx_total, stats.rx_queued, stats.rx_processed,
                 stats.rx_dropped, stats.rx_truncated,
                 stats.rx_management, stats.rx_data, stats.rx_control,
                 stats.rx_misc, stats.queue_current, stats.queue_peak,
                 esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
    }
}

void wifi_sniffer_get_stats(radio_stats_t *out)
{
    if (out == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_stats_mux);
    *out = s_stats;
    portEXIT_CRITICAL(&s_stats_mux);

    if (s_rx_queue != NULL) {
        out->queue_current = uxQueueMessagesWaiting(s_rx_queue);
    }
    out->current_channel = s_current_channel;
}

esp_err_t wifi_sniffer_init(void)
{
    if (s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        err = nvs_flash_erase();
        if (err == ESP_OK) {
            err = nvs_flash_init();
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_flash_init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_netif_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_init failed: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_event_loop_create_default failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Static storage: the default config struct is too large for the
     * app_main task stack. */
    static wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_init failed: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_storage failed: %s", esp_err_to_name(err));
        return err;
    }
    /* STA mode without connecting gives the promiscuous RX path a station
     * control block while keeping the radio fully passive. */
    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_mode failed: %s", esp_err_to_name(err));
        return err;
    }

    s_free_queue = xQueueCreate(RADIO_PACKET_POOL_SIZE, sizeof(radio_packet_t *));
    s_rx_queue = xQueueCreate(RADIO_PACKET_POOL_SIZE, sizeof(radio_packet_t *));
    if (s_free_queue == NULL || s_rx_queue == NULL) {
        ESP_LOGE(TAG, "queue creation failed");
        return ESP_ERR_NO_MEM;
    }

    memset(&s_stats, 0, sizeof(s_stats));
    for (size_t i = 0; i < RADIO_PACKET_POOL_SIZE; i++) {
        radio_packet_t *slot = &s_packet_pool[i];
        (void)xQueueSend(s_free_queue, &slot, 0);
    }

    if (xTaskCreate(radio_rx_task, "radio_rx", RADIO_RX_TASK_STACK,
                    NULL, RADIO_RX_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "radio_rx task creation failed");
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(radio_stats_task, "radio_stat", RADIO_STATS_TASK_STACK,
                    NULL, RADIO_STATS_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "radio_stat task creation failed");
        return ESP_ERR_NO_MEM;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "wifi driver ready (pool=%d pkts x %d B, queues=%d)",
             RADIO_PACKET_POOL_SIZE, (int)sizeof(radio_packet_t),
             RADIO_PACKET_POOL_SIZE);
    return ESP_OK;
}

esp_err_t wifi_sniffer_start(uint8_t channel)
{
    if (!s_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (channel < 1 || channel > 14) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_start failed: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous_rx_cb failed: %s", esp_err_to_name(err));
        return err;
    }

    const wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_CTRL |
                       WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MISC,
    };
    err = esp_wifi_set_promiscuous_filter(&filter);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous_filter failed: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous(true) failed: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_channel(%d) failed: %s", channel, esp_err_to_name(err));
        return err;
    }

    s_current_channel = channel;
    ESP_LOGI(TAG, "promiscuous RX started on channel %d", channel);
    return ESP_OK;
}
