#include "wifi_sniffer.h"

#include "ieee80211_parser.h"

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
static const char *TAG_80211 = "80211";

#define RADIO_RX_TASK_STACK       2048
#define RADIO_RX_TASK_PRIO        5
#define RADIO_STATS_TASK_STACK    3072
#define RADIO_STATS_TASK_PRIO     2
#define RADIO_STATS_PERIOD_MS     3000

/* Debug aid: print the classification of the first N parsed frames.
 * Keep 0 in normal builds; never gates or touches the RX callback. */
#define RADIO_PARSER_DEBUG_N      0

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

/* Maps the driver packet type onto the raw Frame Control type value for
 * the consistency cross-check. 0xFF for types without an FC counterpart. */
static uint8_t driver_pkt_type_to_fc_type(uint8_t packet_type)
{
    switch ((wifi_promiscuous_pkt_type_t)packet_type) {
    case WIFI_PKT_MGMT:
        return IEEE80211_FC_TYPE_VALUE_MGMT;
    case WIFI_PKT_CTRL:
        return IEEE80211_FC_TYPE_VALUE_CTRL;
    case WIFI_PKT_DATA:
        return IEEE80211_FC_TYPE_VALUE_DATA;
    default:
        return 0xFF;
    }
}

/* Counters for one parsed frame. Requires the stats lock. */
static void stats_count_parsed_locked(const radio_packet_t *pkt,
                                      const ieee80211_frame_info_t *info)
{
    s_stats.parser_total++;

    if (!info->valid) {
        /* Empty or too-short packet: safe return, no further reads. */
        s_stats.parser_errors++;
        s_stats.invalid_frames++;
        return;
    }

    const uint8_t driver_type = driver_pkt_type_to_fc_type(pkt->packet_type);
    if (driver_type != 0xFF && driver_type != info->fc.type) {
        s_stats.fc_type_mismatch++;
    }

    switch (info->type) {
    case IEEE80211_TYPE_MGMT:
        s_stats.mgmt_total++;
        switch (info->fc.subtype) {
        case IEEE80211_MGMT_ASSOC_REQ:
            s_stats.assoc_req_count++;
            break;
        case IEEE80211_MGMT_ASSOC_RESP:
            s_stats.assoc_resp_count++;
            break;
        case IEEE80211_MGMT_REASSOC_REQ:
            s_stats.reassoc_req_count++;
            break;
        case IEEE80211_MGMT_REASSOC_RESP:
            s_stats.reassoc_resp_count++;
            break;
        case IEEE80211_MGMT_PROBE_REQ:
            s_stats.probe_req_count++;
            break;
        case IEEE80211_MGMT_PROBE_RESP:
            s_stats.probe_resp_count++;
            break;
        case IEEE80211_MGMT_BEACON:
            s_stats.beacon_count++;
            break;
        case IEEE80211_MGMT_ATIM:
            s_stats.atim_count++;
            break;
        case IEEE80211_MGMT_DISASSOC:
            s_stats.disassoc_count++;
            break;
        case IEEE80211_MGMT_AUTH:
            s_stats.auth_count++;
            break;
        case IEEE80211_MGMT_DEAUTH:
            s_stats.deauth_count++;
            break;
        case IEEE80211_MGMT_ACTION:
            s_stats.action_count++;
            break;
        default:
            s_stats.mgmt_other_count++;
            break;
        }
        break;
    case IEEE80211_TYPE_CTRL:
        s_stats.ctrl_total++;
        switch (info->fc.subtype) {
        case IEEE80211_CTRL_RTS:
            s_stats.rts_count++;
            break;
        case IEEE80211_CTRL_CTS:
            s_stats.cts_count++;
            break;
        case IEEE80211_CTRL_ACK:
            s_stats.ack_count++;
            break;
        case IEEE80211_CTRL_BAR:
            s_stats.bar_count++;
            break;
        case IEEE80211_CTRL_BA:
            s_stats.ba_count++;
            break;
        default:
            s_stats.ctrl_other_count++;
            break;
        }
        break;
    case IEEE80211_TYPE_DATA:
        s_stats.data_total++;
        switch (info->fc.subtype) {
        case IEEE80211_DATA_DATA:
        case IEEE80211_DATA_DATA_CFACK:
        case IEEE80211_DATA_DATA_CFPOLL:
        case IEEE80211_DATA_DATA_CFACK_CFPOLL:
            s_stats.fc_data_count++;
            break;
        case IEEE80211_DATA_NULL:
        case IEEE80211_DATA_CFACK:
        case IEEE80211_DATA_CFPOLL:
        case IEEE80211_DATA_CFACK_CFPOLL:
            s_stats.null_count++;
            break;
        case IEEE80211_DATA_QOS_DATA:
        case IEEE80211_DATA_QOS_DATA_CFACK:
        case IEEE80211_DATA_QOS_DATA_CFPOLL:
        case IEEE80211_DATA_QOS_DATA_CFACK_CFPOLL:
            s_stats.qos_data_count++;
            break;
        case IEEE80211_DATA_QOS_NULL:
            s_stats.qos_null_count++;
            break;
        default:
            s_stats.data_other_count++;
            break;
        }
        break;
    case IEEE80211_TYPE_EXT:
        s_stats.ext_total++;
        break;
    default:
        /* Not reachable with a 2-bit FC type, kept for safety. */
        s_stats.parser_errors++;
        break;
    }
}

/*
 * Consumer task. Phase 1A driver-type counting plus Phase 1B Frame Control
 * classification via the pure parser. All parsing happens here, never in
 * the Wi-Fi callback.
 */
static void radio_rx_task(void *arg)
{
    (void)arg;

#if RADIO_PARSER_DEBUG_N > 0
    uint32_t debug_printed = 0;
#endif

    while (true) {
        radio_packet_t *pkt = NULL;
        if (xQueueReceive(s_rx_queue, &pkt, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        ieee80211_frame_info_t info = {0};
        const bool parsed = ieee80211_parse(pkt->data, pkt->length, &info);

#if RADIO_PARSER_DEBUG_N > 0
        if (parsed && debug_printed < RADIO_PARSER_DEBUG_N) {
            debug_printed++;
            ESP_LOGI(TAG_80211, "dbg drv=%u fc_type=%u sub=%u len=%u",
                     pkt->packet_type, info.fc.type, info.fc.subtype, pkt->length);
        }
#endif

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
        stats_count_parsed_locked(pkt, &info);
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

        ESP_LOGI(TAG_80211,
                 "total=%" PRIu32 " err=%" PRIu32 " invalid=%" PRIu32
                 " mismatch=%" PRIu32,
                 stats.parser_total, stats.parser_errors, stats.invalid_frames,
                 stats.fc_type_mismatch);
        ESP_LOGI(TAG_80211,
                 "MGMT=%" PRIu32 " beacon=%" PRIu32 " probe_req=%" PRIu32
                 " probe_resp=%" PRIu32 " auth=%" PRIu32 " assoc_req=%" PRIu32
                 " deauth=%" PRIu32 " other=%" PRIu32,
                 stats.mgmt_total, stats.beacon_count, stats.probe_req_count,
                 stats.probe_resp_count, stats.auth_count, stats.assoc_req_count,
                 stats.deauth_count, stats.mgmt_other_count);
        ESP_LOGI(TAG_80211,
                 "CTRL=%" PRIu32 " rts=%" PRIu32 " cts=%" PRIu32 " ack=%" PRIu32
                 " bar=%" PRIu32 " ba=%" PRIu32 " other=%" PRIu32,
                 stats.ctrl_total, stats.rts_count, stats.cts_count, stats.ack_count,
                 stats.bar_count, stats.ba_count, stats.ctrl_other_count);
        ESP_LOGI(TAG_80211,
                 "DATA=%" PRIu32 " qos_data=%" PRIu32 " qos_null=%" PRIu32
                 " null=%" PRIu32 " other=%" PRIu32,
                 stats.data_total, stats.qos_data_count, stats.qos_null_count,
                 stats.null_count, stats.data_other_count);
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

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
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

    /* The control subtype filter defaults to "none": without opting in,
     * the driver delivers no RTS/CTS/ACK/BA frames at all. */
    const wifi_promiscuous_filter_t ctrl_filter = {
        .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL,
    };
    err = esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter);
    if (err != ESP_OK) {
        /* Sniffing stays functional without control frames. */
        ESP_LOGW(TAG, "set_promiscuous_ctrl_filter failed: %s", esp_err_to_name(err));
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
