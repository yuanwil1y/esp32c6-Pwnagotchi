#include "wifi_sniffer.h"

#include "channel_hopper.h"
#include "ieee80211_parser.h"
#include "obs_cache.h"
#include "rx_path.h"
#include "world.h"

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char *TAG = "RADIO";
static const char *TAG_80211 = "80211";
static const char *TAG_OBS = "OBS";

#define RADIO_RX_TASK_STACK       2048
#define RADIO_RX_TASK_PRIO        5
#define RADIO_STATS_TASK_STACK    3072
#define RADIO_STATS_TASK_PRIO     2
#define RADIO_STATS_PERIOD_MS     3000

/* Queue wait bound: guarantees the world TTL maintenance also runs when
 * traffic is zero, and that a busy queue cannot starve it either. */
#define RADIO_RX_QUEUE_WAIT_MS    100
#define WORLD_MAINT_INTERVAL_MS   500

/* Debug aid: print the classification of the first N parsed frames.
 * Keep 0 in normal builds; never gates or touches the RX callback. */
#define RADIO_PARSER_DEBUG_N      0

/* Fixed packet pool: no dynamic memory in the RX path. */
static radio_packet_t s_packet_pool[RADIO_PACKET_POOL_SIZE];
static QueueHandle_t s_free_queue; /* radio_packet_t* available for the callback */
static QueueHandle_t s_rx_queue;   /* radio_packet_t* filled by the callback */

static portMUX_TYPE s_stats_mux = portMUX_INITIALIZER_UNLOCKED;
static radio_stats_t s_stats;
static rx_path_stats_t s_rx_stats;
static uint8_t s_current_channel;
static bool s_initialized;

/*
 * Phase 2 World Model. Single writer (radio_rx_task); readers copy a small
 * snapshot under a task-level mutex. Never accessed from the promiscuous
 * callback and never held across LVGL / logging / SD calls beyond the
 * short world operation itself.
 */
static world_t s_world;
static SemaphoreHandle_t s_world_mux;
static uint64_t s_last_world_maint;

static uint64_t radio_now_ms(void)
{
    /* Single monotonic clock for the whole RX path (uint64 ms). */
    return (uint64_t)esp_timer_get_time() / 1000ull;
}

static void world_feed_ap(const ieee80211_ap_observation_t *obs,
                          uint64_t now_ms, bool is_beacon)
{
    if (xSemaphoreTake(s_world_mux, pdMS_TO_TICKS(10)) != pdTRUE) {
        /* Never block the RX task on the world; drop this update. The
         * snapshot consumers keep working with the previous state. */
        return;
    }
    world_on_ap_observation(&s_world, obs, now_ms, is_beacon);
    xSemaphoreGive(s_world_mux);
}

/* TTL/eviction housekeeping; safe to call with or without traffic. The
 * timestamp is only advanced after a completed maintenance run, so a
 * failed mutex take retries on the next call. */
static void world_tick(uint64_t now_ms)
{
    if ((now_ms - s_last_world_maint) < WORLD_MAINT_INTERVAL_MS) {
        return;
    }

    if (xSemaphoreTake(s_world_mux, pdMS_TO_TICKS(10)) != pdTRUE) {
        return;
    }
    world_maintenance(&s_world, now_ms);
    s_last_world_maint = now_ms;
    xSemaphoreGive(s_world_mux);
}

/*
 * Phase 1.5 observation log throttling: fixed-size dedup caches so the
 * console gets one line per new/changed AP and per new (src, ssid) probe,
 * never one line per beacon. This is deliberately NOT an AP database.
 * Touched only from radio_rx_task, so no extra locking.
 */
#define RADIO_PROBE_CACHE_SIZE  16

static obs_ap_cache_t s_ap_cache;

typedef struct {
    bool used;
    uint8_t src[6];
    uint8_t ssid_len;
    char ssid[33];
} probe_cache_entry_t;

static probe_cache_entry_t s_probe_cache[RADIO_PROBE_CACHE_SIZE];
static uint8_t s_probe_cache_next;

/* Global rate cap on observation log lines. Dedup alone is not enough:
 * with more distinct BSSIDs than cache slots, eviction churn could turn
 * every beacon into a "new" AP line. 5 lines/s worst case. */
#define RADIO_OBS_LOG_MIN_INTERVAL_MS 200
static TickType_t s_last_obs_log_tick;

static bool obs_log_rate_ok(void)
{
    const TickType_t now = xTaskGetTickCount();
    if ((now - s_last_obs_log_tick) < pdMS_TO_TICKS(RADIO_OBS_LOG_MIN_INTERVAL_MS)) {
        return false;
    }
    s_last_obs_log_tick = now;
    return true;
}

/* --- rx_path io hooks: FreeRTOS queue mapping (never blocks) --- */

static bool io_slot_alloc(void *ctx, radio_packet_t **out)
{
    (void)ctx;
    return xQueueReceive(s_free_queue, out, 0) == pdTRUE;
}

static bool io_rx_push(void *ctx, radio_packet_t *slot)
{
    (void)ctx;
    return xQueueSend(s_rx_queue, &slot, 0) == pdTRUE;
}

static bool io_slot_return(void *ctx, radio_packet_t *slot)
{
    (void)ctx;
    return xQueueSend(s_free_queue, &slot, 0) == pdTRUE;
}

static void io_lock(void *ctx)
{
    (void)ctx;
    portENTER_CRITICAL(&s_stats_mux);
}

static void io_unlock(void *ctx)
{
    (void)ctx;
    portEXIT_CRITICAL(&s_stats_mux);
}

static const rx_path_io_t s_rx_io = {
    .ctx = NULL,
    .slot_alloc = io_slot_alloc,
    .rx_push = io_rx_push,
    .slot_return = io_slot_return,
    .lock = io_lock,
    .unlock = io_unlock,
};

/*
 * Promiscuous RX callback. Runs in the Wi-Fi driver task context: only read
 * driver metadata and hand the frame to the rx_path core (bounded copy into
 * a pooled buffer + enqueue). Never blocks, never logs, never allocates.
 *
 * rx_ctrl.rx_state: 0 = clean delivery, non-zero = driver-reported error
 * (IDF v5.4 esp_wifi_types_native.h). rx_ctrl.sig_len is the on-air length
 * including FCS. For WIFI_PKT_MISC the driver's payload is zero length;
 * handling that whitelist lives in the rx_path core (Phase 1.5).
 */
static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    /* IDF v5.4 payload contract: sig_len is the on-air length including
     * FCS for MGMT/CTRL/DATA, while MISC packets have a zero-length
     * payload regardless of sig_len (esp_wifi_types.h). The adapter
     * therefore only vouches for payload bytes on whitelisted types; the
     * rx_path core additionally refuses to read payload for anything
     * else. */
    uint16_t payload_len = 0;
    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_CTRL || type == WIFI_PKT_DATA) {
        payload_len = (uint16_t)pkt->rx_ctrl.sig_len;
    }

    rx_frame_view_t view = {
        .type = (uint8_t)type,
        .channel = (uint8_t)pkt->rx_ctrl.channel,
        .rssi = (int8_t)pkt->rx_ctrl.rssi,
        .rx_state = (uint16_t)pkt->rx_ctrl.rx_state,
        .sig_len = (uint16_t)pkt->rx_ctrl.sig_len,
        .payload = pkt->payload,
        .payload_len = payload_len,
    };

    rx_path_on_frame(&s_rx_io, &s_rx_stats, &view);
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

/* Returns true when this (src, ssid) probe has not been logged yet. */
static bool probe_cache_update(const ieee80211_probe_req_observation_t *obs)
{
    for (int i = 0; i < RADIO_PROBE_CACHE_SIZE; i++) {
        probe_cache_entry_t *e = &s_probe_cache[i];
        if (!e->used || memcmp(e->src, obs->source, sizeof(e->src)) != 0) {
            continue;
        }
        if (e->ssid_len == obs->ssid_len &&
            memcmp(e->ssid, obs->ssid, obs->ssid_len) == 0) {
            return false;
        }
        e->ssid_len = obs->ssid_len;
        memcpy(e->ssid, obs->ssid, sizeof(e->ssid));
        return true;
    }

    probe_cache_entry_t *e = &s_probe_cache[s_probe_cache_next % RADIO_PROBE_CACHE_SIZE];
    s_probe_cache_next++;
    e->used = true;
    memcpy(e->src, obs->source, sizeof(e->src));
    e->ssid_len = obs->ssid_len;
    memcpy(e->ssid, obs->ssid, sizeof(e->ssid));
    return true;
}

/*
 * Length passed to the parser: the MAC body of the pooled copy, without
 * the FCS. See rx_path_parse_length() in rx_path.h for the captured /
 * original length contract.
 */
static uint16_t packet_parse_length(const radio_packet_t *pkt)
{
    return rx_path_parse_length(pkt);
}

/* Beacon / probe response observation: parse, count, throttle-log. */
static void handle_ap_observation(const radio_packet_t *pkt,
                                  uint16_t parse_len,
                                  const ieee80211_parse_opts_t *opts,
                                  bool is_beacon)
{
    ieee80211_ap_observation_t obs;
    if (!ieee80211_parse_beacon_or_probe_resp(pkt->data, parse_len, opts, &obs)) {
        portENTER_CRITICAL(&s_stats_mux);
        s_stats.beacon_parse_errors++;
        portEXIT_CRITICAL(&s_stats_mux);
        return;
    }
    obs.rssi = pkt->rssi;
    obs.rx_channel = pkt->channel;

    const ieee80211_security_t sec = ieee80211_classify_security(&obs);
    const obs_ap_result_t res = obs_ap_cache_update(&s_ap_cache, &obs, (uint8_t)sec);

    portENTER_CRITICAL(&s_stats_mux);
    if (is_beacon) {
        s_stats.beacon_parsed++;
    } else {
        s_stats.probe_resp_parsed++;
    }
    s_stats.ie_total += obs.ie_count;
    if (obs.malformed_ie) {
        s_stats.ie_malformed++;
    }
    if (obs.ie_walk_incomplete) {
        s_stats.ie_incomplete++;
    }
    if (obs.ssid_len > 0) {
        s_stats.ssid_found++;
    }
    if (obs.hidden_ssid) {
        s_stats.hidden_ssid_count++;
    }
    if (obs.rsn_present) {
        s_stats.rsn_ie_count++;
    }
    if (obs.wpa_vendor_present) {
        s_stats.wpa_vendor_ie_count++;
    }
    if (obs.ds_param_present) {
        s_stats.channel_ie_count++;
    }
    if (res.action == OBS_AP_SKIPPED) {
        /* Incomplete observation: counted, but no cache / last-obs /
         * log impact at all (issue 5 policy). */
        s_stats.ap_obs_skipped++;
    } else {
        s_stats.ap_cache_inserts = res.inserts;
        s_stats.ap_cache_updates = res.updates;
        s_stats.ap_cache_evictions = res.evictions;
        s_stats.ap_cache_occupied = res.occupied;
        if (obs.ssid_len > 0) {
            memcpy(s_stats.last_ssid, obs.ssid, sizeof(s_stats.last_ssid));
            s_stats.last_ssid_len = obs.ssid_len;
            s_stats.last_ssid_valid = true;
        }
        /* A complete observation always refreshes rssi/channel context;
         * advertised_channel is 0 when the DS IE was absent/invalid and
         * the rx metadata channel fills in. */
        s_stats.last_ap_channel = obs.advertised_channel != 0
                                      ? obs.advertised_channel
                                      : obs.rx_channel;
        s_stats.last_ap_rssi = obs.rssi;
    }
    portEXIT_CRITICAL(&s_stats_mux);

    /* World Model update happens regardless of the log throttle below. */
    world_feed_ap(&obs, radio_now_ms(), is_beacon);

    if (!res.should_log || !obs_log_rate_ok()) {
        return;
    }

    char mac[18];
    ieee80211_format_mac(obs.bssid, mac, sizeof(mac));

    if (obs.hidden_ssid) {
        ESP_LOGI(TAG_OBS, "AP bssid=%s ssid=<hidden> rssi=%d rx_ch=%u adv_ch=%u bintv=%u sec=%s",
                 mac, obs.rssi, obs.rx_channel, obs.advertised_channel,
                 obs.beacon_interval, ieee80211_security_name(sec));
    } else {
        char printable[IEEE80211_SSID_BUF_LEN];
        ieee80211_ssid_to_printable(obs.ssid, obs.ssid_len, printable, sizeof(printable));
        ESP_LOGI(TAG_OBS, "AP bssid=%s ssid=\"%s\" rssi=%d rx_ch=%u adv_ch=%u bintv=%u sec=%s",
                 mac, printable, obs.rssi, obs.rx_channel, obs.advertised_channel,
                 obs.beacon_interval, ieee80211_security_name(sec));
    }
}

/* Probe request observation: parse, count, throttle-log. */
static void handle_probe_request(const radio_packet_t *pkt,
                                 uint16_t parse_len,
                                 const ieee80211_parse_opts_t *opts)
{
    ieee80211_probe_req_observation_t obs;
    if (!ieee80211_parse_probe_request(pkt->data, parse_len, opts, &obs)) {
        portENTER_CRITICAL(&s_stats_mux);
        s_stats.probe_req_errors++;
        portEXIT_CRITICAL(&s_stats_mux);
        return;
    }
    obs.rssi = pkt->rssi;
    obs.rx_channel = pkt->channel;

    const bool log_this = probe_cache_update(&obs);

    portENTER_CRITICAL(&s_stats_mux);
    s_stats.probe_req_parsed++;
    s_stats.ie_total += obs.ie_count;
    if (obs.malformed_ie) {
        s_stats.ie_malformed++;
    }
    if (obs.ie_walk_incomplete) {
        s_stats.ie_incomplete++;
    }
    portEXIT_CRITICAL(&s_stats_mux);

    if (!log_this || !obs_log_rate_ok()) {
        return;
    }

    char mac[18];
    ieee80211_format_mac(obs.source, mac, sizeof(mac));

    if (obs.wildcard_ssid) {
        ESP_LOGI(TAG_OBS, "PROBE src=%s ssid=<wildcard> rssi=%d ch=%u",
                 mac, obs.rssi, obs.rx_channel);
    } else {
        char printable[IEEE80211_SSID_BUF_LEN];
        ieee80211_ssid_to_printable(obs.ssid, obs.ssid_len, printable, sizeof(printable));
        ESP_LOGI(TAG_OBS, "PROBE src=%s ssid=\"%s\" rssi=%d ch=%u",
                 mac, printable, obs.rssi, obs.rx_channel);
    }
}

/*
 * Consumer task. Phase 1A driver-type counting plus Phase 1B Frame Control
 * classification via the pure parser. All parsing happens here, never in
 * the Wi-Fi callback. The slot goes back to the free pool only after the
 * last read of its bytes.
 *
 * Phase 2: the queue wait is BOUNDED so the world TTL maintenance runs
 * both when no packets arrive at all and under continuous traffic (checked
 * per packet and per timeout).
 */
static void radio_rx_task(void *arg)
{
    (void)arg;

#if RADIO_PARSER_DEBUG_N > 0
    uint32_t debug_printed = 0;
#endif

    while (true) {
        radio_packet_t *pkt = NULL;
        if (xQueueReceive(s_rx_queue, &pkt,
                          pdMS_TO_TICKS(RADIO_RX_QUEUE_WAIT_MS)) != pdTRUE) {
            world_tick(radio_now_ms());
            continue;
        }

        world_tick(radio_now_ms());

        const uint16_t parse_len = packet_parse_length(pkt);
        const ieee80211_parse_opts_t opts = {
            .capture_truncated = rx_path_body_truncated(pkt),
        };

        ieee80211_frame_info_t info = {0};
        ieee80211_parse(pkt->data, pkt->length, &info);

#if RADIO_PARSER_DEBUG_N > 0
        if (info.valid && debug_printed < RADIO_PARSER_DEBUG_N) {
            debug_printed++;
            ESP_LOGI(TAG_80211, "dbg drv=%u fc_type=%u sub=%u len=%u",
                     pkt->packet_type, info.fc.type, info.fc.subtype, pkt->length);
        }
#endif

        /* Driver-type counters moved to the RX callback in Phase 1.5
         * (rx_management/rx_control/rx_data/rx_misc in the rx_path core),
         * so dropped frames stay in the type accounting too. What remains
         * here is the Frame Control classification. */
        portENTER_CRITICAL(&s_stats_mux);
        stats_count_parsed_locked(pkt, &info);
        portEXIT_CRITICAL(&s_stats_mux);

        if (info.valid && info.type == IEEE80211_TYPE_MGMT) {
            switch (info.fc.subtype) {
            case IEEE80211_MGMT_BEACON:
                handle_ap_observation(pkt, parse_len, &opts, true);
                break;
            case IEEE80211_MGMT_PROBE_RESP:
                handle_ap_observation(pkt, parse_len, &opts, false);
                break;
            case IEEE80211_MGMT_PROBE_REQ:
                handle_probe_request(pkt, parse_len, &opts);
                break;
            default:
                break;
            }
        }

        rx_path_slot_release(&s_rx_io, &s_rx_stats, pkt);
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
                 " drop=%" PRIu32 " trunc=%" PRIu32 " st_err=%" PRIu32
                 " mgmt=%" PRIu32 " data=%" PRIu32 " ctrl=%" PRIu32
                 " misc=%" PRIu32 " q=%" PRIu32 "/%" PRIu32
                 " heap=%" PRIu32 " min_heap=%" PRIu32,
                 stats.rx.rx_total, stats.rx.rx_queued, stats.rx.rx_processed,
                 stats.rx.rx_dropped_pool + stats.rx.rx_dropped_queue,
                 stats.rx.rx_truncated, stats.rx.rx_state_errors,
                 stats.rx.rx_management, stats.rx.rx_data, stats.rx.rx_control,
                 stats.rx.rx_misc, stats.rx.queue_current, stats.rx.queue_peak,
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
        ESP_LOGI(TAG_OBS,
                 "APCACHE occ=%u/32 ins=%" PRIu32 " upd=%" PRIu32
                 " evict=%" PRIu32 " skip=%" PRIu32
                 " beacon=%" PRIu32 " berr=%" PRIu32
                 " preq=%" PRIu32 " perr=%" PRIu32 " presp=%" PRIu32
                 " ie=%" PRIu32 " ie_err=%" PRIu32 " ie_inc=%" PRIu32
                 " ssid=%" PRIu32 " hidden=%" PRIu32
                 " rsn=%" PRIu32 " wpa=%" PRIu32 " ds=%" PRIu32,
                 stats.ap_cache_occupied,
                 stats.ap_cache_inserts, stats.ap_cache_updates,
                 stats.ap_cache_evictions, stats.ap_obs_skipped,
                 stats.beacon_parsed, stats.beacon_parse_errors,
                 stats.probe_req_parsed, stats.probe_req_errors,
                 stats.probe_resp_parsed, stats.ie_total, stats.ie_malformed,
                 stats.ie_incomplete,
                 stats.ssid_found, stats.hidden_ssid_count,
                 stats.rsn_ie_count, stats.wpa_vendor_ie_count,
                 stats.channel_ie_count);
        ESP_LOGI(TAG,
                 "HOP ch=%u hops=%" PRIu32 " errors=%" PRIu32
                 " dwell=%" PRIu32 "ms",
                 stats.current_channel, stats.hop_count, stats.hop_errors,
                 stats.dwell_ms);
        ESP_LOGI(TAG,
                 "WORLD ap=%u created=%" PRIu32 " expired=%" PRIu32
                 " evicted=%" PRIu32 " rejected=%" PRIu32
                 " stale=%" PRIu32 " invalid=%" PRIu32,
                 stats.ap_db_current, stats.ap_db_created, stats.ap_db_expired,
                 stats.ap_db_evicted, stats.ap_db_rejected,
                 stats.world_obs_stale, stats.world_obs_invalid);
    }
}

void wifi_sniffer_get_stats(radio_stats_t *out)
{
    if (out == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_stats_mux);
    *out = s_stats;
    out->rx = s_rx_stats;
    portEXIT_CRITICAL(&s_stats_mux);

    if (s_rx_queue != NULL) {
        out->rx.queue_current = uxQueueMessagesWaiting(s_rx_queue);
    }
    out->current_channel = s_current_channel;

    /* World snapshot: short bounded copy under the task-level mutex,
     * never inside an interrupt-disabled section. */
    if (s_world_mux != NULL &&
        xSemaphoreTake(s_world_mux, pdMS_TO_TICKS(20)) == pdTRUE) {
        world_snapshot_t ws;
        world_snapshot(&s_world, &ws);
        xSemaphoreGive(s_world_mux);

        out->ap_db_current = ws.ap_current;
        out->ap_db_created = ws.stats.ap_created;
        out->ap_db_expired = ws.stats.ap_expired;
        out->ap_db_evicted = ws.stats.ap_evicted;
        out->ap_db_rejected = ws.stats.ap_rejected;
        out->world_obs_stale = ws.stats.obs_stale;
        out->world_obs_invalid = ws.stats.obs_invalid;
    }

    /* Merge hopper state so consumers need a single snapshot call.
     * current_channel semantics (Phase 1.5): the hopper's last known good
     * channel wins whenever it exists - also after the hopper stops - so
     * the report never falls back to the stale startup channel. */
    channel_hopper_stats_t hop;
    channel_hopper_get_stats(&hop);
    out->hop_count = hop.hop_count;
    out->hop_errors = hop.hop_errors;
    out->dwell_ms = hop.dwell_ms;
    if (hop.current_channel != 0) {
        out->current_channel = hop.current_channel;
    }
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

    /* World Model must be live before the RX task exists and before the
     * promiscuous RX is enabled in wifi_sniffer_start(). */
    s_world_mux = xSemaphoreCreateMutex();
    if (s_world_mux == NULL) {
        ESP_LOGE(TAG, "world mutex creation failed");
        return ESP_ERR_NO_MEM;
    }
    world_init(&s_world);
    s_last_world_maint = 0;

    memset(&s_stats, 0, sizeof(s_stats));
    memset(&s_rx_stats, 0, sizeof(s_rx_stats));
    obs_ap_cache_init(&s_ap_cache);
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
