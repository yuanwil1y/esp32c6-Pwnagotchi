#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * Phase 1.5: host-testable channel table and hopper failure policy.
 *
 * Pure logic over plain integers; the ESP-IDF adapter (channel_hopper.c)
 * feeds it the values returned by esp_wifi_get_country() / esp_wifi_set_channel().
 * No ESP headers are included here so the host regression tests compile the
 * production file directly.
 *
 * IDF v5.4 contract (esp_wifi.h / esp_wifi_types_generic.h):
 * - wifi_country_t.schan : "Start channel of the allowed 2.4GHz Wi-Fi channels"
 * - wifi_country_t.nchan : "Total channel number" (COUNT, not last channel);
 *   the default country is {cc="01", schan=1, nchan=11}, i.e. world-safe 1..11.
 * - esp_wifi_set_channel() returns ESP_ERR_INVALID_ARG for a channel outside
 *   the configured country (deterministic), while transient failures surface
 *   as other error codes (e.g. ESP_ERR_WIFI_TIMEOUT / internal state).
 */

#define HOPPER_MAX_CHANNELS 14
#define HOPPER_HW_CHANNEL_MAX 14 /* 2.4 GHz channels the C6 radio can use */

/* Conservative fallback when the country info is missing or invalid. */
#define HOPPER_FALLBACK_FIRST 1
#define HOPPER_FALLBACK_LAST 11

/*
 * Build the hop list from the driver's country table.
 * `schan`/`nchan` are passed as int on purpose: the upper bound
 * schan + nchan - 1 is computed in the wide type and validated before any
 * narrowing, so a bogus table (e.g. nchan=255) cannot overflow the list.
 * The resulting range is intersected with [1, HOPPER_HW_CHANNEL_MAX].
 * Returns false (and leaves *count untouched at 0) for an invalid or empty
 * table; the caller then applies the conservative 1..11 fallback.
 */
bool hopper_build_list_from_country(int schan, int nchan,
                                    uint8_t *out_channels, uint8_t max_channels,
                                    uint8_t *count);

/* Conservative 1..11 world-safe list for missing/invalid country info. */
void hopper_build_fallback_list(uint8_t *out_channels, uint8_t max_channels,
                                uint8_t *count);

/* Error classes for esp_wifi_set_channel() failures. */
typedef enum {
    HOPPER_ERR_OK = 0,          /* ESP_OK (not a failure) */
    HOPPER_ERR_TRANSIENT,       /* retry with backoff, never retire */
    HOPPER_ERR_INVALID_CHANNEL, /* deterministic: retire the channel */
    HOPPER_ERR_DRIVER_DEAD,     /* driver not init/started: stop hopping */
} hopper_err_class_t;

/* Classify a raw esp_err_t from esp_wifi_set_channel(). Values mirrored
 * from IDF v5.4 esp_err.h / esp_wifi.h (ESP_ERR_WIFI_BASE = 0x3000):
 *   ESP_ERR_INVALID_ARG       0x102  -> deterministic invalid channel
 *   ESP_ERR_WIFI_NOT_INIT     0x3001 -> driver dead
 *   ESP_ERR_WIFI_NOT_STARTED  0x3002 -> driver dead
 *   everything else                  -> transient
 */
hopper_err_class_t hopper_err_classify(int err);

/* Per-channel failure bookkeeping for the bounded retry policy. */
typedef struct {
    uint8_t consecutive_transient;
    uint32_t last_log_ms;
} hopper_channel_health_t;

typedef enum {
    HOP_ACT_CONTINUE, /* transient below threshold: try again next dwell */
    HOP_ACT_SKIP_PASS, /* degraded: skip this channel for the current pass */
    HOP_ACT_RETIRE,    /* deterministic invalid channel: remove from list */
    HOP_ACT_STOP,      /* driver dead: stop the hopper entirely */
} hopper_action_t;

/* Consecutive transient failures tolerated before a channel is skipped
 * for the current pass. The channel stays in the list and is retried on
 * the next pass, so a transient storm can never retire every channel and
 * the retry rate stays bounded (once per pass). */
#define HOPPER_TRANSIENT_SKIP_THRESHOLD 3

/*
 * Feed one set_channel failure into the policy. Log lines are throttled
 * separately via hopper_log_due(). Success on a channel must reset its
 * health via hopper_note_success().
 */
hopper_action_t hopper_note_failure(hopper_channel_health_t *health,
                                    hopper_err_class_t cls);

/* Reset a channel's health after a successful set_channel. */
void hopper_note_success(hopper_channel_health_t *health);

/* True when the caller may log a failure line for this channel now
 * (throttled to one line per 5 s per channel). */
bool hopper_log_due(hopper_channel_health_t *health, uint32_t now_ms);

#define HOPPER_LOG_INTERVAL_MS 5000
