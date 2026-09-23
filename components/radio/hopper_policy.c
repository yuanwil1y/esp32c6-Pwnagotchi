#include "hopper_policy.h"

#include <stddef.h>

/*
 * Phase 1.5 channel table + failure policy. Pure logic, no ESP headers:
 * compiled verbatim into the host regression tests. See the header for the
 * IDF v5.4 contract this encodes.
 */

bool hopper_build_list_from_country(int schan, int nchan,
                                    uint8_t *out_channels, uint8_t max_channels,
                                    uint8_t *count)
{
    if (count != NULL) {
        *count = 0;
    }
    if (out_channels == NULL || count == NULL || max_channels == 0) {
        return false;
    }

    /* Wide type for the arithmetic; validate before narrowing. */
    const int last = schan + nchan - 1;

    if (schan < 1 || nchan < 1 || last > HOPPER_HW_CHANNEL_MAX) {
        return false;
    }

    int first = schan;
    if (first < 1) {
        first = 1;
    }

    uint8_t n = 0;
    for (int ch = first; ch <= last && n < max_channels; ch++) {
        out_channels[n++] = (uint8_t)ch;
    }
    *count = n;
    return n > 0;
}

void hopper_build_fallback_list(uint8_t *out_channels, uint8_t max_channels,
                                uint8_t *count)
{
    if (count != NULL) {
        *count = 0;
    }
    if (out_channels == NULL || count == NULL || max_channels == 0) {
        return;
    }

    uint8_t n = 0;
    for (int ch = HOPPER_FALLBACK_FIRST;
         ch <= HOPPER_FALLBACK_LAST && n < max_channels; ch++) {
        out_channels[n++] = (uint8_t)ch;
    }
    *count = n;
}

hopper_err_class_t hopper_err_classify(int err)
{
    /* Mirrored from IDF v5.4 esp_err.h / esp_wifi.h; see header. */
    enum {
        ESP_OK_ = 0,
        ESP_ERR_INVALID_ARG_ = 0x102,
        ESP_ERR_WIFI_BASE_ = 0x3000,
    };

    if (err == ESP_OK_) {
        return HOPPER_ERR_OK;
    }
    if (err == ESP_ERR_INVALID_ARG_) {
        return HOPPER_ERR_INVALID_CHANNEL;
    }
    if (err == ESP_ERR_WIFI_BASE_ + 1 /* NOT_INIT */ ||
        err == ESP_ERR_WIFI_BASE_ + 2 /* NOT_STARTED */) {
        return HOPPER_ERR_DRIVER_DEAD;
    }
    return HOPPER_ERR_TRANSIENT;
}

hopper_action_t hopper_note_failure(hopper_channel_health_t *health,
                                    hopper_err_class_t cls)
{
    if (health == NULL) {
        return HOP_ACT_STOP;
    }

    switch (cls) {
    case HOPPER_ERR_INVALID_CHANNEL:
        /* Deterministic: the country table excludes this channel. */
        return HOP_ACT_RETIRE;

    case HOPPER_ERR_DRIVER_DEAD:
        /* Retiring channels cannot fix a dead driver; stop cleanly. */
        return HOP_ACT_STOP;

    case HOPPER_ERR_TRANSIENT:
        health->consecutive_transient++;
        if (health->consecutive_transient >= HOPPER_TRANSIENT_SKIP_THRESHOLD) {
            /* Bounded degradation: skip for the rest of this pass, retry
             * on the next pass. Never retires the channel. */
            return HOP_ACT_SKIP_PASS;
        }
        return HOP_ACT_CONTINUE;

    default:
        return HOP_ACT_CONTINUE;
    }
}

void hopper_note_success(hopper_channel_health_t *health)
{
    if (health != NULL) {
        health->consecutive_transient = 0;
    }
}

bool hopper_log_due(hopper_channel_health_t *health, uint32_t now_ms)
{
    if (health == NULL) {
        return false;
    }
    if ((uint32_t)(now_ms - health->last_log_ms) < HOPPER_LOG_INTERVAL_MS) {
        return false;
    }
    health->last_log_ms = now_ms;
    return true;
}
