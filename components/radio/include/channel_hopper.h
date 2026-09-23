#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/*
 * Phase 1D channel hopper.
 *
 * Runs in its own FreeRTOS task and cycles esp_wifi_set_channel() through
 * the 2.4 GHz channels this device's configuration allows. Completely
 * decoupled from the promiscuous RX callback; the parser task only sees
 * frames arriving on whatever channel is current.
 */

typedef struct {
    bool enabled;
    /* Last channel whose set_channel() succeeded; 0 = no successful hop
     * yet (unknown). Kept after the hopper stops so consumers never fall
     * back to a stale startup channel. */
    uint8_t current_channel;
    uint32_t dwell_ms;
    uint32_t hop_count;
    uint32_t hop_errors;
    uint32_t last_hop_ms; /* ms timestamp of the last successful hop */
} channel_hopper_stats_t;

/*
 * Build the channel list from the driver's country table
 * (esp_wifi_get_country(): schan = first channel, nchan = count; missing
 * or invalid tables fall back to world-safe 1..11) and create the hopper
 * task. Requires esp_wifi_start() to have succeeded first.
 *
 * Failure policy: ESP_ERR_INVALID_ARG retires a channel (deterministic
 * invalid entry); other errors are treated as transient - bounded
 * retries, then the channel is skipped for the current pass, never
 * retired, so a transient failure storm cannot retire every channel. A
 * dead driver (NOT_INIT/NOT_STARTED) stops the hopper. Task creation
 * failure leaves enabled == false.
 */
esp_err_t channel_hopper_start(uint32_t dwell_ms);

/* Signal the task to exit and wait briefly for it. Safe if not running. */
void channel_hopper_stop(void);

uint8_t channel_hopper_get_current_channel(void);

/* Concurrency-safe snapshot. */
void channel_hopper_get_stats(channel_hopper_stats_t *out);
