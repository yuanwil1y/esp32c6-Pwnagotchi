#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "sd_logger_core.h"

/* Start the single-owner logger task and its fixed queue/pool. This is called
 * after board_sd_init/self-test; media_mounted records that initial result. */
esp_err_t sd_logger_init(const char *firmware_sha, bool media_mounted);

/* Parser-task producer: fixed-copy, try-only, and never performs file I/O. */
bool sd_logger_try_submit(const radio_packet_t *packet);
bool sd_logger_is_accepting(void);

/* Control requests only enqueue state changes; all file operations remain in
 * the logger task. The wait API is bounded and reports pending on timeout. */
esp_err_t sd_logger_start(void);
bool sd_logger_request_stop(void);
typedef enum {
    SD_LOGGER_WAIT_STOPPED = 0,
    SD_LOGGER_WAIT_PENDING,
    SD_LOGGER_WAIT_ERROR,
} sd_logger_wait_result_t;
sd_logger_wait_result_t sd_logger_wait_stopped(uint32_t timeout_ms);
void sd_logger_get_stats(sd_logger_stats_t *out);

/* Adds capture-start / capture-stop / capture-status to the existing UART
 * console. It never starts capture automatically. */
esp_err_t sd_logger_console_start(void);
