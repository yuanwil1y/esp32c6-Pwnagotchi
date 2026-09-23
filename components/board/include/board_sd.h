#pragma once

#include <stdbool.h>

#include "esp_err.h"

#define BOARD_SD_MOUNT_POINT "/sdcard"
#define BOARD_SD_TEST_FILE   BOARD_SD_MOUNT_POINT "/phase0.txt"

esp_err_t board_sd_init(void);
esp_err_t board_sd_self_test(void);
bool board_sd_is_mounted(void);
