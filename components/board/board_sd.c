#include "board_sd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "driver/sdspi_host.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

#include "board_pins.h"
#include "board_spi.h"

static const char *TAG = "board_sd";
static sdmmc_card_t *s_card;

esp_err_t board_sd_init(void)
{
    if (s_card != NULL) {
        return ESP_OK;
    }

    esp_err_t err = board_spi_init();
    if (err != ESP_OK) {
        return err;
    }

    const esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 512,
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = BOARD_SPI_HOST;

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = BOARD_PIN_SD_CS;
    slot_config.host_id = BOARD_SPI_HOST;

    err = esp_vfs_fat_sdspi_mount(BOARD_SD_MOUNT_POINT, &host, &slot_config,
                                  &mount_config, &s_card);
    if (err != ESP_OK) {
        s_card = NULL;
        ESP_LOGW(TAG, "SD mount: FAIL (%s)", esp_err_to_name(err));
        return err;
    }

    sdmmc_card_print_info(stdout, s_card);
    ESP_LOGI(TAG, "SD mount: OK at %s, size %.2f GB", BOARD_SD_MOUNT_POINT,
             (double)s_card->csd.capacity / 2048.0 / 1024.0);
    return ESP_OK;
}

bool board_sd_is_mounted(void)
{
    return s_card != NULL;
}

esp_err_t board_sd_self_test(void)
{
    if (s_card == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    static const char expected[] = "esp32c6-Pwnagotchi phase0";

    FILE *file = fopen(BOARD_SD_TEST_FILE, "w");
    if (file == NULL) {
        ESP_LOGE(TAG, "SD write: FAIL (open %s, errno=%d '%s')",
                 BOARD_SD_TEST_FILE, errno, strerror(errno));
        return ESP_FAIL;
    }

    const int written = fputs(expected, file);
    const int close_write_result = fclose(file);
    if (written == EOF || close_write_result != 0) {
        ESP_LOGE(TAG, "SD write: FAIL (%s)", BOARD_SD_TEST_FILE);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "SD write: OK (%s)", BOARD_SD_TEST_FILE);

    char actual[sizeof(expected) + 8] = {0};
    file = fopen(BOARD_SD_TEST_FILE, "r");
    if (file == NULL) {
        ESP_LOGE(TAG, "SD read: FAIL (open %s, errno=%d '%s')",
                 BOARD_SD_TEST_FILE, errno, strerror(errno));
        return ESP_FAIL;
    }

    const char *read_result = fgets(actual, sizeof(actual), file);
    fclose(file);
    if (read_result == NULL) {
        ESP_LOGE(TAG, "SD read: FAIL (%s)", BOARD_SD_TEST_FILE);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "SD read: OK -> '%s'", actual);

    if (strcmp(actual, expected) != 0) {
        ESP_LOGE(TAG, "SD verify: FAIL (expected '%s')", expected);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "SD verify: OK");
    return ESP_OK;
}
