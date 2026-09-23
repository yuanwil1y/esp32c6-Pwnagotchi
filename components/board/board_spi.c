#include "board_spi.h"

#include <stdbool.h>
#include <stdint.h>

#include "driver/spi_master.h"
#include "esp_log.h"

#include "board_pins.h"

static const char *TAG = "board_spi";
static bool s_initialized;

esp_err_t board_spi_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    const spi_bus_config_t bus_config = {
        .mosi_io_num = BOARD_PIN_LCD_MOSI,
        .miso_io_num = BOARD_PIN_SD_MISO,
        .sclk_io_num = BOARD_PIN_LCD_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = BOARD_LCD_H_RES * BOARD_LCD_DRAW_LINES * sizeof(uint16_t),
    };

    const esp_err_t err = spi_bus_initialize(BOARD_SPI_HOST, &bus_config, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SPI2 init failed: %s", esp_err_to_name(err));
        return err;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "SPI2 ready: MOSI=%d MISO=%d SCLK=%d",
             BOARD_PIN_LCD_MOSI, BOARD_PIN_SD_MISO, BOARD_PIN_LCD_SCLK);
    return ESP_OK;
}
