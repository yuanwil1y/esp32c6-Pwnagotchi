#include "board_display.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/spi_master.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_sh8601.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lvgl.h"

#include "board_pins.h"
#include "board_spi.h"
#include "board_touch.h"

static const char *TAG = "board_display";

#define LVGL_TICK_PERIOD_MS       2
#define LVGL_TASK_MAX_DELAY_MS    500
#define LVGL_TASK_MIN_DELAY_MS    1
#define LVGL_TASK_STACK_SIZE      (4 * 1024)
#define LVGL_TASK_PRIORITY        4

static SemaphoreHandle_t s_lvgl_mutex;
static esp_lcd_panel_handle_t s_panel;
static lv_disp_draw_buf_t s_draw_buffer;
static lv_disp_drv_t s_display_driver;
static lv_indev_drv_t s_touch_driver;
static lv_color_t *s_buffer_a;
static lv_color_t *s_buffer_b;

/* Status screen (Phase 1A / 1B variants): one label refreshed at a low rate
 * from a task that owns no Wi-Fi context. NULL when no screen is active. */
typedef enum {
    STATUS_SCREEN_NONE = 0,
    STATUS_SCREEN_PHASE1A,
    STATUS_SCREEN_PHASE1B,
    STATUS_SCREEN_PHASE1C,
    STATUS_SCREEN_PHASE1,
} status_screen_kind_t;

static lv_obj_t *s_status_label;
static status_screen_kind_t s_screen_kind;
static bool s_status_touch_ok;
static bool s_status_sd_ok;
static bool s_status_wifi_ok;

/* Exact initialization table used by Waveshare 08_FactoryProgram. */
static const sh8601_lcd_init_cmd_t s_lcd_init_commands[] = {
    {0xb2, (uint8_t[]){0x0c, 0x0c, 0x00, 0x33, 0x33}, 5, 0},
    {0xb7, (uint8_t[]){0x35}, 1, 0},
    {0xbb, (uint8_t[]){0x13}, 1, 0},
    {0xc0, (uint8_t[]){0x2c}, 1, 0},
    {0xc2, (uint8_t[]){0x01}, 1, 0},
    {0xc3, (uint8_t[]){0x0b}, 1, 0},
    {0xc4, (uint8_t[]){0x20}, 1, 0},
    {0xc6, (uint8_t[]){0x0f}, 1, 0},
    {0xd0, (uint8_t[]){0xa4, 0xa1}, 2, 0},
    {0xd6, (uint8_t[]){0xa1}, 1, 0},
    {0xe0, (uint8_t[]){0x00, 0x03, 0x07, 0x08, 0x07, 0x15, 0x2a, 0x44, 0x42, 0x0a, 0x17, 0x18, 0x25, 0x27}, 14, 0},
    {0xe1, (uint8_t[]){0x00, 0x03, 0x08, 0x07, 0x07, 0x23, 0x2a, 0x43, 0x42, 0x09, 0x18, 0x17, 0x25, 0x27}, 14, 0},
    {0x21, (uint8_t[]){0x21}, 0, 0},
    {0x11, (uint8_t[]){0x11}, 0, 120},
    {0x29, (uint8_t[]){0x29}, 0, 0},
};

static bool display_flush_complete(esp_lcd_panel_io_handle_t panel_io,
                                   esp_lcd_panel_io_event_data_t *event_data,
                                   void *user_context)
{
    (void)panel_io;
    (void)event_data;
    lv_disp_drv_t *driver = (lv_disp_drv_t *)user_context;
    lv_disp_flush_ready(driver);
    return false;
}

static void display_flush(lv_disp_drv_t *driver, const lv_area_t *area, lv_color_t *pixels)
{
    esp_lcd_panel_handle_t panel = (esp_lcd_panel_handle_t)driver->user_data;

    const int x1 = area->x1 + BOARD_LCD_X_OFFSET;
    const int x2 = area->x2 + BOARD_LCD_X_OFFSET;
    const int y1 = area->y1;
    const int y2 = area->y2;

    esp_lcd_panel_draw_bitmap(panel, x1, y1, x2 + 1, y2 + 1, pixels);
}

static void touch_read(lv_indev_drv_t *driver, lv_indev_data_t *data)
{
    (void)driver;

    uint16_t x = 0;
    uint16_t y = 0;
    bool pressed = false;
    const esp_err_t err = board_touch_read(&x, &y, &pressed);

    if (err == ESP_OK && pressed) {
        if (x >= BOARD_LCD_H_RES) {
            x = BOARD_LCD_H_RES - 1;
        }
        if (y >= BOARD_LCD_V_RES) {
            y = BOARD_LCD_V_RES - 1;
        }
        data->point.x = x;
        data->point.y = y;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
}

static void lvgl_tick(void *arg)
{
    (void)arg;
    lv_tick_inc(LVGL_TICK_PERIOD_MS);
}

bool board_display_lock(uint32_t timeout_ms)
{
    if (s_lvgl_mutex == NULL) {
        return false;
    }

    const TickType_t timeout = timeout_ms == BOARD_DISPLAY_WAIT_FOREVER
                                   ? portMAX_DELAY
                                   : pdMS_TO_TICKS(timeout_ms);
    return xSemaphoreTake(s_lvgl_mutex, timeout) == pdTRUE;
}

void board_display_unlock(void)
{
    if (s_lvgl_mutex != NULL) {
        xSemaphoreGive(s_lvgl_mutex);
    }
}

static void lvgl_task(void *arg)
{
    (void)arg;
    uint32_t delay_ms = LVGL_TASK_MAX_DELAY_MS;

    while (true) {
        if (board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
            delay_ms = lv_timer_handler();
            board_display_unlock();
        }

        if (delay_ms > LVGL_TASK_MAX_DELAY_MS) {
            delay_ms = LVGL_TASK_MAX_DELAY_MS;
        } else if (delay_ms < LVGL_TASK_MIN_DELAY_MS) {
            delay_ms = LVGL_TASK_MIN_DELAY_MS;
        }
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

esp_err_t board_display_init(void)
{
    esp_err_t err = board_spi_init();
    if (err != ESP_OK) {
        return err;
    }

    lv_init();

    esp_lcd_panel_io_handle_t io_handle = NULL;
    const esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = BOARD_PIN_LCD_DC,
        .cs_gpio_num = BOARD_PIN_LCD_CS,
        .pclk_hz = BOARD_LCD_PIXEL_CLOCK_HZ,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
        .on_color_trans_done = display_flush_complete,
        .user_ctx = &s_display_driver,
    };

    err = esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)BOARD_SPI_HOST,
                                   &io_config, &io_handle);
    if (err != ESP_OK) {
        return err;
    }

    const sh8601_vendor_config_t vendor_config = {
        .init_cmds = s_lcd_init_commands,
        .init_cmds_size = sizeof(s_lcd_init_commands) / sizeof(s_lcd_init_commands[0]),
    };
    const esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = BOARD_PIN_LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .bits_per_pixel = 16,
        .vendor_config = (void *)&vendor_config,
        .data_endian = LCD_RGB_DATA_ENDIAN_BIG,
    };

    err = esp_lcd_new_panel_sh8601(io_handle, &panel_config, &s_panel);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_lcd_panel_reset(s_panel);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_lcd_panel_init(s_panel);
    if (err != ESP_OK) {
        return err;
    }

    const size_t buffer_pixels = BOARD_LCD_H_RES * BOARD_LCD_DRAW_LINES;
    s_buffer_a = heap_caps_malloc(buffer_pixels * sizeof(lv_color_t), MALLOC_CAP_DMA);
    s_buffer_b = heap_caps_malloc(buffer_pixels * sizeof(lv_color_t), MALLOC_CAP_DMA);
    if (s_buffer_a == NULL || s_buffer_b == NULL) {
        free(s_buffer_a);
        free(s_buffer_b);
        s_buffer_a = NULL;
        s_buffer_b = NULL;
        return ESP_ERR_NO_MEM;
    }

    lv_disp_draw_buf_init(&s_draw_buffer, s_buffer_a, s_buffer_b, buffer_pixels);
    lv_disp_drv_init(&s_display_driver);
    s_display_driver.hor_res = BOARD_LCD_H_RES;
    s_display_driver.ver_res = BOARD_LCD_V_RES;
    s_display_driver.flush_cb = display_flush;
    s_display_driver.draw_buf = &s_draw_buffer;
    s_display_driver.user_data = s_panel;
    lv_disp_drv_register(&s_display_driver);

    if (board_touch_available()) {
        lv_indev_drv_init(&s_touch_driver);
        s_touch_driver.type = LV_INDEV_TYPE_POINTER;
        s_touch_driver.read_cb = touch_read;
        lv_indev_drv_register(&s_touch_driver);
    }

    s_lvgl_mutex = xSemaphoreCreateMutex();
    if (s_lvgl_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const esp_timer_create_args_t tick_timer_args = {
        .callback = lvgl_tick,
        .name = "lvgl_tick",
    };
    esp_timer_handle_t tick_timer = NULL;
    err = esp_timer_create(&tick_timer_args, &tick_timer);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000U);
    if (err != ESP_OK) {
        return err;
    }

    const BaseType_t task_result = xTaskCreate(lvgl_task, "lvgl", LVGL_TASK_STACK_SIZE,
                                                NULL, LVGL_TASK_PRIORITY, NULL);
    if (task_result != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "LCD/LVGL ready: SH8601 %dx%d, x-offset=%d",
             BOARD_LCD_H_RES, BOARD_LCD_V_RES, BOARD_LCD_X_OFFSET);
    return ESP_OK;
}

esp_err_t board_display_show_phase0_status(bool touch_ok, bool sd_ok)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    lv_obj_t *screen = lv_scr_act();
    lv_obj_clean(screen);
    lv_obj_set_style_bg_color(screen, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);

    lv_obj_t *label = lv_label_create(screen);
    if (label == NULL) {
        board_display_unlock();
        return ESP_ERR_NO_MEM;
    }

    lv_label_set_text_fmt(label,
                          "esp32c6-Pwnagotchi\n"
                          "\n"
                          "Phase 0\n"
                          "LCD: OK\n"
                          "Touch: %s\n"
                          "SD: %s",
                          touch_ok ? "OK" : "FAIL",
                          sd_ok ? "OK" : "FAIL");
    lv_obj_set_width(label, BOARD_LCD_H_RES - 12);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(label, lv_color_white(), 0);
    lv_obj_set_style_text_line_space(label, 5, 0);
    lv_obj_center(label);

    board_display_unlock();
    return ESP_OK;
}

/* Requires the LVGL mutex to be held. Destroys any previous screen content
 * and creates the shared status label; NULL on allocation failure. */
static lv_obj_t *status_screen_create_locked(void)
{
    s_status_label = NULL;

    lv_obj_t *screen = lv_scr_act();
    lv_obj_clean(screen);
    lv_obj_set_style_bg_color(screen, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);

    lv_obj_t *label = lv_label_create(screen);
    if (label == NULL) {
        return NULL;
    }

    lv_obj_set_width(label, BOARD_LCD_H_RES - 12);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(label, lv_color_white(), 0);
    lv_obj_set_style_text_line_space(label, 5, 0);
    lv_obj_center(label);
    s_status_label = label;
    return label;
}

/* Requires the LVGL mutex to be held. */
static void phase1a_refresh_locked(uint32_t rx_total, uint32_t rx_dropped)
{
    if (s_status_label == NULL || s_screen_kind != STATUS_SCREEN_PHASE1A) {
        return;
    }

    lv_label_set_text_fmt(s_status_label,
                          "esp32c6-Pwnagotchi\n"
                          "\n"
                          "Phase 1A\n"
                          "LCD: OK\n"
                          "Touch: %s\n"
                          "SD: %s\n"
                          "WiFi: %s\n"
                          "\n"
                          "RX: %lu\n"
                          "DROP: %lu",
                          s_status_touch_ok ? "OK" : "FAIL",
                          s_status_sd_ok ? "OK" : "FAIL",
                          s_status_wifi_ok ? "SNIFFING" : "FAIL",
                          (unsigned long)rx_total,
                          (unsigned long)rx_dropped);
}

/* Requires the LVGL mutex to be held. */
static void phase1b_refresh_locked(uint32_t rx_total, uint32_t mgmt, uint32_t data,
                                   uint32_t ctrl, uint32_t errors)
{
    if (s_status_label == NULL || s_screen_kind != STATUS_SCREEN_PHASE1B) {
        return;
    }

    lv_label_set_text_fmt(s_status_label,
                          "esp32c6-Pwnagotchi\n"
                          "\n"
                          "Phase 1B\n"
                          "LCD: OK\n"
                          "Touch: %s\n"
                          "SD: %s\n"
                          "WiFi: %s\n"
                          "\n"
                          "RX: %lu\n"
                          "MGMT: %lu\n"
                          "DATA: %lu\n"
                          "CTRL: %lu\n"
                          "ERR: %lu",
                          s_status_touch_ok ? "OK" : "FAIL",
                          s_status_sd_ok ? "OK" : "FAIL",
                          s_status_wifi_ok ? "SNIFFING" : "FAIL",
                          (unsigned long)rx_total,
                          (unsigned long)mgmt,
                          (unsigned long)data,
                          (unsigned long)ctrl,
                          (unsigned long)errors);
}

esp_err_t board_display_show_phase1a_status(bool touch_ok, bool sd_ok, bool wifi_ok)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    s_status_touch_ok = touch_ok;
    s_status_sd_ok = sd_ok;
    s_status_wifi_ok = wifi_ok;
    s_screen_kind = STATUS_SCREEN_PHASE1A;

    if (status_screen_create_locked() == NULL) {
        s_screen_kind = STATUS_SCREEN_NONE;
        board_display_unlock();
        return ESP_ERR_NO_MEM;
    }
    phase1a_refresh_locked(0, 0);

    board_display_unlock();
    return ESP_OK;
}

esp_err_t board_display_update_phase1a(uint32_t rx_total, uint32_t rx_dropped)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    phase1a_refresh_locked(rx_total, rx_dropped);

    board_display_unlock();
    return ESP_OK;
}

esp_err_t board_display_show_phase1b_status(bool touch_ok, bool sd_ok, bool wifi_ok)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    s_status_touch_ok = touch_ok;
    s_status_sd_ok = sd_ok;
    s_status_wifi_ok = wifi_ok;
    s_screen_kind = STATUS_SCREEN_PHASE1B;

    if (status_screen_create_locked() == NULL) {
        s_screen_kind = STATUS_SCREEN_NONE;
        board_display_unlock();
        return ESP_ERR_NO_MEM;
    }
    phase1b_refresh_locked(0, 0, 0, 0, 0);

    board_display_unlock();
    return ESP_OK;
}

esp_err_t board_display_update_phase1b(uint32_t rx_total, uint32_t mgmt, uint32_t data,
                                       uint32_t ctrl, uint32_t errors)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    phase1b_refresh_locked(rx_total, mgmt, data, ctrl, errors);

    board_display_unlock();
    return ESP_OK;
}

/* Requires the LVGL mutex to be held. last_ssid must already be sanitized
 * for display (printable, length-bounded) by the caller; NULL shows "-". */
static void phase1c_refresh_locked(uint32_t rx_total, uint32_t ap_unique,
                                   uint32_t ie_errors, const char *last_ssid,
                                   uint8_t channel, int8_t rssi)
{
    if (s_status_label == NULL || s_screen_kind != STATUS_SCREEN_PHASE1C) {
        return;
    }

    char info[48];
    if (last_ssid != NULL && channel != 0) {
        snprintf(info, sizeof(info), "CH %u  %ddBm", (unsigned)channel, (int)rssi);
    } else {
        strlcpy(info, "-", sizeof(info));
        last_ssid = NULL;
    }

    lv_label_set_text_fmt(s_status_label,
                          "esp32c6-Pwnagotchi\n"
                          "\n"
                          "Phase 1C\n"
                          "LCD: OK\n"
                          "Touch: %s\n"
                          "SD: %s\n"
                          "WiFi: %s\n"
                          "\n"
                          "RX: %lu\n"
                          "AP: %lu\n"
                          "IE ERR: %lu\n"
                          "Last: %s\n"
                          "%s",
                          s_status_touch_ok ? "OK" : "FAIL",
                          s_status_sd_ok ? "OK" : "FAIL",
                          s_status_wifi_ok ? "SNIFFING" : "FAIL",
                          (unsigned long)rx_total,
                          (unsigned long)ap_unique,
                          (unsigned long)ie_errors,
                          last_ssid != NULL ? last_ssid : "-",
                          info);
}

esp_err_t board_display_show_phase1c_status(bool touch_ok, bool sd_ok, bool wifi_ok)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    s_status_touch_ok = touch_ok;
    s_status_sd_ok = sd_ok;
    s_status_wifi_ok = wifi_ok;
    s_screen_kind = STATUS_SCREEN_PHASE1C;

    if (status_screen_create_locked() == NULL) {
        s_screen_kind = STATUS_SCREEN_NONE;
        board_display_unlock();
        return ESP_ERR_NO_MEM;
    }
    phase1c_refresh_locked(0, 0, 0, NULL, 0, 0);

    board_display_unlock();
    return ESP_OK;
}

esp_err_t board_display_update_phase1c(uint32_t rx_total, uint32_t ap_unique,
                                       uint32_t ie_errors, const char *last_ssid,
                                       uint8_t channel, int8_t rssi)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    phase1c_refresh_locked(rx_total, ap_unique, ie_errors, last_ssid, channel, rssi);

    board_display_unlock();
    return ESP_OK;
}

/* Requires the LVGL mutex to be held. */
static void phase1_refresh_locked(uint8_t channel, uint16_t ap_current,
                                  uint16_t sta_current, uint16_t rel_current,
                                  uint32_t rx_total, uint32_t rx_dropped)
{
    if (s_status_label == NULL || s_screen_kind != STATUS_SCREEN_PHASE1) {
        return;
    }

    /* "STA(obs)": observed MAC addresses. Randomized MACs produce one
     * record each - the number makes no physical-device claim. */
    lv_label_set_text_fmt(s_status_label,
                          "esp32c6-Pwnagotchi\n"
                          "\n"
                          "Phase 2\n"
                          "LCD: OK\n"
                          "Touch: %s\n"
                          "SD: %s\n"
                          "WiFi: %s\n"
                          "\n"
                          "CH: %u\n"
                          "AP: %u\n"
                          "STA(obs): %u\n"
                          "REL: %u\n"
                          "RX: %lu\n"
                          "DROP: %lu\n"
                          "\n"
                          "sniffing...",
                          s_status_touch_ok ? "OK" : "FAIL",
                          s_status_sd_ok ? "OK" : "FAIL",
                          s_status_wifi_ok ? "SNIFFING" : "FAIL",
                          (unsigned)channel,
                          (unsigned)ap_current,
                          (unsigned)sta_current,
                          (unsigned)rel_current,
                          (unsigned long)rx_total,
                          (unsigned long)rx_dropped);
}

esp_err_t board_display_show_phase1_status(bool touch_ok, bool sd_ok, bool wifi_ok)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    s_status_touch_ok = touch_ok;
    s_status_sd_ok = sd_ok;
    s_status_wifi_ok = wifi_ok;
    s_screen_kind = STATUS_SCREEN_PHASE1;

    if (status_screen_create_locked() == NULL) {
        s_screen_kind = STATUS_SCREEN_NONE;
        board_display_unlock();
        return ESP_ERR_NO_MEM;
    }
    phase1_refresh_locked(0, 0, 0, 0, 0, 0);

    board_display_unlock();
    return ESP_OK;
}

esp_err_t board_display_update_phase1(uint8_t channel, uint16_t ap_current,
                                      uint16_t sta_current, uint16_t rel_current,
                                      uint32_t rx_total, uint32_t rx_dropped)
{
    if (!board_display_lock(BOARD_DISPLAY_WAIT_FOREVER)) {
        return ESP_ERR_INVALID_STATE;
    }

    phase1_refresh_locked(channel, ap_current, sta_current, rel_current,
                          rx_total, rx_dropped);

    board_display_unlock();
    return ESP_OK;
}
