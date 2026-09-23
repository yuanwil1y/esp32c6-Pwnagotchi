idf_component_register(
    SRCS
        "board_spi.c"
        "board_i2c.c"
        "board_touch.c"
        "board_sd.c"
        "board_backlight.c"
        "board_display.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES
        driver
        esp_lcd
        esp_timer
        fatfs
        sdmmc
)
