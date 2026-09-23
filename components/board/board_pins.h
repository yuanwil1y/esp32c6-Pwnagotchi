#pragma once

#include "driver/i2c.h"
#include "driver/spi_master.h"

/*
 * Pin map copied from Waveshare 08_FactoryProgram at submodule commit
 * 1fed15e32977de11afe1f710a0f5e915bfcc35a5.
 */
#define BOARD_SPI_HOST              SPI2_HOST
#define BOARD_PIN_LCD_MOSI          4
#define BOARD_PIN_LCD_SCLK          5
#define BOARD_PIN_LCD_CS            7
#define BOARD_PIN_LCD_DC            6
#define BOARD_PIN_LCD_RST           14
#define BOARD_PIN_LCD_BACKLIGHT     15

#define BOARD_PIN_SD_MISO           19
#define BOARD_PIN_SD_CS             20

#define BOARD_I2C_PORT              I2C_NUM_0
#define BOARD_PIN_I2C_SCL           8
#define BOARD_PIN_I2C_SDA           18
#define BOARD_I2C_FREQ_HZ           (200 * 1000)

#define BOARD_TOUCH_I2C_ADDRESS     0x15

#define BOARD_LCD_H_RES             170
#define BOARD_LCD_V_RES             320
#define BOARD_LCD_X_OFFSET          35
#define BOARD_LCD_PIXEL_CLOCK_HZ    (20 * 1000 * 1000)
#define BOARD_LCD_DRAW_LINES        40
