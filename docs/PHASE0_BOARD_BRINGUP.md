# Phase 0 - Board Bring-up

## Reference baseline

Hardware: **Waveshare ESP32-C6-Touch-LCD-1.9**.

The project keeps the Waveshare repository read-only as the `vendor/waveshare` submodule. Phase 0 was extracted from:

`vendor/waveshare/02_Example/ESP-IDF/08_FactoryProgram`

Pinned submodule commit used while extracting the board parameters:

`1fed15e32977de11afe1f710a0f5e915bfcc35a5`

## Reused hardware details

- SPI2 LCD bus: MOSI GPIO4, SCLK GPIO5, CS GPIO7, DC GPIO6, reset GPIO14.
- SH8601 panel configuration: RGB565, big-endian pixel data, 20 MHz pixel clock.
- Waveshare SH8601 initialization command table.
- Native 170x320 orientation and the 35-pixel LCD X offset used by the factory example.
- Touch controller on I2C0, SDA GPIO18, SCL GPIO8, 200 kHz, address `0x15`.
- SD card on the same SPI2 bus, MISO GPIO19 and CS GPIO20.
- Backlight PWM on GPIO15, 50 kHz, 8-bit, inverted duty behavior.
- LVGL 8.3.11 and a 2 ms LVGL tick.

The Phase 0 implementation intentionally reduces the LVGL DMA draw buffer from the factory program's half-screen buffer to 40 lines per buffer. This does not alter panel timing or pin mapping and preserves RAM for later Wi-Fi/parser work.

## Deliberately omitted factory functions

Phase 0 does not include the Factory UI, Wi-Fi scan demo, BLE scan, WS2812/RGB test, clock demo, QMI8658 IMU demo, ADC demo, key/test-pin factory checks, or manufacturing test state machine.

## Runtime layout

- `components/board/board_spi.c`: one shared SPI2 bus for LCD and SD.
- `components/board/board_display.c`: SH8601, LVGL display driver, LVGL tick and dedicated LVGL FreeRTOS task.
- `components/board/board_touch.c`: CST78x-compatible touch probe/read path.
- `components/board/board_sd.c`: SDSPI mount and read/write self-test.
- `components/board/board_i2c.c`: board I2C0 setup and register transactions.
- `components/board/board_backlight.c`: logical 0-100% backlight control.
- `main/app_main.c`: initialization order and Phase 0 status aggregation only.

## Build

Use ESP-IDF 5.4.x, matching the Waveshare FactoryProgram development environment:

```bash
idf.py set-target esp32c6
idf.py build
idf.py -p <PORT> flash monitor
```

The first configure/build downloads managed dependencies declared by `components/board/idf_component.yml`.

## Hardware acceptance test

With an SD card inserted, the expected screen is:

```text
esp32c6-Pwnagotchi

Phase 0
LCD: OK
Touch: OK
SD: OK
```

The SD self-test writes and reads `/sdcard/phase0.txt`. Touching the panel should produce `board_touch` coordinate logs on the serial console.
