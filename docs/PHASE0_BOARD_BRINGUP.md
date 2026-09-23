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

`sdkconfig.defaults` enables `CONFIG_FATFS_LFN_HEAP` because the acceptance
test file name `phase0_test.txt` is longer than 8.3. The factory baseline
ships with long filenames disabled and only ever wrote `test.txt`, so it
never hit this.

## Hardware acceptance test

With an SD card inserted, the expected screen is:

```text
esp32c6-Pwnagotchi

Phase 0
LCD: OK
Touch: OK
SD: OK
```

The SD self-test writes and reads `/sd_card/phase0_test.txt` with the content
`esp32c6-Pwnagotchi phase0`, logging `SD mount/write/read/verify: OK` steps
separately on the serial console. Touching the panel produces `board_touch`
coordinate logs. A missing SD card only downgrades the on-screen SD status;
it must not crash the firmware.

## Phase 0 acceptance record (2026-09-23)

Verified on target hardware (ESP32-C6FH8, 8 MB embedded flash, USB-Serial/JTAG
on the Waveshare ESP32-C6-Touch-LCD-1.9):

- Firmware commit `1a8ed2bce809553d769388cbb26763414c701399`, built by
  GitHub Actions (ESP-IDF v5.4) and flashed via `esptool write-flash` at
  0x0/0x8000/0x10000 from the CI `flasher_args.json`.
- Boot: clean start, no reboot loop, no Guru Meditation, no watchdog reset.
- LCD/LVGL: SH8601 170x320 with x-offset 35 renders correctly (visually
  confirmed), LVGL task refreshes continuously.
- Touch: five-point check (top-left, top-right, center, bottom-left,
  bottom-right) produced correct, un-mirrored, in-range coordinates.
- I2C: 200 kHz bus with CST78x touch at 0x15 responds.
- SD: mount/write/read/verify all OK on a 972 MB SDSC card.
- Backlight: lit from boot (inverted PWM, duty 0 = full on), 80% setting OK.
- 60 s stability monitor after boot: zero errors, zero resets.

Issues found and fixed during on-target acceptance:

1. CI workflow had no artifact upload; it now publishes `firmware.zip`
   (bootloader, partition table, app, flash_args, flasher_args.json) plus the
   raw flash files, and stamps the git SHA into the firmware.
2. SD self-test used `/sdcard/phase0.txt`; aligned to `/sd_card/phase0_test.txt`
   with the specified content and separate mount/write/read/verify logs.
3. Backlight initialized to duty 255 (off, inverted logic); now initializes to
   duty 0 so the panel is lit from boot like the factory program.
4. Writing `phase0_test.txt` failed with EINVAL until FATFS long filenames
   were enabled (see note above).
