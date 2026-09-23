# Phase 1A - Wi-Fi Promiscuous RX

## Scope

Phase 1A adds the passive RX datapath only:

```text
ESP32-C6 Wi-Fi
      |
promiscuous RX callback (Wi-Fi driver task)
      |
static packet pool + FreeRTOS pointer queues (bounded, 24 slots)
      |
radio_rx_task (counts by driver frame type, no parsing)
      |
stats snapshot -> serial summary + LVGL status screen
```

Deliberately out of scope (Phase 1B+): beacon/probe parsing, AP/STA DB,
channel hopping, EAPOL, PCAP, agent/epoch/personality, any Wi-Fi TX.

## Component layout

- `components/radio/include/radio_types.h`: `radio_packet_t`,
  `radio_stats_t`, `RADIO_PACKET_MAX_LEN` (512), `RADIO_PACKET_POOL_SIZE` (24),
  `RADIO_DEFAULT_CHANNEL` (6).
- `components/radio/include/wifi_sniffer.h`: `wifi_sniffer_init()`,
  `wifi_sniffer_start(channel)`, `wifi_sniffer_get_stats()`.
- `components/radio/wifi_sniffer.c`: driver bring-up, RX callback, consumer
  task, stats task.
- `components/board/board_display.c`: Phase 1A status screen
  (`board_display_show_phase1a_status` / `board_display_update_phase1a`).
- `main/app_main.c`: initialization and task start only.

## Wi-Fi bring-up

Follows the official ESP-IDF v5.4 pattern (espnow example family):

```text
nvs_flash_init (erase/retry on no-free-pages / new-version)
esp_netif_init
esp_event_loop_create_default
esp_wifi_init(WIFI_INIT_CONFIG_DEFAULT())
esp_wifi_set_storage(WIFI_STORAGE_RAM)
esp_wifi_set_mode(WIFI_MODE_STA)        /* never connects */
esp_wifi_start
esp_wifi_set_promiscuous_rx_cb
esp_wifi_set_promiscuous_filter(MGMT|CTRL|DATA|MISC)
esp_wifi_set_promiscuous(true)
esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE)
```

ESP32-C6 API notes (verified against v5.4 `esp_wifi_types_native.h`):
the promiscuous RX length field is `rx_ctrl.sig_len` (12-bit, includes FCS),
metadata provides `rx_ctrl.rssi` and `rx_ctrl.channel`. `WIFI_INIT_CONFIG_DEFAULT()`
cannot be used as a static initializer (`&g_wifi_osi_funcs` is an incomplete
type at that point), so the config struct is initialized at runtime.

## RX dataplane guarantees

- Callback runs in the Wi-Fi driver task and only: reads metadata, copies at
  most `RADIO_PACKET_MAX_LEN` bytes from `sig_len`-bounded length into a pooled
  buffer, sends one pointer to the queue. No LVGL, no SD, no printf, no malloc,
  no blocking. `sig_len` is a 12-bit field, so the copy bound can never be
  bypassed by a corrupt length.
- Fixed capacity: 24 statically allocated `radio_packet_t` slots (~12.5 KB
  .bss). Free-slot queue + filled queue, both of depth 24. No dynamic memory
  in the RX path.
- Queue full: the packet is dropped and recycled immediately; `rx_dropped++`.
- Oversized frames: stored truncated at 512 bytes, `rx_truncated++`.
- Counters are guarded by a spinlock critical section; the snapshot API is
  safe to call from any task.

## Serial output

`radio_stat` task prints every 3 s:

```text
I (58031) RADIO: rx=1003 queued=1003 processed=1003 drop=0 trunc=3 mgmt=958 data=45 ctrl=0 misc=0 q=0/1 heap=204072 min_heap=198852
```

`q=current/peak` is the RX queue occupancy; heap watermarks are included to
watch for leaks.

## UI

The Phase 0 status page was extended to the Phase 1A page: `Touch` / `SD`
lines plus `WiFi: SNIFFING`, `RX:` and `DROP:` counters. LVGL is refreshed at
2 Hz by a dedicated task from a stats snapshot; the Wi-Fi callback never
touches LVGL.

## Partition table

Wi-Fi support grows the app to ~1.11 MB, past the default 1 MB factory
slot. `partitions.csv` gives the factory app 4 MB of the 8 MB flash
(`CONFIG_PARTITION_TABLE_CUSTOM`); nvs/phy_init keep the standard placement.

## On-target acceptance

Firmware commit `c809b9b042bacff6e5cbbda0780ed8d8294f1446`
(GitHub Actions run 35874811166, artifact `firmware-c809b9b...`).

Boot (docs/logs/phase1a_boot_c809b9b.log):

```text
I (432) phase1a: firmware git commit: c809b9b...
I (446..924) Phase 0 board inits all OK (backlight/I2C/touch/SPI/LCD-LVGL/SD write+read+verify)
I (935..1030) wifi driver init + RADIO pool ready (pool=24 pkts x 520 B)
I (1194) RADIO: promiscuous RX started on channel 6
I (1202) phase1a: Phase 1A ready: LCD=OK I2C=OK Touch=OK SD=OK WiFi=SNIFFING
```

Stability run (docs/logs/phase1a_stability_1min_c809b9b.log, 60 s from fresh
boot; longer 10-15 min soak deferred per maintainer request):

```text
I (4031)  RADIO: rx=62   queued=62   processed=62   drop=0 trunc=0 ... heap=204072 min_heap=198852
I (58031) RADIO: rx=1003 queued=1003 processed=1003 drop=0 trunc=3 mgmt=958 data=45 ctrl=0 ... heap=204072 min_heap=198852
```

Across all captured sessions with this build (~5 min total runtime) the
console shows no Guru Meditation, no task watchdog, no reboot, and a flat
heap line (204068-204072 free, minimum 198852). RX rate on channel 6 in the
test environment was ~17 pps with `queued == processed == rx` at all times
and queue peak of 1.

## Phase 1A Test Report

```text
Phase 1A Test Report

Firmware commit:       c809b9b042bacff6e5cbbda0780ed8d8294f1446 (c809b9b)
GitHub Actions run:    35874811166 (ESP-IDF Build, success, v5.4 / esp32c6)
Artifact:              firmware-c809b9b042bacff6e5cbbda0780ed8d8294f1446.zip

Promiscuous init:      PASS
RX callback:           PASS
Queue:                 PASS
Consumer task:         PASS
Phase 0 regression:    PASS (serial: LCD/LVGL/Touch/SD all OK; visual screen check pending user)
Stability:             PASS (1-minute gate per maintainer request; 10-15 min soak deferred)

RX total:              1003 (60 s run, channel 6, ~17 pps)
RX queued:             1003
RX processed:          1003
RX dropped:            0
RX truncated:          3
Free heap:             204072 bytes (flat)
Minimum free heap:     198852 bytes

Fixed issues:
- WIFI_INIT_CONFIG_DEFAULT() is not a valid static initializer -> runtime init
- default 1 MB factory partition too small -> custom partitions.csv (4 MB app)

Remaining issues:
- none blocking Phase 1A; longer soak and on-screen visual confirmation of the
  Phase 1A page deferred to the maintainer

Phase 1A: PASS
```

## Next phase (not started)

Phase 1B: 802.11 Frame Control inspection, management/data/control subtype
classification, beacon/probe parsing.
