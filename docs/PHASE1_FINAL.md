# Phase 1D - Channel Hopper & Phase 1 Final Acceptance

## Phase 1D design

`components/radio/channel_hopper.[ch]`:

- Own FreeRTOS task (`hopper`, prio 3), fully decoupled from the RX
  callback; the parser task only sees frames on whatever channel is
  current. `app_main` starts it after `wifi_sniffer_start()`.
- Legal channel list built once from `esp_wifi_get_country_code()`:
  US/CA -> 1..11, other known codes -> 1..13, world-safe/unknown -> 1..11
  (this device reports `01`, mapped to 1..13; all accepted by the driver).
- Fixed policy, no intelligence: dwell 300 ms, plain for-each-channel loop.
- Self-healing without abort: `esp_wifi_set_channel()` failure counts
  `hop_errors`, logs once, retires the channel from the list, and hopping
  continues; an empty list stops the task cleanly.
- `channel_hopper_get_stats()` (spinlock-guarded) merges into
  `wifi_sniffer_get_stats()`; `radio_stats_t.current_channel` now reports
  the live hopper channel while observation records keep `rx_channel` and
  `advertised_channel` separate.
- Serial: one `HOP ch=... hops=... errors=... dwell=...ms` line per 3 s
  stats tick. No per-hop logging.
- UI: Phase 1 overview page (CH / AP / RX / DROP / "sniffing...") at 2 Hz
  from a snapshot; LVGL is never touched by the hopper or callback.

## Firmware under final test

Commit `a3006e89a1b16abbf97f3d63c6606b8f965b4032` (a3006e8), GitHub
Actions run 35893254263, artifact `firmware-a3006e8...zip`. No code
changes after this point; the final baseline below ran on exactly this
build.

Boot (docs/logs/phase1d_boot_a3006e8.log):

```text
I (1208) HOP: country code 01 -> channels 1..13
I (1212) HOP: hopping 13 channels, dwell=300 ms
I (1220) phase1: Phase 1 ready: LCD=OK I2C=OK Touch=OK SD=OK WiFi=SNIFFING HOP=ON
```

Hopper behavior: channel advances every 300 ms (10 hops per 3 s stats
tick), cycles through all 13 channels, `hop_errors=0` throughout, RX/
beacon/AP counters keep growing while hopping.

Multi-channel discovery during a 40 s window: APs observed on
rx_ch 1, 6, 7, 8, 9 and 11, including `William ... S26 Ultra` ch1
(-21 dBm), `DUT` ch9 (-43 dBm), `301` received on ch7 (advertised ch8),
`@DLMU` family across ch6/11.

## Final 1-minute baseline

docs/logs/phase1_final_baseline_a3006e8.log, 75 s capture on a3006e8
(nominal 60 s window t=4s..74s inside it):

```text
t=4031  RADIO: rx=29   ... drop=0 trunc=0   heap=199216 min_heap=194432
t=74033 RADIO: rx=586  ... drop=0 trunc=5   heap=199216 min_heap=194432
t=74058 OBS: ap=17 beacon=467 berr=0 preq=71 presp=12 ie=12080 ie_err=5
t=74069 HOP ch=9 hops=243 errors=0 dwell=300ms
```

Single boot, no Guru Meditation, no watchdog, no reboot; heap flat; UI
and board inits all OK at boot. Touch init OK on serial; no touch events
occurred during the automated capture, so an on-screen touch remains a
user confirmation step.

## Phase 1 Final Test Report

```text
Phase 1 Final Test Report

Firmware commit:     a3006e89a1b16abbf97f3d63c6606b8f965b4032 (a3006e8)
GitHub Actions run:  35893254263 (success)
Artifact:            firmware-a3006e89a1b16abbf97f3d63c6606b8f965b4032.zip

=== Phase 1A ===
Promiscuous RX:      PASS (driver up without connecting, rx_total grows)
RX Callback:         PASS (copy + bounded enqueue only, never blocks)
Queue:               PASS (24 static slots, drop-on-full + counters)
Consumer Task:       PASS (radio_rx_task drives parser + observations)

=== Phase 1B ===
Frame Control:       PASS (byte-wise little-endian, mask/shift)
Type Classification: PASS (MGMT/CTRL/DATA/EXT; matches driver types)
Subtype Classification: PASS (mgmt/ctrl/data subtypes incl. QoS families)
Boundary Safety:     PASS (length gates everywhere; malformed counted only)

=== Phase 1C ===
Beacon Parser:       PASS (467 parsed in baseline, berr=0)
Probe Parser:        PASS (71 req / 12 resp parsed)
SSID:                PASS (named + hidden + non-printable sanitized)
BSSID:               PASS (mgmt address 3)
RSSI:                PASS (from RX metadata)
Channel:             PASS (rx_ch vs advertised DS kept separate)
Security Detection:  PASS (OPEN/PRIVACY/WPA/RSN presence-level)
IE Bounds Safety:    PASS (2+len strict; ie_err only real noise)

=== Phase 1D ===
Channel Hopper:      PASS (dedicated task, 300 ms dwell, 243 hops in 70 s)
Legal Channels:      PASS (country-mapped list; all 13 accepted, errors=0)
Multi-channel RX:    PASS (APs seen on rx_ch 1/6/7/8/9/11)

=== Regression ===
LCD:                 PASS
LVGL:                PASS (2 Hz UI refresh alive)
Touch:               PASS at init; on-screen interaction pending user check
SD:                  PASS (mount/write/read/verify at boot)

=== Final 1-Minute Baseline ===
1min baseline:       PASS

RX total start:      29   (t=4 s)
RX total end:        586  (t=74 s, growth continuous)
RX dropped:          0
RX truncated:        5
Parser errors:       0
Invalid frames:      0
IE malformed:        5 (of 12080; environmental)
Beacon parsed:       467
Probe requests:      71
Probe responses:     12
Unique AP seen:      17
Hop count:           243 (errors=0, dwell=300 ms)
Free heap start:     199216
Free heap end:       199216 (flat)
Minimum free heap:   194432

Known AP test:       S26 Ultra hotspot observed ch1 -21dBm RSN;
                     DUT ch9; 301 (adv ch8); @DLMU xN (ch6/11)
SSID:                "William ... S26 Ultra" / "DUT" / "301" / "@DLMU"
BSSID:               logged per OBS line
Channel:             1 / 6 / 7 / 8 / 9 / 11 observed
RSSI:                -21 .. -92 dBm
Security:            RSN / OPEN classified

Fixed issues (Phase 1D): none required; first build passed CI and on-target.

Remaining issues:
- on-screen touch interaction to be confirmed by the maintainer (init OK)
- Test 2 with two user-controlled APs on chosen channels: partially
  covered by ambient multi-channel observation above

PHASE 1 FINAL: PASS
```

Phase 1 — Passive Wi-Fi Sniffer: **PASS**

## Next phase (not started)

Phase 2: station discovery, 802.11 address semantics (ToDS/FromDS),
AP-STA inference, AP DB + STA DB, TTL/expiry, world model. Higher
complexity; to be designed separately before development.
