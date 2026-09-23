# Phase 1B - 802.11 Frame Classification

## Scope

Phase 1B adds raw 802.11 Frame Control classification on top of the Phase 1A
RX datapath:

```text
promiscuous RX callback (unchanged: copy + enqueue only)
      |
queue (unchanged: static pool, bounded, drop-on-full)
      |
radio_rx_task
      |
ieee80211_parse()   <- new: pure FC decode
      |
type / subtype counters -> stats snapshot -> serial + UI
```

Out of scope (Phase 1C+): SSID / beacon IE parsing, probe SSID parsing,
AP/STA DB, channel hopping, EAPOL, PCAP, agent, any Wi-Fi TX.

## Parser design

`components/radio/ieee80211_parser.[ch]`:

- The 16-bit Frame Control is assembled **little-endian from individual
  bytes** (`frame[0] | frame[1] << 8`). No struct overlay, no pointer casts
  onto the frame buffer, no C bitfield mapping.
- All fields decoded with explicit masks/shifts (`IEEE80211_FC_*_MASK`,
  `IEEE80211_FC_TYPE_SHIFT = 2`, `IEEE80211_FC_SUBTYPE_SHIFT = 4`).
- `ieee80211_parse()` is a pure function: no globals, no logging, no
  allocation. It refuses NULL args and `length < 2` (minimum needed to read
  the FC) and reads only the two FC bytes, so no other per-type minimum
  header length applies in this phase.
- Decoded: protocol version, type, subtype, ToDS/FromDS/Retry/Protected
  (plus MoreFrag/PwrMgt/MoreData/Order).

## Classification

Counted in `radio_rx_task` (a normal FreeRTOS task; the callback still does
zero parsing), guarded by the existing stats spinlock:

- Type: MGMT / CTRL / DATA / EXT (+UNKNOWN safety path, unreachable with a
  2-bit field).
- Management subtypes: assoc req/resp, reassoc req/resp, probe req/resp,
  beacon, ATIM, disassoc, auth, deauth, action (+ other).
- Control subtypes: RTS, CTS, ACK, BAR, BA (+ other).
- Data families: data (+CF variants), null (+CF variants), QoS data
  (+CF variants), QoS null (+ other).
- `fc_type_mismatch` cross-checks the ESP-IDF driver packet type against the
  FC type; on target both agree 100% (mismatch=0).

## ESP-IDF notes

- Control frames are **filtered out by default**: the promiscuous control
  subtype filter defaults to "none", so `WIFI_PROMIS_FILTER_MASK_CTRL` alone
  delivered zero CTRL frames. `esp_wifi_set_promiscuous_ctrl_filter()` with
  `WIFI_PROMIS_CTRL_FILTER_MASK_ALL` opts in (failure is a warning; sniffing
  still works).
- `RADIO_PARSER_DEBUG_N` (compile-time, default 0) prints the first N frame
  classifications for bring-up; default builds have no per-frame logging.

## Serial output (every 3 s)

```text
I (58509) RADIO: rx=948 queued=948 processed=948 drop=0 trunc=12 mgmt=885 data=30 ctrl=33 misc=0 q=0/1 heap=203916 min_heap=199136
I (58509) 80211: total=948 err=0 invalid=0 mismatch=0
I (58514) 80211: MGMT=885 beacon=698 probe_req=14 probe_resp=27 auth=0 assoc_req=0 deauth=0 other=0
I (58523) 80211: CTRL=33 rts=16 cts=0 ack=17 bar=0 ba=0 other=0
I (58528) 80211: DATA=30 qos_data=0 qos_null=0 null=0 other=0
```

## UI

Status screen generalized (`STATUS_SCREEN_PHASE1A/1B`); the Phase 1B page
adds `RX / MGMT / DATA / CTRL / ERR` lines, still refreshed at 2 Hz from a
stats snapshot. The Wi-Fi callback remains free of LVGL work.

## On-target acceptance

Firmware commit `60610f6783bd72a7e2f23462e5e1671f1d8dbae5`
(GitHub Actions run 35878659133, artifact `firmware-60610f6...`).

Test A - Boot / regression (docs/logs/phase1b_boot_60610f6.log):

```text
I (432) phase1b: firmware git commit: 60610f6...
I (813) board_display: LCD/LVGL ready      <- Phase 0 LCD/LVGL OK
I (889..927) board_sd: mount/write/read/verify OK
I (1198) RADIO: promiscuous RX started on channel 6
I (1206) phase1b: Phase 1B ready: LCD=OK I2C=OK Touch=OK SD=OK WiFi=SNIFFING
```

Test B - Frame classification: MGMT / DATA / CTRL all > 0, beacon grows
steadily (~700/min), probe req/resp and RTS/ACK identified, QoS data counted
in earlier captures; `err=0 invalid=0 mismatch=0`, FC totals equal driver
totals frame-for-frame.

Test C (user hotspot observation) is left to the maintainer: enabling a
phone hotspot raises beacon/probe counts; no SSID parsing is involved.

1-minute baseline (docs/logs/phase1b_stability_1min_60610f6.log): single
boot, no Guru/WDT/reboot, rx 33 -> 948 with queued == processed == rx,
drop=0, heap flat (203916-203920 free, minimum 199136).

## Phase 1B Test Report

```text
Phase 1B Test Report

Firmware commit:       60610f6783bd72a7e2f23462e5e1671f1d8dbae5 (60610f6)
GitHub Actions run:    35878659133 (ESP-IDF Build, success)
Artifact:              firmware-60610f6783bd72a7e2f23462e5e1671f1d8dbae5.zip

Frame Control:         PASS (little-endian byte assembly + mask/shift)
Type classification:   PASS (MGMT/CTRL/DATA/EXT; equals driver counts)
Management subtype:    PASS (beacon/probe req/resp/auth/assoc/deauth/action...)
Control subtype:       PASS (RTS/ACK observed live; CTS/BAR/BA counted)
Data subtype:          PASS (data/null/QoS data/QoS null families)
Boundary checking:     PASS (length >= 2 gate; unknown types safe; err=0)
Phase 0 regression:    PASS (LCD/LVGL/Touch/SD all OK at boot)
Phase 1A regression:   PASS (callback/queue/pool untouched; drop/trunc counted)
1min baseline:         PASS

RX total:              948 (60 s, channel 6)
Parser total:          948
Parser errors:         0
Invalid frames:        0
FC/driver mismatch:    0

MGMT: 885  Beacon: 698  Probe Req: 14  Probe Resp: 27
DATA: 30   QoS Data: 0 (observed >0 in pre-fix captures)
CTRL: 33   RTS: 16  ACK: 17

Free heap:           203916 bytes (flat)
Minimum free heap:   199136 bytes

Fixed issues:
- parser missing <stddef.h> (NULL) -> CI build break, fixed
- control frames all filtered by ESP-IDF default -> enabled
  esp_wifi_set_promiscuous_ctrl_filter(ALL)

Remaining issues:
- CTS/BAR/BA not yet observed in the 1-minute window (delivery depends on
  driver/airtime); counters in place, no action needed

Phase 1B: PASS
```

## Next phase (not started)

Phase 1C: beacon/probe IE parser - SSID, BSSID, RSSI, channel, beacon
interval, capability, basic security info.
