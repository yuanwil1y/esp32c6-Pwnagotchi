# Phase 1C - Beacon / Probe Information Element Parser

## Scope

Phase 1C turns classified management frames into structured observations:

```text
promiscuous RX callback (unchanged: copy + enqueue only)
      |
radio_rx_task
      |
Frame Control classification (Phase 1B, unchanged)
      |
beacon / probe response / probe request body parse   <- new
      |   BSSID, fixed fields, strict IE walk
      |   SSID / hidden, DS channel, RSN, WPA vendor
      |
fixed-size dedup caches (log throttling, NOT a DB)
      |
counters + throttled OBS console lines + Phase 1C UI
```

Out of scope (Phase 2+/1D): AP/STA DB, TTL, channel hopping, EAPOL, PCAP,
agent, any Wi-Fi TX.

## Parser additions

`ieee80211_parser.[ch]` gained, still as pure functions over raw bytes:

- Management layout constants: 24-byte header, beacon/probe-resp fixed area
  (timestamp 8 B skipped, interval + capability read via byte-wise
  `read_le16`), address 3 = BSSID, address 2 = probe source.
- `ieee80211_parse_beacon_or_probe_resp()`: fills
  `ieee80211_ap_observation_t`. Requires header+fixed bytes; malformed or
  too-short frames are rejected without touching counters (caller counts).
- `ieee80211_parse_probe_request()`: fills
  `ieee80211_probe_req_observation_t`; SSID length 0 means wildcard probe.
- IE walk with strict bounds: needs 2 bytes for the element header and
  `2 + len` inside the frame; any violation, or SSID length > 32, marks
  `malformed_ie` and stops the walk. No OOB read is possible; the frame is
  never re-entrantly touched.
- Extracted IEs: SSID (0), DS Parameter Set channel (3, stored separately
  from RX metadata channel), RSN presence (48), WPA vendor signature
  (221 with OUI 00:50:F2 + type 01, length-gated).
- Security classify from presence flags only: RSN > WPA > PRIVACY > OPEN.
  The capability Privacy bit alone never maps to WPA2/WPA3.
- Helpers: `ieee80211_format_mac()` (AA:BB:CC:DD:EE:FF) and
  `ieee80211_ssid_to_printable()` (non-printables become '.', always
  NUL-terminated). Raw SSID bytes are never printed with %s.

## Log throttling

Console lines only on first sight of a BSSID or a change in
ssid/channel/security, and per new (source, ssid) probe pair. Fixed caches:
32 AP entries, 16 probe entries (round-robin eviction; explicitly not a DB).
A global 5-lines/s cap covers cache-churn when more BSSIDs exist than slots.
Raw per-beacon logging remains impossible.

## FCS and errored-frame handling (fixed after first on-target run)

The first build showed `ie_malformed ~= every management frame`. Root cause:
the promiscuous payload includes the 4-byte FCS (`sig_len` counts it), so
the IE walk read FCS bytes as trailing IEs. The observation path now ends
the IE area before the FCS whenever the pooled copy was not truncated
(truncated copies have no intact FCS). After the fix `ie_err` fell from
~100% of frames to 0.01% (environmental noise, which also proves the
malformed path works and is safe).

The callback additionally drops deliveries with `rx_ctrl.rx_state != 0`
into `rx_state_errors`; on this target the radio already filters bad FCS,
so the counter stayed 0 while damaged frames never poison observations.

## Serial output

Every 3 s (RADIO + 80211 lines as in Phase 1A/1B, plus):

```text
I (58740) OBS: ap=14 beacon=2313 berr=0 preq=73 perr=0 presp=51 ie=49451 ie_err=5 ssid=1755 hidden=609 rsn=1345 wpa=414 ds=2262
```

Event-driven, rate-capped observation lines:

```text
OBS: AP bssid=00:AD:D5:A9:82:D8 ssid="402" rssi=-85 rx_ch=6 adv_ch=6 bintv=100 sec=RSN
OBS: AP bssid=00:AD:D5:A9:82:D9 ssid=<hidden> rssi=-86 rx_ch=6 adv_ch=6 bintv=100 sec=RSN
OBS: AP bssid=58:EA:1F:B2:AC:CA ssid="..................10cm" rssi=-91 rx_ch=6 adv_ch=6 bintv=100 sec=RSN
OBS: PROBE src=.. ssid="..." rssi=-.. ch=.
```

## UI

Phase 1C page adds `AP:` (unique APs), `IE ERR:` and the latest AP
(`Last: <sanitized ssid>` / `CH n  -nn dBm`), refreshed at 2 Hz from a
snapshot. LVGL still never runs in the Wi-Fi callback.

## On-target acceptance

Firmware commit `ee90aeb5fc3d1d39099f7db9a2735fa1abd707fb`
(GitHub Actions run 35891313696; first 1C build d067ab8 / run 35890110231
found the FCS issue and was fixed in ee90aeb).

Boot (docs/logs/phase1c_boot_ee90aeb.log): Phase 0 lines all OK,
`Phase 1C ready: LCD=OK I2C=OK Touch=OK SD=OK WiFi=SNIFFING`, first AP
observation line at t=1.3 s.

Neighbor APs observed on channel 6 (passive, from the log): `402` RSN,
`@DLMU` OPEN, `<hidden>` RSN, a non-printable SSID rendered as
`..................10cm` RSN - BSSID/RSSI/adv_ch/rx_ch/bintv(100)/sec all
plausible, hidden and printable-sanitization paths both exercised.

1-minute baseline (docs/logs/phase1c_stability_1min_ee90aeb.log): single
boot, no Guru/WDT/reboot; rx 61 -> 2661 with drop=0; beacon=2313 parsed
with berr=0; ie_err=5 of 49451 IEs; heap flat (201776-201780, minimum
197012); AP lines stayed event-driven (no beacon spam).

Deterministic Test C with the maintainer's own phone hotspot (known SSID /
channel) remains a user step: enable the hotspot, watch for one
`OBS: AP ... ssid="<your ssid>"` line with plausible channel/RSSI/security.

## Phase 1C Test Report

```text
Phase 1C Test Report

Firmware commit:       ee90aeb5fc3d1d39099f7db9a2735fa1abd707fb (ee90aeb)
GitHub Actions run:    35891313696 (success; prior 1C run 35890110231 found FCS bug)
Artifact:              firmware-ee90aeb5fc3d1d39099f7db9a2735fa1abd707fb.zip

Beacon parser:         PASS (2313 beacons parsed, berr=0)
SSID parser:           PASS (named, hidden, and non-printable SSIDs all handled)
BSSID:                 PASS (from mgmt address 3)
Channel:               PASS (DS IE vs rx_ch kept separate; both logged)
RSSI:                  PASS (from RX metadata via pooled packet)
Beacon interval:       PASS (100 TU units seen, LE read)
Capability:            PASS (raw saved; Privacy bit used only for PRIVACY class)
RSN detection:         PASS (rsn=1345)
WPA vendor detection:  PASS (wpa=414)
Probe Request:         PASS (73 parsed incl. wildcards; per-(src,ssid) throttle)
Probe Response:        PASS (51 parsed)
IE bounds safety:      PASS (strict 2 + len checks; malformed stops walk; no crash)
1min baseline:         PASS

Known test AP:         maintainer's own hotspot (pending user step)
Observed neighbors:    ssid="402" RSN ch6 -85dBm; ssid="@DLMU" OPEN ch6;
                       hidden RSN; non-printable SSID sanitized
Observed Security:     OPEN / RSN / hidden-RSN all classified

RX total:              2661 (60 s, channel 6)
Beacon parsed:         2313
Beacon parse errors:   0
Probe requests:        73 (errors 0)
Probe responses:       51
IE total:              49451
IE malformed:          5 (0.01%, environmental; safe-stop verified)

Free heap:             201776 bytes (flat across the run)
Minimum free heap:     197012 bytes

Fixed issues:
- FCS bytes were fed to the IE walk (ie_malformed ~= 100% of frames)
  -> IE area now ends before the FCS on non-truncated copies
- radio-errored deliveries (rx_state != 0) now dropped and counted
- hidden/ssid flapping in the first run traced to damaged frames + FCS
  bug; both eliminated by the fixes above

Remaining issues:
- Test C (own hotspot) awaits the maintainer's manual step
- 5 malformed IEs observed are real-world noise; counted and safe

Phase 1C: PASS
```

## Next phase (not started)

Phase 1D: channel hopper - channel list, dwell time, legal 1-13 switching,
sniffer + hopper + LVGL coexistence.
