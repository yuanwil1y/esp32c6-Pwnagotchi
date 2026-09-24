# Phase 3A — Passive EAPOL observation

This stage adds receive-time metadata, a bounded parser view, and read-only
EAPOL observations in `radio_rx_task`. It does not add PCAP/SD writes, session
reassembly, M1–M4 inference, password recovery or verification, active scans,
transmissions, deauthentication, hopping changes, or Agent/UI restructuring.

## Baseline and handoff

- Repository: `yuanwil1y/esp32c6-Pwnagotchi`.
- Actual starting commit: `fac52dd251d6f8c48b866a84381db0a2352ae2e5` on
  `main`, fast-forwarded from the refreshed remote. This commit contains the
  completed Phase 2 World Model and the Phase 2.5 review fixes; the historical
  `phase2-world-model` branch is not used as the new base.
- Repository instructions: no `AGENTS.md` was present in the repository at
  start.
- Phase 2.5 software baseline: GitHub Actions [run 35965566695](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35965566695)
  passed host regression tests in plain and ASan/UBSan modes (101 assertions)
  and the ESP-IDF v5.4 / ESP32-C6 build. The Phase 2.5 document records the
  one-minute hardware smoke test as pending; it is not promoted to PASS here.
- Phase 3A start SHA: `fac52dd251d6f8c48b866a84381db0a2352ae2e5`.
- Phase 3A CI result: final implementation source SHA
  `5336ac7666371e198b8bb0be9e65deda38b1bcf2` passed GitHub Actions run
  [35972440421](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35972440421).
  The run retains the original job logs and uploaded firmware/flash artifacts.
- Hardware passive observation: **PENDING**. No authorized AP/client natural
  connection capture was performed in this stage; no hardware result is
  inferred from offline fixtures or CI.

## RX and capture-view contract

`promiscuous_rx_cb` samples `esp_timer_get_time()` at callback entry and passes
the 64-bit microsecond value through `rx_frame_view_t` into the packet-pool
slot. It is never replaced by parser dequeue or later storage time. ESP-IDF
v5.4 documents this API as fast, lock-free, microsecond-accurate, and usable
from task and ISR contexts: [ESP Timer API](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32c6/api-reference/system/esp_timer.html).
The Wi-Fi callback runs in driver task context and remains limited to time
sampling, bounded copy, metadata transfer, queue operations, and existing
small RX accounting. The timestamp is copied for every packet, including a
reused slot.

`rx_capture_view_t` provides a read-only byte pointer and copied values for:

- captured and original MAC lengths, both excluding FCS;
- RX channel, RSSI, and monotonic microsecond receive time;
- FCS policy (`sig_len` includes the driver-reported 4-byte FCS, removed from
  the MAC parser view);
- whether MAC body bytes were cut off by the 512-byte packet bound.

The Phase 1.5 contract that `orig_length` includes FCS is preserved. The view
computes `original MAC length = orig_length - 4` only after checking the
subtraction cannot underflow; values below four have no valid original MAC
length. `captured_mac_length` is the existing bounded parse length. Losing
only some/all FCS bytes is not marked as MAC truncation; losing MAC body bytes
is. `mac_bytes` points into a pool slot and is valid only until
`rx_path_slot_release()`. Parser observations copy values and retain no slot
pointer. Pool capacity remains 512 bytes per slot; there is no full-length
frame pool or additional storage task.

## Parser support matrix

The pure-C `eapol_parse_frame()` consumes only the unified capture view and
uses the Phase 2.5 802.11 header-length/address parser.

| Input | Result |
| --- | --- |
| Data / Data+CF subtype and QoS Data subtypes that can carry an MSDU | Inspect the exact LLC/SNAP header; parse EAPOL only for `AA AA 03 00 00 00 88 8E`. |
| Null and QoS Null | Never inspect bytes after the MAC header as payload. |
| QoS+Order | Includes QoS and the applicable four-byte HT Control; plain Data+Order does not add HT Control. |
| ToDS / FromDS | Direction and BSSID/STA values are set only for reliable three-address mappings and valid unicast addresses. |
| no-DS, WDS, mesh-control, A-MSDU, fragmented data | Explicitly unsupported and reported; no fragment reassembly. A nonzero fragment number is unsupported even when More Fragments is clear. |
| Protected body | Never search encrypted bytes for plaintext EAPOL. |
| Other Data subtypes, control/management, nonzero 802.11 protocol version | Not parsed as EAPOL. |
| EAPOL versions 1–3; packet types EAP-Packet, Start, Logoff, Key | Outer header and big-endian body length are bounds checked. Unknown packet types and unsupported versions are reported unsupported. Start/Logoff with a nonzero body is malformed. |
| EAPOL-Key descriptor 2 (RSN), 254 (WPA), descriptor versions 1–3 | Check the fixed prefix, 16-byte MIC layout, big-endian Key Data Length field, and its bound within the declared EAPOL body. Pairwise/group comes only from Key Information bit 3. |
| EAPOL-Key descriptor version 0 | Unsupported MIC layout. It is AKM-defined; hostap derives MIC length from negotiated AKM/PMK length (which can be 0, 16, 24, or 32 bytes). No session/AKM context exists here, so the parser does not guess a Key Data Length offset. |
| Unknown Key descriptor | Report unsupported Key descriptor only; do not interpret its payload as a known Key layout. |

Key descriptor and MIC layout references: hostap's [`wpa_eapol_key` and Key
Information definitions](https://github.com/vanhoefm/hostap-wpa3/blob/master/src/common/wpa_common.h)
mark the MIC field variable length and define the descriptor version and
pairwise bit; [`wpa_mic_len()` and AKM-defined handling](https://github.com/vanhoefm/hostap-wpa3/blob/master/src/common/wpa_common.c)
show why version 0 needs negotiated AKM context. Wireshark's [EAPOL
dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-eapol.c)
defines the envelope header length, packet types, and descriptor types. The
Linux kernel's [802.11 header definitions](https://github.com/torvalds/linux/blob/master/include/linux/ieee80211.h)
are also used to cross-check DS, A-MSDU, mesh-control, and fragment fields.

Declared EAPOL body length, not trailing 802.11 padding, bounds the envelope.
When the original MAC length proves the declaration cannot fit in the received
frame, the result is malformed even if the copied bytes were also cut. When
the original frame could contain the declared bytes but the capture did not,
the result is truncated. A complete Key observation validates structural
bounds only; it does not mean a MIC was verified, a session was correlated,
or a handshake succeeded. No nonce, MIC, or key data is retained.

## Observation and statistic semantics

Each parser result is processed in `radio_rx_task` before any World Model
lock or insert attempt. A full World table or missed lock therefore cannot
gate EAPOL recognition. An unsupported or truncated result does not skip the
existing ordinary World Model path. The latest confirmed EAPOL observation
or partial SNAP candidate, and `wifi_sniffer_get_eapol_stats()` snapshot,
contain values only, including the RX timestamp, direction, type, status, and
reliable BSSID/STA values when available.

Counters are saturating frame counts, not unique handshake counts:

- `raw_eapol_frames`: strict complete LLC/SNAP EAPOL EtherType was observed;
  retransmissions count as additional frames.
- `complete_eapol_envelopes`: raw frames with supported EAPOL version/type
  whose declared body bytes are fully present. It describes outer byte
  completeness, not validity of every type-specific body field.
- `complete_key_frames`: structurally complete, supported Key descriptor
  frames only. Pairwise/group counters partition these complete Key frames.
- `truncated_eapol_frames`: confirmed raw frames cut before their declared
  EAPOL bytes, plus partial SNAP-prefix candidates cut before the full
  EtherType. Candidates do not increment `raw_eapol_frames`.
- `malformed_eapol_frames`: strict raw EAPOL frames whose declared length
  overruns a complete MAC frame or whose supported body layout is invalid.
- `unsupported_eapol_frames`: strict raw EAPOL frames with a recognized but
  unsupported EAPOL version/type/descriptor or a no-DS/WDS layout whose
  LLC/SNAP marker remains identifiable.
- `unsupported_mac_layout_frames`: bounded diagnostic count for parsed data
  layouts this stage does not inspect (for example protected, WDS/no-DS,
  mesh, A-MSDU, or fragments); it is not a count of EAPOL packets.
- `eap_packet_frames`, `start_frames`, `logoff_frames`, and `key_frames` count
  raw EAPOL packet types when their four-byte header is present. Unknown Key
  descriptor count is separate.

Aggregate statistics are logged every three seconds. Individual strict EAPOL
observations are rate limited to at most one line per three seconds; there is
no per-frame callback logging. This stage does not infer M1–M4, deduplicate
retries into a handshake, or claim a handshake-completion count.

## Regression and build evidence

Production parser code is compiled by `tests/host/run.sh` in the existing host
suite plus `test_eapol`, in plain and ASan/UBSan modes. Fixtures cover ordinary
and QoS/HT headers, both DS directions, strict LLC/SNAP matching, Null and
protected frames, A-MSDU/mesh/no-DS/WDS, first/middle/final fragments, EAPOL
versions/types/lengths/padding, descriptor and Key Data boundaries, unknown
descriptors, capture truncation, timestamps beyond 32-bit microseconds, queue
delay, pool-slot reuse, and pool conservation.

The repository GitHub Actions workflow ran the commands below against the
implementation source SHA above. No local compilation was performed:

```text
bash tests/host/run.sh                 PASS: plain and ASan/UBSan, 112/112 each
ESP-IDF v5.4 / target esp32c6 build   PASS; firmware.zip and flash artifacts uploaded
```

The final run contains 11 host suites (including `test_eapol`): 112 cases
passed in plain mode and the same 112 passed under ASan/UBSan. The initial
implementation run [35971737017](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35971737017)
found a host compile failure under `-Werror=type-limits`; that diagnostic was
fixed in `72f1b9b`. Intermediate run
[35972070384](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35972070384)
passed both host modes and the ESP-IDF build. A later bounded-view truncation
fix was then included and revalidated by final run 35972440421. The failed
attempt's original log remains available from its Actions run; it is not
represented as a pass.

## Memory and hardware status

- `radio_packet_t` adds one `uint64_t`: 8 bytes per pool slot. The existing
  24-slot pool grows by 192 bytes (from 12,480 to 12,672 bytes, using the
  existing 520-byte slot layout plus eight bytes per slot).
- Both 24-item pointer queues keep their item size and depth. On ESP32-C6,
  their item storage remains 24 × 4 bytes per queue (192 bytes total), with
  the existing dynamically created FreeRTOS queue objects unchanged.
- No task or queue was added. `radio_rx` and `radio_stat` stack allocations
  remain 3,072 bytes each. Parser locals add a bounded capture view and
  value-only EAPOL observation to the existing parser task; on-device stack
  high-water measurement is **PENDING**.
- No authorized natural AP/client connection was available for field
  observation in this run. Hardware passive EAPOL capture is **PENDING**;
  fixed 300 ms hopping may miss exchanges. Offline fixtures and CI are not a
  hardware PASS.

## Final result

**Phase 3A software: PASS at implementation SHA `5336ac7666371e198b8bb0be9e65deda38b1bcf2`; GitHub Actions run 35972440421.**
**Phase 3A hardware: PENDING authorized passive capture.**

No Phase 3B work has started. No merge or release was performed.
