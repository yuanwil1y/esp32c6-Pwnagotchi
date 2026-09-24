# Phase 3B — Standard PCAP + radiotap serialization and offline validation

Status: complete for the pure-C serializer and offline host validation. This
phase adds no SD writer, logger task, PCAP rotation, or live PCAP capture path.

## Baseline and scope

- Actual starting revision: `5617a08236476469fcb134b172ed9fbbcc11833f`, the
  Phase 3A completion on branch `phase3a-eapol`. It contains the repaired Phase
  2 World Model and Phase 3A; work did not start from the then-stale `main`.
- Phase 2.5 software and hardware checks, including its software CI result, are
  recorded in `PHASE2_WORLD_MODEL.md`. Phase 3A records its parser CI and its
  limited passive EAPOL observation on hardware in `PHASE3A_EAPOL.md`.
- The production serializer and final synthetic fixtures were exercised at
  `ffee6c4ebc44612ebb173b362e616b720a44c203` (CI run
  [35979616696](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35979616696)).
  The follow-up commit `b5aa907d1175e3fc98748ef63ffa109f3067d23d` pins the
  CI-generated reference file, checks it byte-for-byte, and retains the actual
  test output; its complete CI run
  [35980262138](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35980262138)
  passed.
- The stale firmware labels were updated to “Phase 3B” in `main/app_main.c`
  and `components/board/board_display.c`.

No Phase 2 or Phase 3A behavior was rewritten as part of this stage.

## File and link type

The serializer emits only classic PCAP 2.4 with microsecond timestamps and
`LINKTYPE_IEEE802_11_RADIOTAP` (127). It writes each integer byte-by-byte in
little-endian order; no compiler struct is written to the file.

- The 24-byte global header has magic `d4 c3 b2 a1`, version 2.4, zero reserved
  fields, snaplen 527, and network/link type 127.
- Each record starts with a 16-byte PCAP record header. `incl_len` and
  `orig_len` include the radiotap header. The former describes bytes actually
  present, and the latter the original no-FCS MAC length plus radiotap.
- The referenced PCAP draft-05 is an Internet-Draft, not an RFC. The
  implementation uses the classic 2.4 file layout and the IANA registered
  link type. See the [draft-05 record](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/05/)
  and [IANA PCAP link-type registry](https://www.iana.org/assignments/pcap).

Radiotap contains only metadata the RX path can support: Flags, Channel when
known, and signed dBm Antenna Signal. Present bits are `0x2a` when channel is
known and `0x22` when omitted. With a known channel, `it_len` is 15: Flags at
offset 8, alignment byte at 9, Channel at 10–13, and signal at 14. With an
unknown channel, `it_len` is 10 and signal is at offset 9. Channel 1–13 maps to
`2412 + 5 * (channel - 1)` MHz; channel 14 maps to 2484 MHz. Channel flags only
claim 2.4 GHz (`0x0080`). Unknown values omit Channel and increment
`records_without_channel`; no frequency is guessed. Radiotap Flags are zero:
there is no emitted FCS and no bad-FCS result. Rate, TSFT, and PHY mode are
omitted because the RX metadata cannot establish them. Alignment and field
definitions follow the [radiotap field rules](https://www.radiotap.org/) and
the [Wireshark radiotap field reference](https://www.wireshark.org/docs/dfref/r/radiotap.html).

## Input, FCS, and truncation contract

`pcap_serializer_encode_record()` accepts the Phase 3A read-only
`rx_capture_view_t`. `mac_bytes` is borrowed only for the call and is never
retained; the caller output buffer must not overlap it. No per-record
allocation, IDF, FreeRTOS, LVGL, or filesystem API is used.

Phase 1.5 reports `radio_packet_t.orig_length` including the four-byte FCS.
Phase 3A's `rx_path_make_capture_view()` checks that reported length before
subtracting four and presents `captured_mac_length` and `original_mac_length`
without FCS. The serializer consumes those lengths as-is and does not subtract
FCS a second time. An input whose original length is below four has
`original_mac_length_valid == false` and is rejected with
`PCAP_REJECT_INVALID_ORIGINAL_LENGTH`.

`capture_truncated` describes missing MAC bytes, not missing FCS bytes. A
capture that includes only part or none of the FCS can still contain the full
MAC frame. For accepted views, the serializer checks that the truncation flag
matches the two no-FCS lengths. Captured MAC bytes are bounded at 512:

- maximum radiotap plus captured MAC data (snaplen): 527 bytes;
- maximum record buffer, including its 16-byte record header: 543 bytes;
- maximum serialized MAC prefix: 512 bytes.

For longer frames, `incl_len` stays bounded and `orig_len` records the larger
original length. The missing tail is not zero-filled. Contradictory lengths,
unsupported FCS policy, invalid time, and insufficient output capacity have
separate saturating caller-owned reject counters. All checks happen before the
first output byte is written. Global-header output is also capacity-checked.

## Time and state

The API takes a caller-owned fixed session anchor: a monotonic receive-time
anchor and an epoch-microsecond anchor. Every record and every rotated file in
one session must use the same anchor. Timestamp is derived from the captured
RX timestamp, never serializer or future storage time. The format uses
seconds/microseconds, not the nanosecond PCAP magic. The encoder rejects a time
before its anchor, arithmetic overflow, or a seconds value beyond the
32-bit classic PCAP field.

The device has no trusted UTC source in this phase and no clock-sync code was
added. An epoch anchor of zero is valid but makes Wireshark show times near the
Unix epoch; this is not UTC. The reference fixture uses a deterministic test
anchor of `1700000000.999900` seconds and crosses second boundaries.

`pcap_serializer_stats_t` is caller-owned and saturates at `UINT32_MAX`. It
reports encoded records, records without a channel, and rejects by reason. The
serializer does not claim unique packets, EAPOL handshakes, or successful
authentication.

## Reference capture and independent readback

`tests/fixtures/phase3b/reference.pcap` is generated by the production code and
contains 11 synthetic records: beacon, probe request, Data, QoS Data with an
unknown channel, Data Null, QoS Null, ACK control, EAP-Packet, complete
EAPOL-Key, capture-truncated EAPOL-Key, and four-address WDS Data. MAC
addresses use local synthetic values; there is no real AP/client traffic.
`expected.tsv` provides expected decoded fields per frame. CI first verifies
the generated bytes exactly match the checked-in reference, then reads the
generated file with Wireshark's independent tools.

The successful CI run used TShark/capinfos 4.2.2 and reported 11 records, 810
file bytes, and a 527-byte file-header snaplen. The highest actual packet
capture length is 63 bytes. `frame.cap_len`/`frame.len` matched the PCAP
included/original lengths on every row. TShark decoded the expected channel
frequencies and dBm signal, the 802.11 source/destination addresses, EAP-Packet
type 0 in frame 8, and EAPOL-Key type 3 in frames 9–10. Frame 10 shows
`cap_len=63`, `frame.len=146`; the missing body was not padded. Channel is
intentionally absent for frames 4 and 11. TShark reported no generic
`_ws.malformed` frames, including for the capture-truncated frame.

The exact host summary and TShark/capinfos step output, with CI timestamps, are
retained in:

- `logs/phase3b_host_ci_35980262138.log`
- `logs/phase3b_tshark_ci_35980262138.log`

The reference PCAP is 810 bytes with SHA-256
`b330561e0d3fa3c6068921aa2e567815016ba60597257df6c0a09f96495f29de`.

## CI commands and results

The host regression job ran:

```text
bash tests/host/run.sh
python3 tests/host/validate_reference_pcap.py tests/host/build/reference.pcap
```

The first command compiles production sources into 12 suites and runs all 125
checks in plain mode and all 125 under ASan+UBSan. Both modes passed on
`b5aa907d1175e3fc98748ef63ffa109f3067d23d`. The second command checks the
committed fixture, compares TShark fields to `expected.tsv`, and ensures no
complete fixture is marked malformed. Its CI step invokes:

```text
capinfos -c -s -l tests/host/build/reference.pcap
tshark -r tests/host/build/reference.pcap -T fields -E separator=/t -E occurrence=f \
  -e frame.number -e frame.cap_len -e frame.len -e frame.time_epoch \
  -e radiotap.channel.freq -e radiotap.dbm_antsignal \
  -e wlan.sa -e wlan.da -e eapol.type
tshark -r tests/host/build/reference.pcap -Y _ws.malformed -T fields -e frame.number
```

The same commit passed the workflow's ESP-IDF v5.4 ESP32-C6 build. The run
linked above includes both successful jobs. Local compilation and tests were
not run; the configured GitHub CI performed them.

## Memory and limits

Phase 3A already added the 64-bit receive timestamp to each slot: the 24-slot
packet pool is 12,672 bytes, and the two existing pointer queues use 192 bytes
of item storage total. Phase 3B changes none of those sizes and adds no task,
queue, global writable storage, or dynamic allocation. The serializer's only
fixed byte arrays on a call are the 16-byte record header and 15-byte radiotap
header; no task or configured stack size is added. Compiler stack usage was
not separately measured.

For a later queue made of complete encoded records, budget at most 543 bytes
per entry (`N * 543` bytes for `N` entries), plus whatever queue metadata or
batch framing that later phase chooses. The reference PCAP and host fixtures do
not consume firmware packet-pool memory.

No SD storage, write-all loop, persistence-failure path, PCAPNG, handshake
session tracking, active scanning, or packet transmission is part of Phase 3B.
There is no hardware PCAP write acceptance to report because this phase adds no
device-side writer.

## References

- [PCAP draft-05](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/05/)
  (Internet-Draft, not an RFC)
- [IANA PCAP link-type registry](https://www.iana.org/assignments/pcap)
- [Radiotap field and alignment rules](https://www.radiotap.org/)
- [Wireshark Radiotap fields](https://www.wireshark.org/docs/dfref/r/radiotap.html)
- [Wireshark IEEE 802.11 fields](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [Wireshark EAPOL fields](https://www.wireshark.org/docs/dfref/e/eapol.html)
