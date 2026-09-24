# Phase 3C — Bounded asynchronous SD logger

Status: host/IDF CI passed for the console-isolation revision
`e43968db4d8181b5cd00dd586184c2ce300e921b` on run
[35993675554](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35993675554).
Live testing then identified insufficient stack in the isolated console
initialization task. Its stack is being raised from 12 KiB to 16 KiB for the
next CI and hardware attempt. Real capture, controlled stop, extracted-file
TShark readback, and live display/hopping/heap observation remain **PENDING**.
The user confirmed that an SD card is inserted and authorized creating new
uniquely named files. No existing file is formatted, deleted, or overwritten.

## Baseline and handoff

- Repository: `yuanwil1y/esp32c6-Pwnagotchi`.
- Actual Phase 3C starting SHA: `1b6d6fe8558ad8df5fbfbb076f747b26127898f8`,
  branch `phase3b-pcap`; working tree was clean before Phase 3C edits. This
  baseline includes the repaired Phase 2 World Model, Phase 3A capture view and
  RX timestamp, and Phase 3B serializer. It is not the stale `main`.
- No `AGENTS.md` was present at start.
- Phase 2.5 software check: PASS, GitHub Actions run
  [35965566695](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35965566695)
  (host plain + ASan/UBSan and ESP-IDF v5.4 build). Its one-minute hardware
  smoke test remains PENDING as stated by the Phase 3A handoff; the older
  Phase 2 live test is not used to fill that check.
- Phase 3A software CI: PASS on run
  [35972956027](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35972956027).
  Its limited passive live EAPOL observation is recorded in
  `PHASE3A_EAPOL.md`; this is not Phase 3C SD evidence.
- Phase 3B serializer CI: PASS on run
  [35980262138](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35980262138).
  Host plain and ASan/UBSan suites and ESP-IDF v5.4 build passed; TShark and
  capinfos 4.2.2 independently decoded the 11-frame synthetic reference PCAP.
  Original CI output is retained in `docs/logs/phase3b_host_ci_35980262138.log`
  and `docs/logs/phase3b_tshark_ci_35980262138.log`.

No Phase 2, Phase 3A, or Phase 3B fixes are rewritten by this stage. The
firmware display label is advanced to Phase 3C.

## Current CI and first hardware attempt

At `d921f036d5a3a6355fbe26cd3e6f084da0aa0fa7`, Actions run 35991522213 passed
the ESP-IDF v5.4 ESP32-C6 build, `idf.py size size-components size-files`, and
the complete host suite (13/13 EAPOL envelope cases and 12/12 logger state
cases, plain and ASan/UBSan). TShark/capinfos 4.2.2 independently read both the
11-frame Phase 3B reference and the logger-produced synthetic record. The
synthetic row was `cap_len=527`, `frame.len=1035`, time `0.000100000`, channel
2437, RSSI -47, expected WLAN addresses, EAPOL type 1, with no malformed
diagnostic; its sidecar showed accepted=serialized=written=flushed=1. Original
host/build outputs are in `docs/logs/phase3c_*_35991522213.log`.

The firmware image size was 1,233,216 B, with the 4 MiB app partition reporting
71% free. Linker size reported total `.bss` 64,688 B; the `libstorage.a`
contribution was 10,238 B, including 10,238 B attributed to
`sd_logger_idf.c.obj`. The target logger core reported `sizeof(s_core)=10,184`
B at startup. The initial main-task stack was the IDF default 3,584 B. The
device passed LCD/touch bring-up, SD mount, exclusive-file write/readback and
logger task creation, then immediately raised a stack protection fault in
`main` before Wi-Fi/sniffer startup. The 29,627-byte raw COM3 log is kept
outside the repository at
`D:\pwn\phase3c-evidence\35991522213\phase3c-com3-after-flash.raw.log`
(SHA-256 `A4C476F57E5024963CB8A61D82D1BB774D18E21F5448DBEDEA0734588005E61F`).
The device was disconnected while the startup stack is corrected; no EAPOL
capture was started. Automatic reboot created several newly named self-test
probe files; the old fixed `/sd_card/phase0_test.txt` path was never opened for
write, and no existing file was overwritten or deleted.

The next image, `6e4827cf05a3bccd165a06f68ae17de04e065e35`, tried an 8 KiB
main-task stack but still faulted in `main`. Its 49,235-byte raw COM3 log is
kept outside the repository at
`D:\pwn\phase3c-evidence\35992620025\phase3c-com3-boot.raw.log`
(SHA-256 `981E311CDD1BB5271339E96729DC86BEE1CDB3D4AFAC92C155A4CC93A01896A2`).
That window contains five visible stack protection faults and six successful
uniquely named self-test writes; the captured stack bounds were
`0x40837b2c..0x40839d20` with SP `0x40837b20`. Wi-Fi remained uninitialized and
no capture session had been started.

The following `e43968db4d8181b5cd00dd586184c2ce300e921b` image isolated UART
console/linenoise setup in a temporary 12,288 B `sd_console_init` task and
restored the IDF main-task default of 3,584 B. Its 60,087-byte raw COM3 log is
at `D:\pwn\phase3c-evidence\35993675554\phase3c-com3-boot.raw.log` (SHA-256
`BFBE8E1215AA07E10EC3C39A5D218DC8BCEEAC1E8FB43C0314A3740E979ABAFE`). The
window shows seven stack protection faults in `sd_console_init`; captured SP
`0x4084bc10` crossed its lower bound `0x4084bed8` by 712 B. The main stack did
not fault, but console initialization never completed, so Wi-Fi and capture
still did not start. The next revision raises only this temporary setup-task
stack to 16,384 B; CI and hardware revalidation are pending.

## Ownership and data flow

```text
Wi-Fi callback / driver task
  └─ esp_timer_get_time + bounded copy (512-byte cap) + radio queue
       └─ radio_rx_task / parser task
            ├─ try_submit: copy radio_packet_t to independent logger pool
            ├─ existing EAPOL/parser/World Model work continues
            └─ release radio slot at its existing parser lifecycle boundary

sd_logger task (sole SD/FILE owner)
  ├─ FIFO of fixed logger-pool slot indices
  ├─ Phase 3B serializer → fixed record scratch → 4 KiB batch
  ├─ bounded file operations, periodic sync, stop/drain, rotation
  └─ PCAP + sidecar through the existing FatFs/VFS mount

UI / UART console
  └─ value-only stats snapshot; never owns a logger buffer or FILE handle
```

The capture sink is called in the parser task before high-level parsing and
World Model updates. It performs only validation, reservation, a bounded copy,
and queue bookkeeping. It never calls storage APIs or waits for the logger.
The logger pool is independent of the 24-slot radio pool. World table fullness,
parser classification, observation-log throttling, and EAPOL validity do not
gate valid raw MGMT/CTRL/DATA records. Recording is explicit and starts OFF.

The single parser producer commits copied slots to a FIFO. One logger consumer
serializes and writes them in that order; no prioritization or timestamp sort
reorders records. `rx_timestamp_us` stays attached to its original frame.
Submission copies the complete bounded `radio_packet_t`; no pointer into the
radio or logger pool escapes a slot lifetime. A full logger pool drops only the
new submission and counts it as a storage drop. Stop first rejects new submits,
waits for any already-reserved copy, drains accepted FIFO entries, syncs, and
closes. A new session is refused while prior slots or handles remain owned.

## PCAP, filter, and time contract

Every PCAP file uses the Phase 3B pure-C classic PCAP 2.4 serializer with
`LINKTYPE_IEEE802_11_RADIOTAP` 127, snaplen 527, and a 16-byte packet record
header. It receives the Phase 3A unified read-only capture view. `orig_length`
still includes the driver's four FCS bytes; the capture view removes them once
with an underflow check. Files omit FCS, preserve the captured MAC prefix,
record original no-FCS length in `orig_len`, and show `incl_len < orig_len`
for body truncation. The 512-byte radio copy bound is unchanged.

The default recording filter is raw MGMT, CTRL, and DATA frames with valid
driver storage bounds and a complete minimum MAC header for the reported type.
This accepts raw frames before beacon/security/EAPOL semantic parsing, so a
high-level malformed or unsupported frame is still recordable. MISC, lengths
outside the driver/pool contract, and frames too short to contain their
minimum MAC header are rejected and counted separately. Control ACK/CTS use a
10-byte minimum; other control frames use the 16-byte minimum. Management uses
24 bytes. Data uses 24 bytes, plus the complete QoS and applicable HT Control
fields when indicated. The capture filter is fixed for a session and stored in
its sidecar.

One session anchor is fixed when `capture-start` is requested and reused by all
rotated files. PCAP epoch anchor is zero because the device has no trusted UTC;
Wireshark will show capture-session-relative times near the Unix epoch, not
absolute device uptime or real date/time. Records whose RX timestamp predates the session anchor
(for example a queued radio frame crossing the start boundary) are dropped
with `pre_session_timestamp`; they do not fail the session or get retimestamped
at dequeue/write time.

## Files, lifecycle, and failure behavior

Only the logger task owns `FILE *` handles and performs directory, open, write,
flush/sync, rotation, summary, and close operations. Files live under
`/sd_card/capture/`:

- `session-<64-bit-random-id>.txt` — sidecar summary;
- `capture-<64-bit-random-id>-<sequence>.pcap` — PCAP segments.

Every file uses `open(O_CREAT | O_EXCL)` so an ID collision never truncates an
existing path. The FAT VFS in the selected IDF v5.4 source maps `O_CREAT|O_EXCL`
to FatFs `FA_CREATE_NEW` and maps `FR_EXIST` to `EEXIST`. Bounded collision
retries select a different session ID or segment number. No old file is
deleted, and no automatic “free space” cleanup occurs. The existing board
mount has `format_if_mount_failed=false`. The boot SD self-test also creates a
randomly named `phase0-selftest-<id>-<attempt>.txt` using `O_EXCL`, syncs and
reads it back. This prevents the prior fixed-path probe from overwriting an
existing `/sd_card/phase0_test.txt` and leaves only its new uniquely named
small probe file on the card.

The state machine is `DISABLED → STARTING → RECORDING → STOPPING → STOPPED`;
mount/open/write/sync/close failures go to `ERROR`. `DISABLED` accurately means
the initial mount was unavailable; an explicit start may retry the mount.
Mount/self-test success alone does not set the logger to `RECORDING`: the
sidecar and PCAP are exclusively opened, and the global PCAP header is written
and synced first. An error closes owned handles, frees queued/writing slots,
counts records lost to I/O, and does not stop the sniffer. The incomplete PCAP
is never appended to again. Recovery is explicit `capture-start` after the
fault/card is corrected (or restart); there is no automatic retry loop.

The initial per-file bound is 16 MiB or five minutes; rotation only occurs
between complete records and preserves the session time anchor. The named
session PCAP limit is 128 MiB, including global headers. Reaching it stops the
session and reports `limit_reached`; files are not rotated beyond that budget.
The batch is 4 KiB and flush/sync is due every second while active, plus at
stop/rotation. A 100 ms I/O duration threshold increments `io_slow_count`; the
maximum open/write/sync/close latency is retained and reported every three
seconds. Writer work is confined to one maximum 4 KiB batch or one record per
worker step. Synchronous FatFs/SD protocol calls use IDF command timeouts;
application code does not force-delete a task that might hold FAT/SPI
resources. A `capture-stop` caller waits at most five seconds; timeout returns
`STOPPING`/pending and leaves logger-owned memory untouched.

The IDF v5.4 `SDSPI_HOST_DEFAULT()` leaves host-wide command timeout at zero,
which makes the SDMMC protocol use each command's own timeout. The IDF v5.4
SD SPI API documents timeout returns; the exact worst-case wall time of a
4 KiB multi-command FatFs write and its effect on the shared LCD bus will be
reported from measured hardware telemetry. Do not interpret `fwrite`/`written`
as durable: `written` means a full PCAP batch write call completed; `flushed`
increments only after `fflush`, `ferror`, and `fsync` succeed. Physical power
loss after the last sync may lose newer records.

The SD card and LCD retain the existing SPI2 bus. No new bus instance or extra
stdio payload buffer is introduced (`_IONBF`); the 4 KiB core batch is the only
write batch. Actual concurrent display responsiveness and heap/stack margins
remain hardware acceptance items below.

## Control and counters

The UART console provides:

- `capture-start` — request a fresh session and exclusive file names;
- `capture-stop` — reject new records, drain/sync/close, wait up to five seconds;
- `capture-status` — print current state, session, queue, file, latency, and
  cumulative counters.

The existing status display adds logger state, `written`, and `storage_drop`.
Radio RX pool/queue drops remain in the separate `DROP` display field and
radio counters. Logger snapshots and logs are limited to UI 2 Hz and logger
status every three seconds; per-frame logging is not added.

Counter meanings:

| Counter | Meaning |
| --- | --- |
| `accepted` | raw packet copy committed to logger FIFO |
| `serialized` | accepted record encoded successfully; includes later limit drops |
| `written` | complete record batch passed through write-all |
| `flushed` | records covered by a successful flush + fsync |
| `storage_drop` | sum of logger-side queue/full/not-recording/I/O/limit/pre-session drops; never includes radio RX drops |
| `drop_queue_full` | new record dropped because every logger slot is owned |
| `drop_pre_session` | copied radio frame had RX time before the fixed session anchor |
| `drop_io` | current/queued records lost after writer failure |
| `drop_limit` | current or queued records not written after the session byte limit |
| `rejected_invalid` / `filtered_non_data` | invalid raw bounds/minimum MAC header / MISC or unsupported driver type |
| `storage_full_errors` | writer explicitly reported `ENOSPC` on a write |
| `files_incomplete` | a PCAP file suffered a partial write, sync, or close failure |

These are packet/frame counts, not unique packets or handshakes. Retransmitted
802.11 frames remain separate captures. The sidecar stores firmware SHA,
session ID, monotonic anchor/time policy, snaplen, FCS policy, raw filter,
accepted/serialized/written/flushed, drops, errors, rotations, collisions,
latency maxima, and incomplete-file count.

## Memory and scheduling budget

Phase 3A radio memory is unchanged: `radio_packet_t` is 528 B; 24 slots use
12,672 B, and the two existing pointer queues use 192 B total. The logger pool
is separate: 8 × 528 = 4,224 B, plus 4,096 B batch and 543 B serializer record
scratch. These buffers and the FIFO index array are embedded in static
`sd_logger_core_t`; target `sizeof(s_core)` is printed on boot and is to be
recorded with hardware results. Logger-specific atomics/counters/paths and
other storage control BSS are also reflected in that value and linker size
output.

The task stack request is 6,144 B for `sd_logger`, 16,384 B for the temporary
`sd_console_init` task, and 4,096 B for the persistent UART REPL. Together these
new task stacks request 26,624 B at their peak overlap; the temporary startup
stack is released after the REPL starts. They are runtime allocations, not
static BSS; FreeRTOS task control objects and one event group are also runtime
allocations. The IDF main task remains at its default 3,584 B. Existing UI
(4,096 B), RX (3,072 B), and radio-stat (3,072 B) task stack sizes are not
changed. `uxTaskGetStackHighWaterMark()` values for logger, console startup,
and UI, plus before/after logger/console heap and minimum heap, are emitted on
device. The mount reuses
the existing board FatFs configuration (`max_files=5`, `CONFIG_FATFS_LFN_HEAP`);
PCAP and sidecar use two handles within that existing limit. No additional FAT
workspace size is configured; mount/FatFs dynamic memory will be measured by
heap deltas on hardware. Exact `.bss`, task high-water, minimum heap, and FAT
mount workspace remain PENDING until the CI firmware runs on device.

The queue slots, index FIFO, and fixed buffers are finite. Parser/callback
never waits on SD; any queue saturation becomes an explicit storage drop. No
claim of zero-drop capture is made.

## Regression and independent validation

`tests/host/test_sd_logger.c` invokes production `sd_logger_core.c` with an
injected writer. It covers FIFO/full-queue behavior, separate pool ownership,
producer progress while a writer blocks, RX time versus delayed dequeue,
pre-session time handling, timestamps beyond 32-bit microseconds, slot/pool
conservation, short-write offsets, partial/zero write errors, ENOSPC,
flush/close/open failure, absent media, exclusive filename collisions,
session restart isolation, file/age rotation, and session limits. The host
test produces one synthetic truncated EAPOL Start PCAP plus sidecar. CI reads
that artifact using TShark/capinfos, independently comparing cap/frame length,
time, channel, RSSI, MAC addresses, EAPOL type, malformed diagnostics, and the
sidecar's accepted/serialized/written/flushed counts. This host artifact is
synthetic and does not substitute for an SD-card capture.

The workflow commands to be run on GitHub Actions are:

```text
bash tests/host/run.sh
python3 tests/host/validate_reference_pcap.py tests/host/build/reference.pcap
python3 tests/host/validate_phase3c_capture.py tests/host/build/phase3c_logger_sample.pcap
ESP-IDF v5.4 / ESP32-C6 build
```

No local compile/test is run for this task. This document will be updated with
the actual Phase 3C commit SHA, Actions run and logs, and device evidence after
the branch CI and authorized hardware check. Failed attempts, if any, will
remain identified as failed rather than being described as passes.

## Hardware acceptance status

**PENDING — no Phase 3C firmware has yet been flashed or recorded on COM3.**
The user confirmed the device is attached to COM3 and the SD card is inserted;
file creation is authorized. After CI success, verification still needs to:

1. flash only the CI-built app image and retain the original raw COM3 log;
2. check startup mount/self-test, logger `STOPPED`, SD/lcd/touch/world, fixed
   hopper behavior, heap minima, and logger/RX/UI stack telemetry;
3. use `capture-start`, allow passive capture, then `capture-stop` and confirm
   `STOPPED`, closed files, and sidecar counts;
4. independently read the actual SD PCAP with TShark/capinfos and compare
   record count and incl/orig lengths with `written`; report no-capture periods
   honestly because fixed hopping can miss frames;
5. observe UI responsiveness during active 4 KiB SD write/sync activity.

The firmware does not request Wi-Fi reassociation, deauthentication, active
scanning, or transmit packets. This phase does not implement PCAPNG, handshake
reassembly, M1–M4 completion, password testing/recovery, Agent behavior, or a
new UI menu. Phase 3 overall acceptance is not claimed.
