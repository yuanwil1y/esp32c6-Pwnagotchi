# Phase 3C — Bounded asynchronous SD logger

Status: **PENDING**. Code SHA
`3f23fcd08f7da23b606e2289e326bf8d8734875b` passed GitHub host and ESP-IDF CI
run [36001491669](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/36001491669).
Its app-only image was flashed and booted stably. A live SD recording ran, but
`capture-stop` ended in `ERROR` with one I/O error even though accepted,
serialized, written, and flushed all reached 1,594. Six additional records
were dropped at the full logger queue. The user has no SD reader, so the file
has not been extracted or independently read by TShark; hardware PCAP
readback and successful controlled-stop acceptance remain **PENDING**.
Active hopping/RX/heap/stack telemetry was observed. Visual LCD responsiveness
was not independently assessed during the write interval.
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
still did not start. The 16,384 B revision passed host/IDF CI in run
35994419351, but the `c56dca3ff54f9de50caa55eb92457eeb2a327df0` hardware boot
still triggered stack protection in `sd_console_init`. Its 71,205-byte raw
COM3 log is at
`D:\pwn\phase3c-evidence\35994419351\phase3c-com3-boot.raw.log` (SHA-256
`B1D1BFD222FBCA717455D34B0CA13A9BBD293FFD4E9F6299CCFAB3F8525E8FBD`). At the
fault, SP `0x4084bec0` was 24 B below the reported lower bound `0x4084bed8`;
the captured window contains eight visible stack faults and nine successful
unique self-test writes. Console initialization did not complete, Wi-Fi did
not start, and no recording session began. The device is now disconnected.
The `8835e59c7887b87f68eb694841548626e68d2671` revision raises the startup
stack to 24,576 B and selects USB Serial/JTAG for the board's COM3 control
console. Both CI jobs passed in run
[35997776604](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35997776604):
plain and ASan/UBSan host tests, both independent TShark validations, and the
ESP-IDF v5.4 build. The app image is 1,211,968 B (CI total image size
1,211,851 B); linker `.bss` is 64,648 B, and `sd_logger_idf.c.obj` contributes
10,238 B `.bss`. The generated config confirms USB Serial/JTAG is the primary
console and main-task stack remains 3,584 B. The app SHA-256 is
`FE96A9077C89005FB0BD8DC61343BBA8A422440EF53F611A239D22977F4E7880` and the
embedded git SHA matches the revision. Raw job logs are retained in
`docs/logs/phase3c_build_ci_35997776604.log` and
`docs/logs/phase3c_host_ci_35997776604.log`.

The image was flashed app-only at `0x10000`; esptool v5.4 reported `Hash of
data verified`. The board booted without a stack fault and ran stably for
several minutes with SD/LCD/touch healthy, Wi-Fi receive and fixed 300 ms hopping
active. A representative runtime snapshot reported RX queue `q=0/7`, radio
drop=0, free heap 163,064 B, minimum heap 158,268 B, RX stack HWM 988 B, UI
stack HWM 1,544 B, and logger stack HWM 3,756 B. An actual passive EAPOL-Key
observation was logged with `rx_us=6182520`, direction 2, key class 1, and a
reliable BSSID/STA mapping. However, logger status stayed `STOPPED`; the
control startup error above meant no SD session or file was created, so this
does not verify recording or a controlled stop. The full ESP-IDF Monitor log
is preserved outside the repository at
`D:\pwn\phase3c-evidence\35997776604\log..20260924203521.txt` (287,646 B,
SHA-256 `ACF5F9DF181A52ADAEF0B2BF65F41EB7E7C27B184E168D40E13E2E6B029F3983`).
It contains raw wireless metadata and remains local.

The follow-up replaces ESP-IDF's all-in-one REPL creation with a dedicated
4 KiB bounded reader task on the existing USB Serial/JTAG driver. It accepts
only `capture-start`, `capture-stop`, `capture-status`, and `help`; it neither
owns radio/logger slots nor performs storage work. Its app-only hardware run
and the remaining acceptance gap are recorded below.

Code SHA `3f23fcd08f7da23b606e2289e326bf8d8734875b` passed run
[36001491669](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/36001491669):
host plain + ASan/UBSan, Phase 3B reference PCAP and synthetic logger PCAP
TShark/capinfos checks, and ESP-IDF v5.4 ESP32-C6 build. The CI app image is
1,192,112 B (0x1230b0); total image size is 1,191,987 B, `.bss` is 64,576 B,
and `sd_logger_idf.c.obj` contributes 10,238 B `.bss`. The artifact SHA-256 is
`FB5D930CDF5B9C69107E8B5EDDE1318D4D1C6EE5216EAEB286E73D943A21C926`. CI
`flash_args` lists bootloader at `0x0`, partition table at `0x8000`, and app
at `0x10000`; hardware verification will write only the app address. The
firmware SHA is embedded as `3f23fcd08f7da23b606e2289e326bf8d8734875b`.
Original job logs are retained in
`docs/logs/phase3c_build_ci_36001491669.log` and
`docs/logs/phase3c_host_ci_36001491669.log`.

The matching 1,192,112-byte app image was written only at offset `0x10000`;
esptool reported `Hash of data verified`. Its SHA-256 was
`FB5D930CDF5B9C69107E8B5EDDE1318D4D1C6EE5216EAEB286E73D943A21C926`. The
device booted without a reboot loop. USB Serial/JTAG accepted `capture-status`,
`capture-start`, and `capture-stop`. A new exclusive session opened
`/sd_card/capture/capture-9D808161AA2EF8C5-0000.pcap`; no existing file was
opened for write.

During approximately 67 seconds of recording, the latest stop snapshot was
`state=ERROR accepted=1594 serialized=1594 written=1594 flushed=1594`,
`storage_drop=6` (all six `queue_full`), `old_rx=0`, `io_drop=0`,
`errors=1`, and queue depth `0/8`. Maximum open/write/sync/close durations were
437399/138439/139233/4178 us. The logger had stopped accepting records and its
owned file handles had been closed by the error cleanup path, but the state is
not reported as a successful stop. The public status does not identify whether
the close error came from the PCAP or the sidecar, so that cause remains
unknown. The counters indicate all accepted records reached both written and
flushed, but without reading the card they do not establish PCAP integrity.
The actual PCAP and sidecar have not been copied off the card because the user
does not have an SD reader. No card format, deletion, or overwrite was done.

Radio telemetry continued during the session: hopping remained at 300 ms with
zero hop errors; RX drop remained zero and RX queue depth was `0/2`. At the
last active-write snapshots free heap was about 158 KiB with 154,280 B minimum;
RX, logger, and UI stack high-water marks were 984 B, 2,348 B, and 1,444 B.
The UI task continued reporting, but the display and touch were not visually
verified while the SD was busy. The user toggled a phone's Wi-Fi once during
recording. The firmware's EAPOL raw observation count remained at its
pre-session value of 1, so this capture provides no evidence that the
reconnection's EAPOL frames were received; fixed-channel hopping can miss
them. No deauthentication was observed by the sniffer and no active wireless
operation was issued by the logger.

The full raw COM3 monitor log is retained locally, not committed because it
contains nearby network identifiers:
`D:\pwn\phase3c-evidence\36001491669\log..20260924205901.txt` (78,226 B,
SHA-256 `22777FAE04679B9E15BA27E71EC0C56C158C644558FE857CEF2925B26D93CFFB`).
GitHub Actions run
[36002325074](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/36002325074)
also completed successfully for the subsequent documentation-only commit.

The `f2fe1c411d81bf8058fcb801c0be580fb0c8a709` revision passed both CI jobs in
run [35995388924](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/35995388924):
host plain and ASan/UBSan, both independent TShark validators, and the IDF v5.4
build. The CI app image is 1,233,504 B; linker `.bss` is 64,688 B, and
`sd_logger_idf.c.obj` contributes 10,238 B `.bss`. The generated config
confirms the main-task stack remains at the default 3,584 B. The image SHA-256
is `096C93AD6317C47D49467A27CB42C117A4897618D53C77DD96B6F9FCB8C43707` and its
embedded full git SHA matches the revision.

That image was written only to app offset `0x10000`; esptool v5.4 reported
`Hash of data verified`. The 25-second raw COM3 capture is kept outside the
repository at
`D:\pwn\phase3c-evidence\35995388924\phase3c-com3-boot.raw.log` (114,165 B,
SHA-256 `5B09E4D6DDA1A54535C9164FC1102060F7D32A4BBC1DC895BFCB6F9FCB8C43707`).
It contains 13 observed stack faults and 13 successful uniquely named SD
self-tests. Each fault names `sd_console_init`; the first reports bounds
`0x4084bed8..0x40850ed0` (20,472 B actual span) and SP `0x4084bed0`, 8 B past
the lower bound. LCD/touch setup, SD mount, SD write/readback, and logger
initialization passed; Wi-Fi/sniffer/hopping and the command REPL did not
start, and recording remained OFF. Thus there is no live logger I/O or
capture acceptance evidence yet. The device has been disconnected. This trace
corrects an earlier mistaken subtraction: the 20,480 B stack request did take
effect; the request was simply still too small.

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

UI / USB Serial/JTAG console
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

The USB Serial/JTAG console provides:

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

The task stack request is 6,144 B for `sd_logger`, 24,576 B for the temporary
`sd_console_init` task, and 4,096 B for the persistent USB Serial/JTAG REPL. Together these
new task stacks request 34,816 B at their peak overlap; the temporary startup
stack is released after the REPL starts. They are runtime allocations, not
static BSS; FreeRTOS task control objects and one event group are also runtime
allocations. The IDF main task remains at its default 3,584 B. Existing UI
(4,096 B), RX (3,072 B), and radio-stat (3,072 B) task stack sizes are not
changed. `uxTaskGetStackHighWaterMark()` values for logger, console startup,
and UI, plus before/after logger/console heap and minimum heap, are emitted on
device. The mount reuses
the existing board FatFs configuration (`max_files=5`, `CONFIG_FATFS_LFN_HEAP`);
PCAP and sidecar use two handles within that existing limit. No additional FAT
workspace size is configured. For the booted 3f23 image, CI reports linker
`.bss=64,576` B and `sd_logger_idf.c.obj` `.bss=10,238` B. Runtime minimum free
heap was 154,280 B. The observed logger stack high-water mark decreased from
3,756 B while idle to 2,348 B at the post-stop error snapshot; RX/UI high-water
marks were 984/1,444 B. FAT workspace has not been isolated from the board's
shared existing mount and remains unmeasured separately.

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

No local build or test is run for this task. The CI run and all hardware
attempts are recorded above. The latest control-reader image was flashed
app-only; the SD close error and missing card readback prevent hardware
acceptance.

## Hardware acceptance status

**PENDING — live recording and radio operation were demonstrated, but the
controlled stop returned `ERROR`; the physical file is not independently
verified.** The only available raw capture copy is the local monitor log noted
above. The user has no SD reader, so the session PCAP and sidecar cannot
currently be read off the card. The close-failure source (PCAP versus sidecar)
is unknown from the current firmware's aggregate error status. Visual LCD/touch
responsiveness during active SD writes also remains unverified. Do not count
the written/flushed counters or synthetic host TShark run as a hardware PCAP
PASS.

What was verified: the code and app-only image passed GitHub CI; the device
booted stably; direct USB Serial/JTAG control worked; a uniquely named file
was opened and received records; status reported 1,594 accepted/serialized/
written/flushed records and six logger queue-full drops; RX drops stayed zero;
300 ms hopping continued without reported hop errors; heap and task stack
telemetry remained available. The phone Wi-Fi toggle did not increase the
EAPOL observation counter during this capture, which is consistent with the
known possibility of missing a brief connection exchange while hopping.

To finish hardware acceptance, use an SD reader to extract the existing
session files without changing them, run TShark/capinfos on the PCAP and
compare its packet count and lengths with the recorded counters, and investigate
the reported close error before any future acceptance claim. Confirm display
responsiveness during an active write as part of that follow-up. No local build
or test result is substituted for GitHub CI, and no live capture file was
uploaded or committed.

The firmware does not request Wi-Fi reassociation, deauthentication, active
scanning, or transmit packets. This phase does not implement PCAPNG, handshake
reassembly, M1–M4 completion, password testing/recovery, Agent behavior, or a
new UI menu. Phase 3 overall acceptance is not claimed.

## USB Serial/JTAG readback follow-up

Because the user does not have an SD reader, a follow-up adds a read-only path
to retrieve an already stopped or failed session over the existing USB
Serial/JTAG console. It does not add an SD task, alter the recording path, or
write to the card. The logger task remains the only owner of SD files and
performs `stat`/open/read/close for export. Export is refused unless the live
logger state is `STOPPED` or `ERROR`; start/stop requests are refused while an
export request owns the reader. The old session remains in its original file
and is selected only by its 16-hex session ID.

Commands:

```text
capture-status
capture-export-info 9D808161AA2EF8C5
capture-export 9D808161AA2EF8C5 pcap 0 0
capture-export 9D808161AA2EF8C5 summary 0 0
```

The `capture-export-info` response lists PCAP segments and exact byte lengths.
The data command accepts a file kind, segment index, and decimal byte offset.
USB output is ASCII lines with 512-byte maximum Base64 chunks, original file
offsets, and CRC-32. The host receiver verifies each chunk, retries from the
first missing offset, fsyncs a local `.part` file, and renames it only after
the device confirms the file end. Existing local output files are never
overwritten; an interrupted `.part` file can be resumed. Install `pyserial`
once with `python -m pip install pyserial`, then run from the repository root:

```text
python tools/capture_serial_export.py COM3 --session 9D808161AA2EF8C5 --output-dir D:\pwn\capture-export
```

The receiver does not upload the resulting PCAP or summary. The output can be
independently checked with TShark after retrieval. This serial path is only a
transport for the existing SD bytes: until it successfully transfers the
session and an independent reader checks it, the SD recording acceptance stays
**PENDING**. The implementation and its CI result are recorded in the final
follow-up entry below.

### Follow-up implementation and validation

- Starting revision: `5379a5e9c3321173642c2c2ac7f04b8e58161d3f`, after the
  Phase 3C hardware attempt and documentation; the already recorded failed
  session `9D808161AA2EF8C5` remains on the SD card. No Phase 2/3A/3B fixes or
  existing Phase 3C capture ownership were rewritten.
- Implementation commits: `3d76f7fed611bf15916d8a9130b9fe360aa0cf50`
  (serial readback, status detail, protocol, host receiver),
  `7ddaf86fe1ff3ed2f227542a4c2e7568e32d96f3` (wire file-kind correction),
  `51e209b022e73161bddb3dec3f08cb11bb3e8640` (host command names), and
  `496667192ba4ece8e8cc103032c80040c3cb9968` (prompt-prefixed host frames).
- GitHub Actions run
  [36008775587](https://github.com/yuanwil1y/esp32c6-Pwnagotchi/actions/runs/36008775587)
  passed both jobs. Host plain and ASan/UBSan regression suites passed,
  including seven serial receiver tests for CRC/base64 validation, files over
  16 chunks, resuming, gap retry, and refusing output overwrite. The existing
  reference PCAP and synthetic logger PCAP were independently read by
  TShark/capinfos 4.2.2. The ESP-IDF v5.4 ESP32-C6 build passed.
- Firmware app image: 1,199,088 B (`0x124bf0`); linker `.bss` is 65,936 B.
  Linker `.bss` increased 1,360 B from the recorded 3f23 image.
  `sd_logger_idf.c.obj` contributes 11,600 B `.bss`, up 1,362 B. The delta is
  consistent with the 512-byte binary and
  800-byte encoded static buffers plus export state. There is no new task,
  queue, packet-sized allocation, FAT workspace, or stack request; the logger
  and USB console stack requests remain 6,144 B and 4,096 B. The app artifact
  SHA-256 is
  `BB56AD4C071D9E46A9388769F8B908BD3A8FB74D8A17B61E962B84946B6715AE`.
- The first CI attempt (run `36008368470`) passed the IDF build but failed two
  host receiver tests because the receiver compared device `P`/`S` frame tags
  against the CLI words `pcap`/`summary`. The correction is covered by the
  fully passing run above. Logs retained in `docs/logs/` are the actual GitHub
  job logs; no local compile or test was used.
- The 7ddaf86 app was app-only flashed to `0x10000` on COM3; esptool v5.4
  verified the written hash. It booted and `capture-export-info` reported the
  target PCAP size as 216,586 B and sidecar size as zero. An end-offset read
  returned `!PCAP,END,P,0,216586`. A full body transfer did not produce a
  valid data chunk; the host `.part` remains zero bytes. The target app had
  tried to enqueue each roughly 700-byte ASCII frame in one USB Serial/JTAG
  write, larger than the configured 256-byte TX ring. The corrective firmware
  change sends 128-byte bounded slices; it must pass CI and be app-only flashed
  before retrying. No SD file was created, changed, or deleted by readback.
- Hardware PCAP readback is still **PENDING**. The last recorded logger state
  was `ERROR` after 1,594 records; its I/O-stage cause cannot be retroactively
  recovered from that firmware. After the bounded-write fix, acceptance still
  requires a complete serial transfer and independent `capinfos`/TShark packet
  count and length results. This is not a Phase 3C acceptance PASS. Live raw
  serial debug output is kept outside Git at `D:\pwn\phase3c-evidence\` because
  it includes nearby network identifiers.
