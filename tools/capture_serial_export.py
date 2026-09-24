#!/usr/bin/env python3
"""Download a stopped Phase 3C PCAP and sidecar through USB Serial/JTAG.

The device streams CRC-protected, base64-encoded chunks. The tool resumes at
the first missing/corrupt offset and creates new local output files without
overwriting existing files.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys
import time
import zlib
import os
from pathlib import Path
from typing import Iterable


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SESSION_RE = re.compile(r"^[0-9A-Fa-f]{16}$")


def clean_line(line: bytes | str) -> str:
    if isinstance(line, bytes):
        line = line.decode("ascii", errors="replace")
    return ANSI_RE.sub("", line).strip()


def decode_data_line(line: bytes | str):
    """Return (kind, index, offset, payload) for a valid data frame.

    Non-frame console output returns None. A damaged frame raises ValueError.
    """
    text = clean_line(line)
    if not text.startswith("!PCAP,DATA,"):
        return None
    fields = text.split(",", 7)
    if len(fields) != 8 or fields[0] != "!PCAP" or fields[1] != "DATA":
        raise ValueError("malformed PCAP data frame")
    kind = fields[2]
    if kind not in ("P", "S"):
        raise ValueError("unknown export file kind")
    try:
        index = int(fields[3], 10)
        offset = int(fields[4], 10)
        length = int(fields[5], 10)
        expected_crc = int(fields[6], 16)
        payload = base64.b64decode(fields[7], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid PCAP data field") from exc
    if index < 0 or offset < 0 or length <= 0 or len(payload) != length:
        raise ValueError("PCAP data length/offset mismatch")
    if zlib.crc32(payload) & 0xFFFFFFFF != expected_crc:
        raise ValueError("PCAP chunk CRC mismatch")
    return kind, index, offset, payload


def parse_info(lines: Iterable[bytes | str], session_id: str):
    """Parse logger metadata lines and return state, files, summary size."""
    normalized_session = session_id.upper()
    state = None
    files: dict[int, int] = {}
    summary_size = None
    ended = False
    for raw in lines:
        text = clean_line(raw)
        fields = text.split(",")
        if len(fields) >= 6 and fields[:3] == ["!PCAP", "INFO", "SESSION"]:
            if fields[4].upper() != normalized_session:
                continue
            state = fields[3]
        elif len(fields) == 5 and fields[:3] == ["!PCAP", "INFO", "PCAP"]:
            try:
                files[int(fields[3], 10)] = int(fields[4], 10)
            except ValueError:
                continue
        elif len(fields) == 4 and fields[:3] == ["!PCAP", "INFO", "SUMMARY"]:
            try:
                summary_size = int(fields[3], 10)
            except ValueError:
                continue
        elif text == "!PCAP,INFO,END":
            ended = True
    if not ended or state is None or summary_size is None:
        raise ValueError("incomplete capture-export-info response")
    return state, files, summary_size


def _read_info(ser, session_id: str):
    ser.reset_input_buffer()
    ser.write(f"capture-export-info {session_id}\r".encode("ascii"))
    ser.flush()
    lines = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        line = ser.readline()
        if not line:
            continue
        lines.append(line)
        if clean_line(line) == "!PCAP,INFO,END":
            return parse_info(lines, session_id)
    raise TimeoutError("timed out waiting for capture-export-info")


def _stream_file(ser, session_id: str, kind: str, index: int, size: int,
                 path: Path, timeout: float) -> None:
    wire_kind = {"pcap": "P", "summary": "S"}.get(kind.lower())
    if wire_kind is None:
        raise ValueError(f"unsupported export kind: {kind}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    partial_path = path.with_name(path.name + ".part")
    if partial_path.exists():
        output = partial_path.open("r+b")
        expected = partial_path.stat().st_size
        if expected > size:
            output.close()
            raise ValueError(f"partial file is larger than device file: {partial_path}")
    else:
        output = partial_path.open("xb")
        expected = 0

    try:
        output.truncate(expected)
        last_offset = None
        attempts_at_offset = 0
        end_seen = False
        while expected < size or not end_seen:
            if expected != last_offset:
                last_offset = expected
                attempts_at_offset = 0
            ser.reset_input_buffer()
            ser.write(f"capture-export {session_id} {kind} {index} {expected}\r".encode("ascii"))
            ser.flush()
            attempts_at_offset += 1
            if attempts_at_offset > 16:
                raise RuntimeError(f"too many retries at offset {expected} for {path.name}")
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                raw = ser.readline()
                if not raw:
                    continue
                text = clean_line(raw)
                if text.startswith("!PCAP,ERROR,"):
                    raise RuntimeError(text)
                if text.startswith(f"!PCAP,END,{wire_kind},{index},"):
                    try:
                        reported_size = int(text.rsplit(",", 1)[1], 10)
                    except ValueError as exc:
                        raise RuntimeError("malformed capture export end frame") from exc
                    if reported_size != size:
                        raise RuntimeError("capture size changed during export")
                    end_seen = True
                    break
                try:
                    frame = decode_data_line(raw)
                except ValueError:
                    continue
                if frame is None:
                    continue
                frame_kind, frame_index, offset, payload = frame
                if frame_kind != wire_kind or frame_index != index:
                    continue
                if offset == expected and offset + len(payload) <= size:
                    output.seek(offset)
                    written = output.write(payload)
                    if written != len(payload):
                        raise OSError("short local output write")
                    expected += len(payload)
                    end_seen = False

            # A lost END is retried at offset=size; the device returns END even
            # when there are no data bytes left. Gaps resume at the first
            # offset not yet written.
        if expected != size or not end_seen:
            raise RuntimeError("device did not confirm the complete file")
        output.flush()
        os.fsync(output.fileno())
        output.truncate(size)
    except Exception:
        output.close()
        raise
    else:
        output.close()

    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    partial_path.rename(path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", help="USB Serial/JTAG COM port, for example COM3")
    parser.add_argument("--session", required=True,
                        help="16-hex-digit session ID printed by capture-status")
    parser.add_argument("--output-dir", type=Path, default=Path("capture-export"),
                        help="new local directory for exported files")
    parser.add_argument("--baud", type=int, default=115200,
                        help="serial setting (USB Serial/JTAG ignores the bit rate)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="seconds to wait for each bounded file stream")
    args = parser.parse_args(argv)
    if not SESSION_RE.fullmatch(args.session):
        parser.error("--session must be exactly 16 hexadecimal digits")
    session_id = args.session.upper()

    try:
        import serial
    except ImportError:
        print("pyserial is required: python -m pip install pyserial", file=sys.stderr)
        return 2

    try:
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = 0.5
        ser.write_timeout = 5
        ser.dtr = False
        ser.rts = False
        with ser:
            time.sleep(0.5)
            state, files, summary_size = _read_info(ser, session_id)
            print(f"session={session_id} logger_state={state} pcap_files={len(files)}")
            for index, size in sorted(files.items()):
                if size <= 0:
                    continue
                filename = f"capture-{session_id}-{index:04d}.pcap"
                path = args.output_dir / filename
                transfer_timeout = max(args.timeout, size / 8000.0 + 10.0)
                _stream_file(ser, session_id, "pcap", index, size, path,
                             transfer_timeout)
                print(f"saved {path} bytes={size}")
            if summary_size > 0:
                path = args.output_dir / f"session-{session_id}.txt"
                transfer_timeout = max(args.timeout, summary_size / 8000.0 + 10.0)
                _stream_file(ser, session_id, "summary", 0, summary_size, path,
                             transfer_timeout)
                print(f"saved {path} bytes={summary_size}")
    except Exception as exc:  # noqa: BLE001 - present serial/transfer failures to operator
        print(f"capture export failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
