#!/usr/bin/env python3
"""Independently decode the deterministic capture emitted by test_sd_logger."""

import csv
import subprocess
import sys
from decimal import Decimal
from pathlib import Path


FIELDS = [
    "frame.number", "frame.cap_len", "frame.len", "frame.time_epoch",
    "radiotap.channel.freq", "radiotap.dbm_antsignal", "wlan.sa", "wlan.da",
    "eapol.type",
]


def run(args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_phase3c_capture.py capture.pcap")
    capture = Path(sys.argv[1])
    if not capture.is_file():
        raise SystemExit(f"capture not found: {capture}")

    print(run(["tshark", "--version"]).splitlines()[0])
    print("== capinfos ==")
    print(run(["capinfos", "-c", "-s", "-l", str(capture)]).rstrip())
    command = ["tshark", "-r", str(capture), "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(["-e", field])
    output = run(command)
    print("== TShark fields ==")
    print("\t".join(FIELDS))
    print(output.rstrip())
    actual = []
    for row in csv.reader(output.splitlines(), delimiter="\t"):
        if len(row) != len(FIELDS):
            raise AssertionError(f"TShark returned {len(row)} fields: {row!r}")
        epoch_us = str(int(Decimal(row[3]) * Decimal(1_000_000)))
        actual.append([
            row[0], row[1], row[2], epoch_us, row[4] or "-", row[5],
            row[6].lower() or "-", row[7].lower() or "-", row[8] or "-",
        ])

    expected_path = (Path(__file__).resolve().parents[1] / "fixtures" /
                     "phase3c" / "expected.tsv")
    with expected_path.open(newline="", encoding="utf-8") as stream:
        expected = list(csv.reader(stream, delimiter="\t"))
    header = expected.pop(0)
    if header != ["frame", "cap_len", "frame_len", "epoch_us", "channel_freq",
                  "rssi_dbm", "wlan_sa", "wlan_da", "eapol_type"]:
        raise AssertionError(f"unexpected expected.tsv header: {header}")
    if actual != expected:
        raise AssertionError(f"decoded fields differ: actual={actual!r} expected={expected!r}")
    if len(actual) != 1 or int(actual[0][1]) >= int(actual[0][2]):
        raise AssertionError("expected one honest capture-truncated frame")
    print("PASS: frame lengths, timestamp, channel, RSSI, addresses and EAPOL type match")

    malformed = run(["tshark", "-r", str(capture), "-Y", "_ws.malformed",
                     "-T", "fields", "-e", "frame.number"]).strip()
    print("== malformed diagnostics ==")
    print(malformed or "(none)")
    if malformed:
        raise AssertionError("synthetic valid padded EAPOL Start was marked malformed")

    summary_path = capture.with_suffix(".summary.txt")
    if not summary_path.is_file():
        raise AssertionError(f"summary missing: {summary_path}")
    summary = summary_path.read_text(encoding="utf-8")
    if "accepted=1\nserialized=1\nwritten=1\nflushed=1\n" not in summary:
        raise AssertionError("summary counters do not match the one-frame capture")
    print("PASS: sidecar reports accepted=serialized=written=flushed=1")


if __name__ == "__main__":
    main()
