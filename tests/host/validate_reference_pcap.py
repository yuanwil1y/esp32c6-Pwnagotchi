#!/usr/bin/env python3
"""Check the generated classic pcap with independent Wireshark CLI tools."""

import csv
import subprocess
import sys
from decimal import Decimal
from pathlib import Path


FIELDS = [
    "frame.number",
    "frame.cap_len",
    "frame.len",
    "frame.time_epoch",
    "radiotap.channel.freq",
    "radiotap.dbm_antsignal",
    "wlan.sa",
    "wlan.da",
    "eapol.type",
]


def run(args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout


def normalize(rows):
    normalized = []
    for row in rows:
        if len(row) != len(FIELDS):
            raise AssertionError(f"TShark returned {len(row)} fields: {row!r}")
        epoch_us = str(int(Decimal(row[3]) * Decimal(1_000_000)))
        normalized.append([
            row[0], row[1], row[2], epoch_us, row[4] or "-", row[5],
            row[6].lower() or "-", row[7].lower() or "-", row[8] or "-",
        ])
    return normalized


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_reference_pcap.py capture.pcap")
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
    print("== TShark fields (tab-separated) ==")
    print("\t".join(FIELDS))
    print(output.rstrip())
    actual = normalize(list(csv.reader(output.splitlines(), delimiter="\t")))

    expected_file = (Path(__file__).resolve().parents[1] /
                     "fixtures" / "phase3b" / "expected.tsv")
    with expected_file.open(newline="", encoding="utf-8") as expected_stream:
        expected_rows = list(csv.reader(expected_stream, delimiter="\t"))
    expected_header = expected_rows.pop(0)
    if expected_header != [
            "frame", "cap_len", "frame_len", "epoch_us", "channel_freq",
            "rssi_dbm", "wlan_sa", "wlan_da", "eapol_type"]:
        raise AssertionError(f"unexpected expected.tsv header: {expected_header}")
    if actual != expected_rows:
        print("== expected fields ==")
        print("\n".join("\t".join(row) for row in expected_rows))
        raise AssertionError("TShark decoded fields differ from expected.tsv")
    print(f"PASS: {len(actual)} frame rows match expected.tsv")

    malformed = run(["tshark", "-r", str(capture), "-Y", "_ws.malformed",
                     "-T", "fields", "-e", "frame.number"]).splitlines()
    malformed = [line.strip() for line in malformed if line.strip()]
    print("== malformed diagnostic frame numbers ==")
    print(",".join(malformed) if malformed else "(none)")
    if any(number != "10" for number in malformed):
        raise AssertionError("a non-truncated fixture was marked malformed")
    print("PASS: only the intentionally capture-truncated frame may be malformed")


if __name__ == "__main__":
    main()
