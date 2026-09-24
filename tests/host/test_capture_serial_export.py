#!/usr/bin/env python3
import base64
import sys
import tempfile
import types
import unittest
from pathlib import Path
import zlib
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import capture_serial_export as export  # noqa: E402


class CaptureSerialExportTests(unittest.TestCase):
    def test_production_c_golden_frame(self):
        frame = b"!PCAP,DATA,P,0,0,3,352441C2,YWJj\r\n"
        self.assertEqual(export.decode_data_line(frame), ("P", 0, 0, b"abc"))

    def test_reject_crc_mismatch(self):
        frame = "!PCAP,DATA,S,0,9,3,00000000,YWJj\r\n"
        with self.assertRaisesRegex(ValueError, "CRC"):
            export.decode_data_line(frame)

    def test_reject_bad_base64_or_length(self):
        with self.assertRaises(ValueError):
            export.decode_data_line("!PCAP,DATA,P,0,0,3,352441C2,YWJ!\r\n")
        with self.assertRaisesRegex(ValueError, "length"):
            export.decode_data_line("!PCAP,DATA,P,0,0,4,352441C2,YWJj\r\n")

    def test_info_session_filter_and_files(self):
        lines = [
            b"I (10) RADIO: unrelated log\r\n",
            b"!PCAP,INFO,SESSION,ERROR,9D808161AA2EF8C5,0\r\n",
            b"!PCAP,INFO,PCAP,0,216586\r\n",
            b"!PCAP,INFO,SUMMARY,532\r\n",
            b"!PCAP,INFO,END\r\n",
        ]
        state, files, summary_size = export.parse_info(
            lines, "9d808161aa2ef8c5")
        self.assertEqual(state, "ERROR")
        self.assertEqual(files, {0: 216586})
        self.assertEqual(summary_size, 532)

    def test_strip_terminal_control_sequences(self):
        line = "\x1b[32m!PCAP,INFO,END\x1b[0m\r\n"
        self.assertEqual(export.clean_line(line), "!PCAP,INFO,END")

    def test_stream_more_than_sixteen_chunks_and_retry_a_gap(self):
        class FakeSerial:
            def __init__(self, payload):
                self.payload = payload
                self.lines = []
                self.dropped_first_chunk = False

            def reset_input_buffer(self):
                self.lines.clear()

            def write(self, command):
                fields = command.decode("ascii").strip().split()
                _, session, kind, index, offset_text = fields
                offset = int(offset_text)
                first = True
                while offset < len(self.payload):
                    chunk = self.payload[offset:offset + 512]
                    if not (first and not self.dropped_first_chunk):
                        encoded = base64.b64encode(chunk).decode("ascii")
                        line = (f"!PCAP,DATA,{kind[0].upper()},{index},{offset},"
                                f"{len(chunk)},{zlib.crc32(chunk) & 0xffffffff:08X},"
                                f"{encoded}\r\n")
                        self.lines.append(line.encode("ascii"))
                    else:
                        self.dropped_first_chunk = True
                    first = False
                    offset += len(chunk)
                self.lines.append(
                    f"!PCAP,END,{kind[0].upper()},{index},{len(self.payload)}\r\n"
                    .encode("ascii"))
                return len(command)

            def flush(self):
                pass

            def readline(self):
                return self.lines.pop(0) if self.lines else b""

        payload = bytes((index * 17) & 0xff for index in range(512 * 20 + 23))
        serial = FakeSerial(payload)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture-test.pcap"
            export._stream_file(serial, "0123456789ABCDEF", "pcap", 0,
                                len(payload), path, 0.01)
            self.assertEqual(path.read_bytes(), payload)
            self.assertFalse(path.with_name(path.name + ".part").exists())
            self.assertTrue(serial.dropped_first_chunk)

    def test_partial_file_resumes_and_existing_output_is_not_overwritten(self):
        payload = bytes(range(256)) * 4

        class FakeSerial:
            def __init__(self, data):
                self.data = data
                self.lines = []

            def reset_input_buffer(self):
                self.lines.clear()

            def write(self, command):
                _, _, kind, index, offset_text = command.decode("ascii").strip().split()
                offset = int(offset_text)
                chunk = self.data[offset:offset + 512]
                if chunk:
                    encoded = base64.b64encode(chunk).decode("ascii")
                    self.lines.append(
                        f"!PCAP,DATA,{kind[0].upper()},{index},{offset},{len(chunk)},"
                        f"{zlib.crc32(chunk) & 0xffffffff:08X},{encoded}\r\n"
                        .encode("ascii"))
                self.lines.append(
                    f"!PCAP,END,{kind[0].upper()},{index},{len(self.data)}\r\n"
                    .encode("ascii"))
                return len(command)

            def flush(self):
                pass

            def readline(self):
                return self.lines.pop(0) if self.lines else b""

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture-test.pcap"
            partial = path.with_name(path.name + ".part")
            partial.write_bytes(payload[:512])
            export._stream_file(FakeSerial(payload), "0123456789ABCDEF",
                                "pcap", 0, len(payload), path, 0.01)
            self.assertEqual(path.read_bytes(), payload)
            self.assertFalse(partial.exists())
            with self.assertRaises(FileExistsError):
                export._stream_file(FakeSerial(payload), "0123456789ABCDEF",
                                    "pcap", 0, len(payload), path, 0.01)

    def test_main_uses_console_file_names_and_exports_session(self):
        payload = b"pcap-vector"

        class FakeSerial:
            def __init__(self):
                self.lines = []
                self.commands = []

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def reset_input_buffer(self):
                self.lines.clear()

            def write(self, command):
                self.commands.append(command.decode("ascii").strip())
                fields = self.commands[-1].split()
                if fields[0] == "capture-export-info":
                    self.lines.extend([
                        b"!PCAP,INFO,SESSION,STOPPED,0123456789ABCDEF,1\r\n",
                        b"!PCAP,INFO,PCAP,0,11\r\n",
                        b"!PCAP,INFO,SUMMARY,0\r\n",
                        b"!PCAP,INFO,END\r\n",
                    ])
                else:
                    _, _, kind, index, offset_text = fields
                    offset = int(offset_text)
                    chunk = payload[offset:]
                    encoded = base64.b64encode(chunk).decode("ascii")
                    tag = "P" if kind == "pcap" else "S"
                    self.lines.append(
                        f"!PCAP,DATA,{tag},{index},{offset},{len(chunk)},"
                        f"{zlib.crc32(chunk) & 0xffffffff:08X},{encoded}\r\n"
                        .encode("ascii"))
                    self.lines.append(
                        f"!PCAP,END,{tag},{index},{len(payload)}\r\n"
                        .encode("ascii"))
                return len(command)

            def flush(self):
                pass

            def readline(self):
                return self.lines.pop(0) if self.lines else b""

        fake_serial = FakeSerial()
        serial_module = types.SimpleNamespace(Serial=lambda: fake_serial)
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(sys.modules, {"serial": serial_module}), \
                    patch.object(export.time, "sleep"):
                result = export.main([
                    "COM3", "--session", "0123456789ABCDEF",
                    "--output-dir", directory,
                ])
            self.assertEqual(result, 0)
            self.assertEqual(fake_serial.commands[0],
                             "capture-export-info 0123456789ABCDEF")
            self.assertEqual(fake_serial.commands[1],
                             "capture-export 0123456789ABCDEF pcap 0 0")
            self.assertEqual(
                (Path(directory) / "capture-0123456789ABCDEF-0000.pcap").read_bytes(),
                payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
