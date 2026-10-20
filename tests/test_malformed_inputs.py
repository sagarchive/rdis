"""Regressions for malformed inputs found by tests/fuzz.py. Each case is the smallest hand-built reproduction."""
import gzip
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rdis import containers
from rdis.loader import open_image


def write(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def stored_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            z.writestr(name, data)
    return bytearray(buf.getvalue())


class LoaderRejectsUnknownCpus(unittest.TestCase):
    def test_elf_with_an_unrecognised_machine_number_is_a_value_error(self):
        import sleigh_fixtures as F
        data = bytearray(F.elf("ppc")[0])
        data[18:20] = (1044).to_bytes(2, "big")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError) as ctx:
                open_image(write(d, "odd.elf", data))
        self.assertIn("unsupported CPU", str(ctx.exception))

    def test_mach_o_with_an_unrecognised_cpu_type_is_a_value_error(self):
        header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x00ABCDEF, 0, 2, 0, 0, 0, 0)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                open_image(write(d, "odd.macho", header + b"\0" * 64))


class MachOWithoutSymbolTables(unittest.TestCase):
    def test_binary_without_a_dynamic_symbol_table_still_loads(self):
        """A Mach-O with no LC_DYSYMTAB (the fuzzer produced many) once crashed import resolution."""
        import shutil, subprocess
        cc = shutil.which("cc")
        if not cc or sys.platform != "darwin":
            self.skipTest("needs a macOS toolchain")
        with tempfile.TemporaryDirectory() as d:
            src = write(d, "t.c", b"int main(void){return 0;}\n")
            out = os.path.join(d, "t")
            subprocess.run([cc, src, "-o", out], check=True, capture_output=True)
            with open(out, "rb") as fh:
                data = bytearray(fh.read())
            ncmds = struct.unpack_from("<I", data, 16)[0]
            pos = 32
            for _ in range(ncmds):
                cmd, size = struct.unpack_from("<II", data, pos)
                if cmd == 0xB:                                    # LC_DYSYMTAB: turn it into an unknown command
                    struct.pack_into("<I", data, pos, 0x7F)
                pos += size
            path = write(d, "no-dysymtab", data)
            import lief
            self.assertIsNone(lief.MachO.parse(path).at(0).dynamic_symbol_command)
            self.assertTrue(open_image(path).sections)


class ArchivesFailWithValueError(unittest.TestCase):
    def check(self, data):
        with tempfile.TemporaryDirectory() as d:
            path = write(d, "bad.zip", data)
            for call in (lambda: containers.slices(path),
                         lambda: containers.extract(path, "lib/x.so", os.path.join(d, "out")),
                         lambda: containers.find_entry(path, "x.so")):
                try:
                    call()
                except (ValueError, KeyError):
                    pass

    def test_truncated_archive(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + bytes(64))])
        self.check(bytes(data[:-10]))

    def test_damaged_central_directory_magic(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + bytes(64))])
        data[data.rfind(b"PK\x01\x02") + 3] = 0xFF
        self.check(bytes(data))

    def test_damaged_local_header_magic(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + bytes(64))])
        data[3] = 0xFF
        self.check(bytes(data))

    def test_wrong_crc_surfaces_as_value_error_not_bad_zip_file(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + b"A" * 64)])
        data[data.find(b"A" * 8) + 3] ^= 0xFF
        with tempfile.TemporaryDirectory() as d:
            path = write(d, "crc.zip", data)
            with self.assertRaises(ValueError) as ctx:
                containers.extract(path, "lib/x.so", os.path.join(d, "out"))
        self.assertIn("malformed archive", str(ctx.exception))

    def test_negative_local_header_offset(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + bytes(64))])
        at = data.rfind(b"PK\x01\x02") + 42
        data[at:at + 4] = struct.pack("<I", 0xFFFFFFF0)
        self.check(bytes(data))

    def test_corrupt_gzip_stream_is_a_value_error_or_a_raw_choice(self):
        good = gzip.compress(b"\x7fELF" + bytes(256))
        with tempfile.TemporaryDirectory() as d:
            path = write(d, "bad.gz", good[:20] + b"\xff" * 8 + good[28:])
            try:
                containers.slices(path)
            except ValueError:
                pass

    def test_unsupported_zip_features_are_value_errors(self):
        data = stored_zip([("lib/x.so", b"\x7fELF" + bytes(64))])
        at = data.find(b"PK\x03\x04")
        data[at + 8:at + 10] = struct.pack("<H", 99)
        cd = data.rfind(b"PK\x01\x02")
        data[cd + 10:cd + 12] = struct.pack("<H", 99)
        with tempfile.TemporaryDirectory() as d:
            path = write(d, "method.zip", data)
            with self.assertRaises(ValueError) as ctx:
                containers.extract(path, "lib/x.so", os.path.join(d, "out"))
        self.assertIn("malformed archive", str(ctx.exception))

    def test_missing_files_keep_their_real_error(self):
        with self.assertRaises(FileNotFoundError):
            containers.slices("/no/such/archive.zip")


if __name__ == "__main__":
    unittest.main()
