"""Focused regressions for cache identity, bounded extraction and section lookup.

Run with: python -m unittest tests.test_precision_regressions
"""
import gzip
import io
import os
import tarfile
import tempfile
import unittest

from rdis import containers
from rdis.arch import make
from rdis.loader import Image, Section


class PrecisionRegressionTests(unittest.TestCase):
    def test_section_lookup_has_no_arbitrary_256_mib_cutoff(self):
        # A long earlier segment remains valid even after a later, short segment has ended.
        sections = [
            Section("long", 0x1000, 0x30000000, 0, True),
            Section("short", 0x10000000, 0x10, 0, False),
        ]
        image = Image("fixture", "raw", make("x86_64"), 0, 0, sections, {}, {}, lambda va, n: b"", lambda va: 0)
        self.assertEqual(image.section_at(0x28000000).name, "long")
        self.assertIsNone(image.section_at(0x31000000))

    def test_decompression_rejects_oversized_output_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "one.gz")
            with gzip.open(source, "wb") as stream:
                stream.write(b"x")
            with self.assertRaisesRegex(ValueError, "exceeds"):
                containers._decompress(source, os.path.join(tmp, "cache"), 0)

    def test_tar_extraction_cache_tracks_archive_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "package.tar")
            cache_dir = os.path.join(tmp, "cache")

            def write_archive(payload):
                with tarfile.open(archive, "w") as tf:
                    info = tarfile.TarInfo("lib/sample.so")
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))

            write_archive(b"ELF!")
            first = containers._tar_extract(archive, "lib/sample.so", cache_dir, 1)
            with open(first, "rb") as stream:
                self.assertEqual(stream.read(), b"ELF!")

            write_archive(b"MACH")
            second = containers._tar_extract(archive, "lib/sample.so", cache_dir, 1)
            with open(second, "rb") as stream:
                self.assertEqual(stream.read(), b"MACH")
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
