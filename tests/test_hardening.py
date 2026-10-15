"""Regression tests for content identity, bounded extraction, and interval lookup."""
import gzip
import io
import os
import tarfile
import tempfile
import unittest
import zipfile

from rdis import containers
from rdis.loader import Image, Section


class ContainerHardeningTests(unittest.TestCase):
    def test_decompression_rejects_output_over_limit_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as td:
            source = os.path.join(td, "payload.gz")
            with gzip.open(source, "wb") as f:
                f.write(b"x" * ((1 << 20) + 1))
            cache_dir = os.path.join(td, "cache")
            with self.assertRaisesRegex(ValueError, "exceeds"):
                containers._decompress(source, cache_dir, max_mb=1)
            self.assertEqual(os.listdir(cache_dir), [])

    def test_decompression_cache_tracks_content_not_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            source = os.path.join(td, "payload.gz")
            cache_dir = os.path.join(td, "cache")
            def write(payload):
                with gzip.open(source, "wb") as f:
                    f.write(payload)
            write(b"first")
            first = containers._decompress(source, cache_dir, 1)
            original_stat = os.stat(source)
            write(b"other")
            os.utime(source, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            second = containers._decompress(source, cache_dir, 1)
            with open(first, "rb") as f:
                self.assertEqual(f.read(), b"first")
            with open(second, "rb") as f:
                self.assertEqual(f.read(), b"other")
            self.assertNotEqual(first, second)

    def test_tar_cache_tracks_archive_content(self):
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "bundle.tar")
            cache_dir = os.path.join(td, "cache")
            def write(payload):
                with tarfile.open(archive, "w") as tar:
                    info = tarfile.TarInfo("libsample.so")
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            write(b"AAAA")
            first = containers._tar_extract(archive, "libsample.so", cache_dir, 1)
            st = os.stat(archive)
            write(b"BBBB")
            os.utime(archive, ns=(st.st_atime_ns, st.st_mtime_ns))
            second = containers._tar_extract(archive, "libsample.so", cache_dir, 1)
            with open(first, "rb") as f:
                self.assertEqual(f.read(), b"AAAA")
            with open(second, "rb") as f:
                self.assertEqual(f.read(), b"BBBB")
            self.assertNotEqual(first, second)

    def test_zip_extract_returns_complete_member(self):
        with tempfile.TemporaryDirectory() as td:
            archive = os.path.join(td, "bundle.zip")
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("libsample.so", b"sample")
            out = containers.extract(archive, "libsample.so", os.path.join(td, "cache"), 1)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"sample")

    def test_invalid_size_limit_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source = os.path.join(td, "payload.gz")
            with gzip.open(source, "wb") as f:
                f.write(b"x")
            for invalid in (0, -1, True, 1.5):
                with self.subTest(max_mb=invalid):
                    with self.assertRaises(ValueError):
                        containers._decompress(source, os.path.join(td, "cache"), invalid)


class SectionLookupTests(unittest.TestCase):
    def _image(self, sections):
        image = Image.__new__(Image)
        image.sections = sections
        return image

    def test_overlap_lookup_does_not_depend_on_fixed_scan_distance(self):
        old = Section("wide", 0, 0x40000000, 0, True)
        newer = Section("tiny", 0x10000000, 0x100, 0, False)
        image = self._image([old, newer])
        self.assertIs(image.section_at(0x30000000), old)
        self.assertIsNone(image.section_at(0x50000000))

    def test_section_end_is_exclusive_and_overlaps_prefer_latest_start(self):
        early = Section("early", 0x1000, 0x100, 0, True)
        late = Section("late", 0x1080, 0x100, 0, False)
        image = self._image([early, late])
        self.assertIs(image.section_at(0x1080), late)
        self.assertIs(image.section_at(0x117f), late)
        self.assertIsNone(image.section_at(0x1180))


if __name__ == "__main__":
    unittest.main()
