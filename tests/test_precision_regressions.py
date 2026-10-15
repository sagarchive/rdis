"""Focused regressions for cache identity, bounded extraction and section lookup.

Run with: python -m unittest tests.test_precision_regressions
"""
import gzip
import io
import os
import tarfile
import tempfile
import zipfile
import unittest
from unittest.mock import patch

from rdis import cache, containers, render
from rdis.arch import make
from rdis.loader import Image, Section
from rdis import mcp_server, server


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

    def test_graphviz_labels_strip_control_characters_and_escape_quotes(self):
        label = render._dot_label("one" + chr(10) + "two" + chr(0) + '"' + chr(92) + "tail")
        self.assertNotIn(chr(10), label)
        self.assertNotIn(chr(0), label)
        self.assertIn(chr(92) + '"', label)
        self.assertIn(chr(92) * 2, label)

    def test_decompression_rejects_oversized_output_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "one.gz")
            with gzip.open(source, "wb") as stream:
                stream.write(b"x")
            with self.assertRaisesRegex(ValueError, "exceeds"):
                containers._decompress(source, os.path.join(tmp, "cache"), 0)

    def test_wasm_rejects_truncated_headers_and_section_framing(self):
        from rdis.wasm import WasmModule

        with self.assertRaisesRegex(ValueError, "header"):
            WasmModule(b"\0asm")
        with self.assertRaisesRegex(ValueError, "version"):
            WasmModule(b"\0asm\x02\0\0\0")
        with self.assertRaisesRegex(ValueError, "truncated WebAssembly section"):
            WasmModule(b"\0asm\x01\0\0\0\x01\x05\x60")

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

    def test_zip_extraction_cache_tracks_archive_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "package.zip")
            cache_dir = os.path.join(tmp, "cache")

            def write_archive(payload):
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
                    zf.writestr("lib/sample.so", payload)

            write_archive(b"ELF!")
            first = containers.extract(archive, "lib/sample.so", cache_dir, 1)
            with open(first, "rb") as stream:
                self.assertEqual(stream.read(), b"ELF!")
            write_archive(b"MACH")
            second = containers.extract(archive, "lib/sample.so", cache_dir, 1)
            with open(second, "rb") as stream:
                self.assertEqual(stream.read(), b"MACH")
            self.assertNotEqual(first, second)

    def test_zip_oversize_rejection_leaves_no_partial_cache_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "oversized.zip")
            cache_dir = os.path.join(tmp, "cache")
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("lib/sample.so", b"one byte")
            with self.assertRaisesRegex(ValueError, "larger than"):
                containers.extract(archive, "lib/sample.so", cache_dir, 0)
            self.assertFalse(os.path.exists(cache_dir))

    def test_compressed_cache_tracks_bytes_not_only_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "payload.gz")
            cache_dir = os.path.join(tmp, "cache")

            def write_compressed(payload):
                with open(source, "wb") as raw:
                    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream:
                        stream.write(payload)

            write_compressed(b"ELF!")
            first = containers._decompress(source, cache_dir, 1)
            old_stat = os.stat(source)
            write_compressed(b"MACH")
            os.utime(source, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
            second = containers._decompress(source, cache_dir, 1)
            with open(first, "rb") as stream:
                self.assertEqual(stream.read(), b"ELF!")
            with open(second, "rb") as stream:
                self.assertEqual(stream.read(), b"MACH")
            self.assertNotEqual(first, second)

    def test_web_shared_analysis_misses_on_same_metadata_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "sample.bin")
            with open(source, "wb") as stream:
                stream.write(b"AAAA")
            initial = os.stat(source)
            server.ANALYSES.clear()
            with patch.object(server, "_analyze", side_effect=[object(), object()]) as analyze:
                server._shared_analysis(source, "x86_64", False, False, False, "raw", 0)
                with open(source, "wb") as stream:
                    stream.write(b"BBBB")
                os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                server._shared_analysis(source, "x86_64", False, False, False, "raw", 0)
                self.assertEqual(analyze.call_count, 2)
            server.ANALYSES.clear()

    def test_mcp_cache_misses_on_same_metadata_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "sample.bin")
            with open(source, "wb") as stream:
                stream.write(b"AAAA")
            initial = os.stat(source)
            mcp_server._CACHE.clear()
            with patch.object(mcp_server, "open_image", return_value=object()):
                with patch.object(mcp_server.cache, "analyze", side_effect=[object(), object()]) as analyze:
                    mcp_server._prog(source, arch="x86_64", loader="raw", base=0)
                    with open(source, "wb") as stream:
                        stream.write(b"BBBB")
                    os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                    mcp_server._prog(source, arch="x86_64", loader="raw", base=0)
                    self.assertEqual(analyze.call_count, 2)
            mcp_server._CACHE.clear()

    def test_mcp_function_limit_is_validated_and_bounded(self):
        class FakeProgram:
            names = {i: f"fn_{i}" for i in range(20)}
            functions = {i: object() for i in range(20)}
            def display(self, address):
                return self.names[address]

        with patch.object(mcp_server, "_prog", return_value=FakeProgram()):
            self.assertEqual(len(mcp_server.t_list_functions("ignored", limit=100000)["functions"]), 20)
            self.assertEqual(mcp_server.t_list_functions("ignored", limit=-1)["functions"], [])
            with self.assertRaises(ValueError):
                mcp_server.t_list_functions("ignored", limit="all")

    def test_upload_token_metadata_is_bounded_per_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            session_state = {"uploads": {}}
            with patch.dict(server.CFG, {"upload_dir": tmp, "max_mb": 1, "max_uploads_per_session": 2}):
                with patch.object(server, "slices", return_value=[]):
                    server._local.session = session_state
                    try:
                        first = server._upload(b"one", "one.bin")["token"]
                        server._upload(b"two", "two.bin")
                        server._upload(b"three", "three.bin")
                        self.assertEqual(len(session_state["uploads"]), 2)
                        self.assertNotIn(first, session_state["uploads"])
                    finally:
                        del server._local.session

    def test_persistent_cache_hash_includes_new_and_changed_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = os.path.join(tmp, "cache.py")
            with open(module, "w") as stream:
                stream.write("# fixture cache module")
            with open(os.path.join(tmp, "analysis.py"), "w") as stream:
                stream.write("version = 1")
            previous = cache.__file__
            try:
                cache.__file__ = module
                first = cache._code_hash()
                with open(os.path.join(tmp, "objc.py"), "w") as stream:
                    stream.write("version = 1")
                second = cache._code_hash()
                with open(os.path.join(tmp, "objc.py"), "w") as stream:
                    stream.write("version = 2")
                third = cache._code_hash()
                self.assertNotEqual(first, second)
                self.assertNotEqual(second, third)
            finally:
                cache.__file__ = previous


if __name__ == "__main__":
    unittest.main()
