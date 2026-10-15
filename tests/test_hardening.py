"""Regression tests for content identity, bounded extraction, and interval lookup."""
import gzip
import io
import os
import random
import socket
import tarfile
import threading
import tempfile
import unittest
import zipfile
from unittest import mock

from rdis import containers, server as rdis_server
from rdis.loader import Image, Section
from rdis.wasm import WasmModule, _name, _uleb
from rdis.render import _dot_label
from rdis import mcp_server


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

    def test_randomized_lookup_matches_linear_interval_oracle(self):
        rng = random.Random(0x52444953)
        sections = [
            Section(f"s{i}", rng.randrange(0, 0x50000000), rng.randrange(0, 0x50000000), i, bool(i & 1))
            for i in range(300)
        ]
        image = self._image(sections)
        for _ in range(1000):
            address = rng.randrange(0, 0x80000000)
            matches = [(s.va, i, s) for i, s in enumerate(sections)
                       if s.size > 0 and s.va <= address < s.va + s.size]
            expected = max(matches, key=lambda item: (item[0], item[1]))[2] if matches else None
            self.assertIs(image.section_at(address), expected, f"address={address:#x}")


class CacheIdentityTests(unittest.TestCase):
    def setUp(self):
        self.old_cache = mcp_server._CACHE.copy()
        mcp_server._CACHE.clear()

    def tearDown(self):
        mcp_server._CACHE.clear()
        mcp_server._CACHE.update(self.old_cache)

    def test_mcp_cache_invalidates_same_path_same_size_and_mtime(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "input.bin")
            with open(path, "wb") as f:
                f.write(b"AAAA")
            original_stat = os.stat(path)
            analyzed = []
            with mock.patch.object(mcp_server, "open_image", side_effect=lambda *a, **k: object()), \
                 mock.patch.object(mcp_server.cache, "analyze", side_effect=lambda image: analyzed.append(image) or object()):
                first = mcp_server._prog(path)
                with open(path, "wb") as f:
                    f.write(b"BBBB")
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                second = mcp_server._prog(path)
            self.assertIsNot(first, second)
            self.assertEqual(len(analyzed), 2)

    def test_mcp_cache_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(mcp_server, "open_image", side_effect=lambda *a, **k: object()), \
                 mock.patch.object(mcp_server.cache, "analyze", side_effect=lambda image: object()):
                for i in range(mcp_server._CACHE_MAX + 2):
                    path = os.path.join(td, f"input-{i}.bin")
                    with open(path, "wb") as f:
                        f.write(str(i).encode())
                    mcp_server._prog(path)
            self.assertEqual(len(mcp_server._CACHE), mcp_server._CACHE_MAX)


class HttpFramingTests(unittest.TestCase):
    def setUp(self):
        self.old_cfg = dict(rdis_server.CFG)
        rdis_server.CFG.update(single_user=True, request_timeout=2, max_workers=4)
        self.httpd = rdis_server.BoundedThreadingHTTPServer(("127.0.0.1", 0), rdis_server.Handler, max_workers=4)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        rdis_server.CFG.clear()
        rdis_server.CFG.update(self.old_cfg)

    def _request(self, raw):
        with socket.create_connection(self.httpd.server_address, timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(raw)
            sock.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response.extend(chunk)
            return bytes(response)

    def test_chunked_transfer_encoding_is_rejected(self):
        response = self._request(
            b"POST /api/upload HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"Transfer-Encoding is not supported", response)

    def test_incomplete_content_length_is_rejected(self):
        response = self._request(
            b"POST /api/upload HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 10\r\n"
            b"\r\nabc"
        )
        self.assertIn(b"400 Bad Request", response)
        self.assertIn(b"incomplete request body", response)


class WasmBoundsTests(unittest.TestCase):
    def test_truncated_header_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "header"):
            WasmModule(b"\0asm\x01")

    def test_section_length_cannot_extend_past_module(self):
        # Valid magic/version, section 1 claims five bytes but only one byte follows.
        data = b"\0asm\x01\0\0\0\x01\x05\x60"
        with self.assertRaisesRegex(ValueError, "exceeds module bounds"):
            WasmModule(data)

    def test_truncated_section_length_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "LEB128"):
            WasmModule(b"\0asm\x01\0\0\0\x01")

    def test_leb_and_name_helpers_reject_truncated_inputs(self):
        with self.assertRaisesRegex(ValueError, "LEB128"):
            _uleb(b"", 0)
        with self.assertRaisesRegex(ValueError, "name"):
            _name(b"\x05ab", 0)

    def test_malformed_section_is_reported_not_silently_discarded(self):
        # Type-section vector count has an unterminated LEB128.
        data = b"\0asm\x01\0\0\0\x01\x01\x80"
        module = WasmModule(data)
        self.assertTrue(any("truncated unsigned LEB128" in error for error in module.errors))



class RenderingSafetyTests(unittest.TestCase):
    def test_dot_label_escapes_newlines_quotes_and_backslashes(self):
        label = _dot_label('first\\nsecond "quoted" \\\\ tail')
        self.assertNotIn("\\n", label.replace("\\\\n", ""))
        self.assertIn("\\\\n", label)
        self.assertIn('\\\\"quoted\\\\"', label)
        self.assertIn("\\\\\\\\", label)



if __name__ == "__main__":
    unittest.main()
