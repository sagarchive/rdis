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


class AggregateStorageQuotaTests(unittest.TestCase):
    def test_atomic_extraction_cache_rejects_aggregate_overflow_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as td:
            first = os.path.join(td, "first.bin")
            second = os.path.join(td, "second.bin")
            containers._write_atomic(td, first, lambda stream: stream.write(b"abc"),
                                     max_total_bytes=3)
            with self.assertRaisesRegex(containers.StorageLimitError, "quota exceeded"):
                containers._write_atomic(td, second, lambda stream: stream.write(b"x"),
                                         max_total_bytes=3)
            self.assertTrue(os.path.isfile(first))
            self.assertFalse(os.path.exists(second))
            self.assertEqual(sorted(os.listdir(td)), ["first.bin"])

    def test_uploads_respect_aggregate_disk_quota(self):
        with tempfile.TemporaryDirectory() as td:
            local_session = {"docs": {}, "cur": None, "uploads": {}}
            with mock.patch.object(rdis_server._local, "session", local_session, create=True), \
                 mock.patch.dict(rdis_server.CFG, {"upload_dir": td, "max_mb": 2,
                                                   "max_upload_storage_mb": 1}), \
                 mock.patch.object(rdis_server, "slices", return_value=[]):
                rdis_server._upload(b"a" * (1 << 20), "first.bin")
                with self.assertRaisesRegex(containers.StorageLimitError, "quota exceeded"):
                    rdis_server._upload(b"b", "second.bin")
                self.assertEqual(len(os.listdir(td)), 1)

    def test_concurrent_duplicate_uploads_share_one_quota_entry(self):
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as td:
            payload = b"a" * (1 << 20)
            def upload():
                rdis_server._local.session = {"docs": {}, "cur": None, "uploads": {}}
                return rdis_server._upload(payload, "same.bin")
            with mock.patch.dict(rdis_server.CFG, {"upload_dir": td, "max_mb": 2,
                                                   "max_upload_storage_mb": 1}), \
                 mock.patch.object(rdis_server, "slices", return_value=[]):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: upload(), range(2)))
            self.assertEqual(results[0]["sha256"], results[1]["sha256"])
            self.assertEqual(len(os.listdir(td)), 1)

    def test_invalid_aggregate_storage_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            for invalid in (0, -1, True, 1.5):
                with self.subTest(max_total_mb=invalid):
                    with self.assertRaisesRegex(ValueError, "max_total_mb"):
                        containers.extract("missing.zip", "member", td, max_total_mb=invalid)


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



class ServerCacheIdentityTests(unittest.TestCase):
    def test_shared_analysis_invalidates_same_path_same_size_and_mtime(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "binary.bin")
            with open(path, "wb") as f:
                f.write(b"AAAA")
            original_stat = os.stat(path)
            old_cache = rdis_server.ANALYSES.copy()
            rdis_server.ANALYSES.clear()
            try:
                with mock.patch.object(rdis_server, "_analyze", side_effect=lambda *args: object()) as analyze:
                    first = rdis_server._shared_analysis(path, "arm64", True, True, True, "raw", 0)
                    with open(path, "wb") as f:
                        f.write(b"BBBB")
                    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                    second = rdis_server._shared_analysis(path, "arm64", True, True, True, "raw", 0)
                self.assertIsNot(first, second)
                self.assertEqual(analyze.call_count, 2)
            finally:
                rdis_server.ANALYSES.clear()
                rdis_server.ANALYSES.update(old_cache)


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


    def test_invalid_function_type_form_is_reported(self):
        # One type entry whose form byte is not 0x60.
        module = WasmModule(b"\0asm\x01\0\0\0\x01\x02\x01\x00")
        self.assertTrue(any("invalid function type form" in error for error in module.errors))

    def test_small_random_section_bodies_do_not_escape_low_level_errors(self):
        rng = random.Random(0x5741534D)
        header = b"\0asm\x01\0\0\0"
        for size in range(64):
            body = bytes(rng.randrange(256) for _ in range(size))
            section_id = rng.randrange(13)
            data = header + bytes([section_id, size]) + body
            with self.subTest(size=size, section=section_id):
                try:
                    WasmModule(data)
                except ValueError:
                    # Rejecting an invalid module/section is expected; low-level parser exceptions
                    # such as IndexError, AssertionError, or struct.error are not.
                    pass

    def test_malformed_section_is_reported_not_silently_discarded(self):
        # Type-section vector count has an unterminated LEB128.
        data = b"\0asm\x01\0\0\0\x01\x01\x80"
        module = WasmModule(data)
        self.assertTrue(any("truncated unsigned LEB128" in error for error in module.errors))



class FloatingTemporaryTests(unittest.TestCase):
    def test_pinned_float_memory_expressions_keep_floating_type(self):
        from rdis.lift import Lifter

        lifter = object.__new__(Lifter)
        lifter._temptype = {}
        self.assertEqual(lifter._scalar_type("v0 + *(float *)p * v1"), "float")
        self.assertEqual(lifter._scalar_type("v0 + *(double *)p * v1"), "double")


class PointerArithmeticTests(unittest.TestCase):
    def test_computed_element_address_uses_byte_arithmetic(self):
        from rdis.lift import Lifter

        lifter = object.__new__(Lifter)
        lifter._argtypes = {}
        lifter._ptrvars = {}
        lifter._temptype = {}
        lifter._localname = {}
        lifter._localtype = {}
        self.assertEqual(lifter._byte_ptr("&rdi[rsi_1]"), "(char *)&rdi[rsi_1]")


class DebuggerSafetyTests(unittest.TestCase):
    def test_lldb_quote_escapes_scalars_and_rejects_controls(self):
        from rdis.debug import _lldb_quote

        value = "a" + chr(92) + 'b"c'
        quoted = _lldb_quote(value)
        self.assertEqual(quoted, '"' + "a" + chr(92) * 2 + "b" + chr(92) + '"c' + '"')
        with self.assertRaisesRegex(ValueError, "control character"):
            _lldb_quote("symbol" + chr(10) + "run quit")


class CFGLayoutTests(unittest.TestCase):
    def test_overview_cfg_is_compact_and_detail_mode_preserves_more_instructions(self):
        from types import SimpleNamespace
        from rdis.render import to_dot

        class FakeArch:
            def kind(self, insn):
                return 0
            def data_refs(self, insn, state):
                return []
            def target(self, insn):
                return None

        class FakeProgram:
            arch = FakeArch()
            comments = {}
            objc = None
            functions = {}
            image = SimpleNamespace(imports={})

            def display(self, addr):
                return ""

            def call_target(self, insn, state):
                return None

            def strings(self):
                return {}

        instructions = [SimpleNamespace(address=0x1000 + i * 4, mnemonic="mov",
                                        op_str=f"r0, #{i}") for i in range(20)]
        block = SimpleNamespace(addr=0x1000, shown=instructions, insns=instructions, succs=[])
        func = SimpleNamespace(addr=0x1000, blocks={0x1000: block})
        prog = FakeProgram()
        overview = to_dot(prog, func)
        detail = to_dot(prog, func, detail=True)
        self.assertLess(overview.count(" mov "), detail.count(" mov "))
        self.assertIn('ranksep="0.62 equally"', overview)
        self.assertIn("pad=0.22", overview)

    def test_conditional_edges_are_labeled_and_entry_is_highlighted(self):
        from types import SimpleNamespace
        from rdis.arch import CJMP
        from rdis.render import to_dot

        class FakeArch:
            def kind(self, insn):
                return CJMP if hasattr(insn, "target") else 0
            def target(self, insn):
                return getattr(insn, "target", None)
            def data_refs(self, insn, state):
                return []

        class FakeProgram:
            arch = FakeArch()
            comments = {}
            objc = None
            functions = {}
            image = SimpleNamespace(imports={})

            def display(self, addr):
                return ""
            def call_target(self, insn, state):
                return getattr(insn, "target", None)
            def strings(self):
                return {}

        branch = SimpleNamespace(address=0x1000, mnemonic="jne", op_str="0x2000",
                                 target=0x2000)
        other = SimpleNamespace(address=0x2000, mnemonic="ret", op_str="")
        fallthrough = SimpleNamespace(address=0x3000, mnemonic="ret", op_str="")
        blocks = {
            0x1000: SimpleNamespace(shown=[branch], insns=[branch], succs=[0x2000, 0x3000]),
            0x2000: SimpleNamespace(shown=[other], insns=[other], succs=[]),
            0x3000: SimpleNamespace(shown=[fallthrough], insns=[fallthrough], succs=[]),
        }
        dot = to_dot(FakeProgram(), SimpleNamespace(addr=0x1000, blocks=blocks))
        self.assertIn('class="entry"', dot)
        self.assertIn('label="T"', dot)
        self.assertIn('label="F"', dot)


class RenderingSafetyTests(unittest.TestCase):
    def test_dot_label_escapes_newlines_quotes_and_backslashes(self):
        source = "line one\nline two \"quoted\" \\\\ tail"
        label = _dot_label(source)
        self.assertNotIn("\n", label)
        self.assertIn("\\n", label)
        self.assertIn('\\"quoted\\"', label)
        self.assertIn("\\\\", label)


if __name__ == "__main__":
    unittest.main()
