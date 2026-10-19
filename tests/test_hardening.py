"""Regression tests for content identity, bounded extraction, and interval lookup."""
import gzip
import json
import io
import os
import random
import socket
import tarfile
import threading
import tempfile
import unittest
import zipfile
import warnings
from types import SimpleNamespace
from contextlib import redirect_stdout
from unittest import mock

from rdis import containers, server as rdis_server
from rdis.analysis import Program, _LayerXrefs
from rdis.loader import Image, Section
from rdis.wasm import WasmModule, _name, _uleb
from rdis.render import _dot_label, callgraph
from rdis.arch import CALL
from rdis import mcp_server, console, __main__ as rdis_cli


class ExportImportIdentityTests(unittest.TestCase):
    @staticmethod
    def _program(path):
        image = SimpleNamespace(
            path=path, format="raw", arch=SimpleNamespace(name="x86_64"),
            symbols={}, imports={}, thumb=set(), entry=0x1000, base=0,
            sections=[],
        )
        return Program(image)

    def test_export_identity_allows_same_bytes_and_rejects_replaced_binary(self):
        with tempfile.TemporaryDirectory() as td:
            source = os.path.join(td, "source.bin")
            target = os.path.join(td, "target.bin")
            with open(source, "wb") as f:
                f.write(b"same exact binary bytes")
            with open(target, "wb") as f:
                f.write(b"same exact binary bytes")
            exporting = self._program(source)
            exporting.rename(0x1000, "good_name")
            exported = {"rdis_db": 1, "name": "source", "arch": exporting.arch.name,
                        **rdis_server._db_dict(exporting)}

            importing = self._program(target)
            with mock.patch.object(rdis_server, "prog", return_value=importing), \
                 mock.patch.object(rdis_server, "_persist"):
                rdis_server.post("import", exported)
            self.assertEqual(importing.user_names, {0x1000: "good_name"})

            with open(target, "wb") as f:
                f.write(b"different binary bytes")
            importing2 = self._program(target)
            with mock.patch.object(rdis_server, "prog", return_value=importing2), \
                 mock.patch.object(rdis_server, "_persist"):
                with self.assertRaisesRegex(ValueError, "different binary"):
                    rdis_server.post("import", exported)
            self.assertEqual(importing2.user_names, {})

    def test_legacy_export_requires_separate_explicit_import_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            with open(binary, "wb") as f:
                f.write(b"payload")
            importing = self._program(binary)
            legacy = {"rdis_db": 1, "arch": "x86_64", "names": {"4096": "legacy_name"}}
            with mock.patch.object(rdis_server, "prog", return_value=importing), \
                 mock.patch.object(rdis_server, "_persist"):
                with self.assertRaisesRegex(ValueError, "no binary digest"):
                    rdis_server.post("import", legacy)
                self.assertEqual(importing.user_names, {})
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    rdis_server.post("import", legacy, query={"allow_legacy": ["1"]})
            self.assertEqual(importing.user_names, {0x1000: "legacy_name"})
            self.assertTrue(any("cannot be proven" in str(w.message) for w in caught))


class SidecarIdentityTests(unittest.TestCase):
    @staticmethod
    def _program(path, arch="x86_64", fmt="raw"):
        image = SimpleNamespace(
            path=path, format=fmt, arch=SimpleNamespace(name=arch),
            symbols={}, imports={}, thumb=set(), entry=0,
        )
        return Program(image)

    def test_matching_rdb_restores_annotations_for_the_same_binary(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            sidecar = binary + ".rdb"
            with open(binary, "wb") as f:
                f.write(b"exact-original-content")
            writer = self._program(binary)
            writer.rename(0x1000, "verified_name")
            writer.comment(0x1000, "verified comment")
            writer.bookmark(0x1000)
            writer.set_type(0x2000, "ascii")
            writer.save(sidecar)
            with open(sidecar, encoding="utf-8") as f:
                metadata = json.load(f)
            self.assertEqual(metadata["rdb_version"], 2)
            self.assertEqual(len(metadata["binary_sha256"]), 64)

            reader = self._program(binary)
            reader.load(sidecar)
            self.assertEqual(reader.user_names, {0x1000: "verified_name"})
            self.assertEqual(reader.comments, {0x1000: "verified comment"})
            self.assertEqual(reader.bookmarks, {0x1000})
            self.assertEqual(reader.user_types, {0x2000: "ascii"})

    def test_rdb_round_trip_requires_exact_binary_content(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            sidecar = binary + ".rdb"
            with open(binary, "wb") as f:
                f.write(b"AAAA")
            original = os.stat(binary)
            writer = self._program(binary)
            writer.rename(0x1000, "trusted_name")
            writer.comment(0x1000, "annotation from this exact binary")
            writer.save(sidecar)

            # Same path, format, architecture, size and preserved mtime is still a different binary.
            with open(binary, "wb") as f:
                f.write(b"BBBB")
            os.utime(binary, ns=(original.st_atime_ns, original.st_mtime_ns))
            reader = self._program(binary)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                reader.load(sidecar)
            self.assertEqual(reader.user_names, {})
            self.assertEqual(reader.comments, {})
            self.assertTrue(any("binary content" in str(w.message).lower() for w in caught))
            self.assertTrue(os.path.exists(sidecar), "mismatched sidecar must be preserved for recovery")

    def test_rdb_identity_checks_path_format_and_architecture(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            other = os.path.join(td, "other.bin")
            sidecar = binary + ".rdb"
            for path in (binary, other):
                with open(path, "wb") as f:
                    f.write(b"same payload")
            writer = self._program(binary)
            writer.rename(0x1000, "only_for_original")
            writer.save(sidecar)

            for reader in (self._program(other), self._program(binary, arch="arm64"),
                           self._program(binary, fmt="elf")):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    reader.load(sidecar)
                self.assertEqual(reader.user_names, {})
                self.assertTrue(caught, "identity mismatch should be visible to the caller")

    def test_v2_sidecar_without_digest_is_rejected_even_with_legacy_opt_in(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            sidecar = binary + ".rdb"
            with open(binary, "wb") as f:
                f.write(b"payload")
            with open(sidecar, "w", encoding="utf-8") as f:
                json.dump({"rdb_version": 2, "path": binary, "format": "raw",
                           "arch": "x86_64", "names": {"4096": "must_not_load"}}, f)
            reader = self._program(binary)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                reader.load(sidecar, allow_legacy=True)
            self.assertEqual(reader.user_names, {})
            self.assertTrue(any("digest is malformed" in str(w.message) for w in caught))

    def test_legacy_rdb_can_be_imported_only_by_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            sidecar = binary + ".rdb"
            with open(binary, "wb") as f:
                f.write(b"payload")
            with open(sidecar, "w", encoding="utf-8") as f:
                json.dump({"path": binary, "format": "raw", "arch": "x86_64",
                           "names": {"4096": "legacy_name"}}, f)
            reader = self._program(binary)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                reader.load(sidecar, allow_legacy=True)
            self.assertEqual(reader.user_names, {0x1000: "legacy_name"})
            self.assertTrue(any("cannot be proven" in str(w.message) for w in caught))

    def test_unfingerprinted_legacy_rdb_is_not_applied_implicitly(self):
        with tempfile.TemporaryDirectory() as td:
            binary = os.path.join(td, "program.bin")
            sidecar = binary + ".rdb"
            with open(binary, "wb") as f:
                f.write(b"payload")
            with open(sidecar, "w") as f:
                json.dump({"path": binary, "format": "raw", "arch": "x86_64",
                           "names": {"4096": "legacy_name"}}, f)
            reader = self._program(binary)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                reader.load(sidecar)
            self.assertEqual(reader.user_names, {})
            self.assertTrue(any("legacy" in str(w.message).lower() for w in caught))


class CopyOnWriteXrefTests(unittest.TestCase):
    def test_get_and_items_mutation_never_changes_shared_base_xrefs(self):
        base = {0x1000: {(0x2000, "data")}, 0x3000: {(0x4000, "call")}}
        overlay = _LayerXrefs(base)
        overlay.get(0x1000).add((0x5000, "jmp"))
        dict(overlay.items())[0x3000].add((0x6000, "tail"))
        self.assertEqual(base[0x1000], {(0x2000, "data")})
        self.assertEqual(base[0x3000], {(0x4000, "call")})
        self.assertIn((0x5000, "jmp"), overlay[0x1000])
        self.assertIn((0x6000, "tail"), overlay[0x3000])


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


class MalformedInputFuzzSmokeTests(unittest.TestCase):
    def test_deterministic_webassembly_mutations_never_leak_low_level_exceptions(self):
        import random
        from rdis.wasm import WasmModule

        rng = random.Random(0x52444953)
        valid_header = b"\0asm\x01\0\0\0"
        corpus = [b"", b"\0asm", valid_header]
        for n in range(256):
            payload = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 96)))
            corpus.append((valid_header + payload) if n % 2 == 0 else payload)
        for index, payload in enumerate(corpus):
            with self.subTest(case=index):
                try:
                    WasmModule(payload)
                except ValueError:
                    pass


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

    def test_unresolved_conditional_target_is_not_mislabeled_as_not_taken(self):
        from types import SimpleNamespace
        from rdis.arch import CJMP
        from rdis.render import to_dot

        class FakeArch:
            def kind(self, insn):
                return CJMP if getattr(insn, "conditional", False) else 0
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

        branch = SimpleNamespace(address=0x1000, mnemonic="b.cond", op_str="?",
                                 conditional=True, target=None)
        ret1 = SimpleNamespace(address=0x2000, mnemonic="ret", op_str="")
        ret2 = SimpleNamespace(address=0x3000, mnemonic="ret", op_str="")
        blocks = {
            0x1000: SimpleNamespace(shown=[branch], insns=[branch], succs=[0x2000, 0x3000]),
            0x2000: SimpleNamespace(shown=[ret1], insns=[ret1], succs=[]),
            0x3000: SimpleNamespace(shown=[ret2], insns=[ret2], succs=[]),
        }
        dot = to_dot(FakeProgram(), SimpleNamespace(addr=0x1000, blocks=blocks))
        self.assertIn("color=gray", dot)
        self.assertNotIn('label="T"', dot)
        self.assertNotIn('label="F"', dot)


class BrowserCFGSourceTests(unittest.TestCase):
    def test_cfg_fit_zoom_export_and_controls_are_regression_gated(self):
        from pathlib import Path

        html = (Path(__file__).resolve().parents[1] / "rdis" / "web" / "index.html").read_text()
        self.assertIn('svg.querySelector("g.graph")', html)
        self.assertIn('zoomAt(Math.pow(1.0018, -delta)', html)
        self.assertIn('target.getBoundingClientRect()', html)
        self.assertIn('rect.width, availH / rect.height', html)
        self.assertIn('"--mono"', html)
        self.assertIn('Math.max(0.005, scale * factor)', html)
        self.assertIn('Shift+wheel to pan', html)
        self.assertIn('new XMLSerializer().serializeToString(copy)', html)
        self.assertIn('const resolve = s => s.replace(/var\\(', html)
        self.assertIn('aria-label="Fit graph to view"', html)
        self.assertIn('Control-flow graph. Drag to pan', html)
        self.assertIn('Call graph. Select a function', html)
        self.assertIn('data-mode="callgraph"', html)
        self.assertIn('async function showCallGraph(addr, options = {})', html)
        self.assertIn('api("callgraph"', html)
        self.assertIn('n.setAttribute("tabindex", "0")', html)
        self.assertIn('n.setAttribute("role", "button")', html)
        self.assertIn('.node:focus polygon, .node:focus path', html)
        self.assertIn('.node.cur polygon, .node.cur path', html)
        self.assertIn('box-shadow:0 2px 10px rgba(0,0,0,.25);z-index:5', html)
        self.assertIn('e.key === "Enter" && e.shiftKey', html)
        self.assertIn('n.dispatchEvent(new MouseEvent("click"', html)
        self.assertIn('replace(/[^a-zA-Z0-9._-]+/g, "_")', html)


class RenderingSafetyTests(unittest.TestCase):
    def test_dot_label_escapes_newlines_quotes_and_backslashes(self):
        source = "line one\nline two \"quoted\" \\\\ tail"
        label = _dot_label(source)
        self.assertNotIn("\n", label)
        self.assertIn("\\n", label)
        self.assertIn('\\"quoted\\"', label)
        self.assertIn("\\\\", label)



class CallGraphTests(unittest.TestCase):
    class FakeImage:
        def __init__(self, functions):
            self.imports = {0x9000: "puts"}
            self.symbols = {}
            self._functions = functions

        def is_code(self, addr):
            return addr in self._functions

    class FakeArch:
        def kind(self, insn):
            return insn.kind

        def target(self, insn):
            return insn.target

        def data_refs(self, insn, state):
            return []

    class FakeProgram:
        def __init__(self, function_specs, xrefs, site_owners, names=None):
            self.functions = {}
            self.names = names or {}
            self.xrefs = xrefs
            self.site_owners = site_owners
            self.arch = CallGraphTests.FakeArch()
            self.image = None
            for addr, spec in function_specs.items():
                blocks = {}
                for site, target, kind in spec.get("insns", []):
                    insn = SimpleNamespace(address=site, target=target, kind=kind,
                                           mnemonic="call", op_str=hex(target))
                    blocks.setdefault(site, SimpleNamespace(addr=site, end=site + 1, insns=[])).insns.append(insn)
                    self.site_owners[site] = addr
                self.functions[addr] = SimpleNamespace(addr=addr, calls=set(spec.get("calls", ())), blocks=blocks)
            self.image = CallGraphTests.FakeImage(self.functions)

        def display(self, addr):
            return self.names.get(addr, "")

        def resolve(self, value):
            if isinstance(value, int):
                if value in self.functions or value in self.image.imports:
                    return value
                raise KeyError(f"unknown address: {value:#x}")
            text = str(value)
            try:
                addr = int(text, 0)
                if addr in self.functions or addr in self.image.imports:
                    return addr
            except ValueError:
                pass
            for addr, name in self.names.items():
                if name == text:
                    return addr
            raise KeyError(f"unknown symbol: {text}")

        def xrefs_to(self, addr):
            return sorted(self.xrefs.get(addr, ()))

        def function_at(self, addr):
            owner = self.site_owners.get(addr)
            return self.functions.get(owner)

        def call_target(self, insn, regs=None):
            return insn.target

    @classmethod
    def make_program(cls):
        specs = {
            0x1000: {"calls": {0x1000, 0x2000}, "insns": [
                (0x1004, 0x2000, CALL), (0x1008, 0x1000, CALL), (0x100C, 0x9000, CALL)
            ]},
            0x2000: {"calls": set(), "insns": [(0x2004, 0x9000, CALL)]},
            0x3000: {"calls": {0x1000}, "insns": [(0x3010, 0x1000, CALL)]},
            0x4000: {"calls": {0x3000}, "insns": [(0x4010, 0x3000, CALL)]},
        }
        xrefs = {
            0x1000: [(0x1008, "call"), (0x3010, "call")],
            0x2000: [(0x1004, "call")],
            0x3000: [(0x4010, "call")],
            0x9000: [(0x100C, "call"), (0x2004, "call")],
        }
        return cls.FakeProgram(specs, xrefs, {})

    def test_callgraph_has_addressed_callers_callees_imports_and_recursion(self):
        prog = self.make_program()
        result = callgraph(prog, prog.functions[0x1000], direction="both", depth=1)
        self.assertEqual(result["addr"], "0x1000")
        self.assertFalse(result["truncated"])
        self.assertIn('digraph "callgraph"', result["dot"])
        self.assertIn('"0x3000" -> "0x1000"', result["dot"])
        self.assertIn('"0x1000" -> "0x2000"', result["dot"])
        self.assertIn('"0x1000" -> "0x9000"', result["dot"])
        self.assertIn('"0x1000" -> "0x1000"', result["dot"], "recursive edge should be preserved")
        self.assertIn('class="cg-import"', result["dot"])
        self.assertEqual(result["nodes"], 4)

    def test_callgraph_depth_and_direction_limit_neighborhood(self):
        prog = self.make_program()
        callers = callgraph(prog, prog.functions[0x1000], direction="callers", depth=1)
        self.assertIn('"0x3000" -> "0x1000"', callers["dot"])
        self.assertNotIn('"0x1000" -> "0x2000"', callers["dot"])
        self.assertNotIn('"0x1000" -> "0x9000"', callers["dot"])
        self.assertNotIn('"0x4000" -> "0x3000"', callers["dot"])

        deeper = callgraph(prog, prog.functions[0x1000], direction="callers", depth=2)
        self.assertIn('"0x4000" -> "0x3000"', deeper["dot"])
        self.assertEqual(deeper["depth"], 2)

        callees = callgraph(prog, prog.functions[0x1000], direction="callees", depth=1)
        self.assertIn('"0x1000" -> "0x2000"', callees["dot"])
        self.assertNotIn('"0x3000" -> "0x1000"', callees["dot"])

    def test_callgraph_bounds_large_neighborhood_and_reports_truncation(self):
        specs = {0x1000: {"calls": set(range(0x2000, 0x2082)), "insns": []}}
        for addr in range(0x2000, 0x2082):
            specs[addr] = {"calls": set(), "insns": []}
        prog = self.FakeProgram(specs, {}, {})
        result = callgraph(prog, prog.functions[0x1000], direction="callees", depth=1)
        self.assertEqual(result["nodes"], result["node_limit"])
        self.assertLessEqual(result["edges"], result["edge_limit"])
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["nodes"], 120)

    def test_callgraph_dot_escapes_untrusted_names_and_rejects_bad_controls(self):
        prog = self.make_program()
        prog.names[0x1000] = 'evil"\\n"; injected [shape=plaintext]'
        result = callgraph(prog, prog.functions[0x1000])
        self.assertIn('id="cg_function_1000"', result["dot"])
        self.assertNotIn('evil"\\n"; injected [shape=plaintext]', result["dot"])
        self.assertIn(chr(92) + '"', result["dot"])

    def test_callgraph_api_validates_direction_and_depth(self):
        from rdis.server import _api_doc

        prog = self.make_program()
        query = {"func": ["0x1000"], "direction": ["callees"], "depth": ["2"]}
        arg = lambda key, default=None: query.get(key, [default])[0]
        with mock.patch("rdis.server._func", return_value=prog.functions[0x1000]) as lookup:
            result = _api_doc("callgraph", query, arg, prog)
            self.assertEqual(result["direction"], "callees")
            self.assertEqual(result["depth"], 2)
            lookup.assert_called_once()

        # Bad arguments must be rejected before function resolution. This prevents an invalid
        # function id or other lookup error from masking the request-validation response.
        for bad in ({"func": ["0x1000"], "direction": ["up"]},
                    {"func": ["0x1000"], "depth": ["9"]},
                    {"func": ["0x1000"], "depth": ["not-a-number"]},
                    {"direction": ["up"]}):
            bad_arg = lambda key, default=None, q=bad: q.get(key, [default])[0]
            with self.subTest(query=bad), mock.patch(
                "rdis.server._func", side_effect=AssertionError("lookup should not happen before validation")
            ), self.assertRaises(ValueError):
                _api_doc("callgraph", bad, bad_arg, prog)


class CallGraphSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.prog = CallGraphTests.make_program()

    def test_console_callgraph_returns_dot_and_summary(self):
        result = console.run(self.prog, "callgraph 0x1000 callers 2")
        self.assertIn('digraph "callgraph"', result["output"])
        self.assertEqual(result["goto"], "0x1000")
        self.assertEqual(result["nodes"], 3)
        self.assertEqual(result["summary"], "callers, depth 2: 3 nodes, 3 edges")
        self.assertTrue(result["output"].endswith("}"))

    def test_console_callgraph_rejects_bad_direction_depth_and_extra_args(self):
        for line, expected in (
            ("callgraph 0x1000 upward", "direction must be one of"),
            ("callgraph 0x1000 both 0", "depth must be from 1 to 4"),
            ("callgraph 0x1000 both nope", "depth must be an integer"),
            ("callgraph 0x1000 both 1 extra", "usage: callgraph"),
        ):
            with self.subTest(line=line):
                self.assertIn(expected, console.run(self.prog, line)["output"])

    def test_cli_callgraph_outputs_dot_and_json_metadata(self):
        with mock.patch.object(rdis_cli.containers, "slices", return_value=[]), \
             mock.patch.object(rdis_cli, "build", return_value=self.prog):
            output = io.StringIO()
            with redirect_stdout(output):
                rdis_cli.main(["fixture.bin", "-f", "0x1000", "--callgraph",
                               "--callgraph-direction", "callees", "--callgraph-depth", "2"])
            self.assertIn('digraph "callgraph"', output.getvalue())

            output = io.StringIO()
            with redirect_stdout(output):
                rdis_cli.main(["fixture.bin", "-f", "0x1000", "--callgraph", "--json"])
            data = json.loads(output.getvalue())
            self.assertEqual(data["direction"], "both")
            self.assertEqual(data["depth"], 1)
            self.assertIn('digraph "callgraph"', data["dot"])
            self.assertIn("node_limit", data)

    def test_mcp_callgraph_returns_bounded_structured_graph(self):
        with mock.patch.object(mcp_server, "_prog", return_value=self.prog) as load:
            result = mcp_server.t_callgraph("fixture.bin", "0x1000", direction="callers", depth=2)
        load.assert_called_once_with("fixture.bin", None)
        self.assertIn('digraph "callgraph"', result["dot"])
        self.assertEqual(result["direction"], "callers")
        self.assertEqual(result["depth"], 2)
        self.assertEqual(result["node_limit"], render.CALLGRAPH_MAX_NODES)
        self.assertIn("callgraph", mcp_server.TOOLS)
        listed = mcp_server._handle({"method": "tools/list", "params": {}})
        tool = next(t for t in listed["tools"] if t["name"] == "callgraph")
        self.assertEqual(tool["inputSchema"]["properties"]["direction"]["type"], "string")
        self.assertEqual(tool["inputSchema"]["properties"]["depth"]["type"], "integer")
        with mock.patch.object(mcp_server, "_prog", return_value=self.prog):
            response = mcp_server._handle({"method": "tools/call", "params": {
                "name": "callgraph", "arguments": {
                    "path": "fixture.bin", "func": "0x1000", "direction": "callees", "depth": 2
                }
            }})
        rpc_result = json.loads(response["content"][0]["text"])
        self.assertIn('digraph "callgraph"', rpc_result["dot"])
        self.assertEqual(rpc_result["direction"], "callees")

    def test_mcp_callgraph_rejects_bad_arguments_before_loading_binary(self):
        for args in ({"direction": "up"}, {"depth": 0}, {"depth": 5}, {"depth": "bad"}, {"depth": True}):
            with self.subTest(args=args), mock.patch.object(
                mcp_server, "_prog", side_effect=AssertionError("binary must not be loaded")
            ), self.assertRaises(ValueError):
                mcp_server.t_callgraph("missing.bin", "0x1000", **args)


if __name__ == "__main__":
    unittest.main()
