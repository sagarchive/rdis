import os
import re
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Headers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = subprocess.Popen([sys.executable, "-m", "rdis.server", "--port", str(cls.port), "--no-open"],
                                    cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT}, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/", timeout=1).close()
                return
            except OSError:
                time.sleep(0.1)
        cls.proc.kill()
        raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.headers

    def test_every_response_carries_the_hardening_headers(self):
        for path in ("/", "/api/docs"):
            h = self.get(path)
            self.assertEqual(h["X-Content-Type-Options"], "nosniff", path)
            self.assertEqual(h["X-Frame-Options"], "DENY", path)
            self.assertEqual(h["Referrer-Policy"], "no-referrer", path)
            self.assertIn("camera=()", h["Permissions-Policy"], path)

    def test_the_content_security_policy_is_tight(self):
        csp = self.get("/")["Content-Security-Policy"]
        for directive in ("default-src 'none'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'",
                          "connect-src 'self'"):
            self.assertIn(directive, csp)
        self.assertNotIn("unsafe-eval", csp.replace("wasm-unsafe-eval", ""))
        hosts = set(re.findall(r"https?://[^\s;]+", csp))
        self.assertEqual(hosts, {"https://cdn.jsdelivr.net"})

    def test_api_responses_are_never_cached(self):
        self.assertEqual(self.get("/api/docs")["Cache-Control"], "no-store")

    def test_the_page_only_loads_scripts_from_hosts_the_policy_allows(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as r:
            page = r.read().decode()
        for src in re.findall(r'<script[^>]+src="([^"]+)"', page):
            self.assertTrue(src.startswith("https://cdn.jsdelivr.net/") or src.startswith("/"), src)
            if src.startswith("https://"):
                self.assertRegex(src, r"@\d+\.\d+\.\d+/", "an unpinned CDN version")


class Container(unittest.TestCase):
    def test_the_image_does_not_run_as_root(self):
        with open(os.path.join(ROOT, "Dockerfile")) as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        users = [l.split()[1] for l in lines if l.startswith("USER ")]
        self.assertTrue(users and users[-1] not in ("root", "0"), users)
        self.assertLess(max(i for i, l in enumerate(lines) if l.startswith("USER ")),
                        next(i for i, l in enumerate(lines) if l.startswith("CMD ")))
        self.assertTrue(any(l.startswith("HEALTHCHECK") for l in lines))


if __name__ == "__main__":
    unittest.main()
