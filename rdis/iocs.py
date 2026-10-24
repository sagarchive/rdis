"""Indicator-of-Compromise (IOC) extraction from binary strings.

Given the strings rdis already extracts (``{addr, text}`` pairs), classify URLs,
domains, IPs, test/staging hosts, execution primitives and persistence markers.
"""
import re
import ipaddress

# -- TLDs (about 150 common ones) --------------------------------------------
TLD_SET = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "vc",
    "app", "dev", "xyz", "info", "biz", "name", "pro", "aero", "museum", "asia",
    "cat", "coop", "jobs", "mobi", "tel", "travel", "us", "uk", "ca", "au",
    "de", "fr", "jp", "cn", "in", "br", "ru", "it", "nl", "se", "no", "fi",
    "dk", "ch", "at", "be", "es", "pt", "ie", "nz", "za", "mx", "ar", "cl",
    "pe", "ve", "my", "sg", "kr", "tw", "hk", "th", "id", "ph", "vn", "pl",
    "cz", "hu", "ro", "bg", "hr", "sk", "si", "lt", "lv", "ee", "lu", "mt",
    "cy", "is", "li", "mc", "ad", "sm", "va", "by", "md", "ge", "am", "az",
    "kz", "uz", "tj", "kg", "tm", "mn", "np", "bd", "lk", "kh", "mm", "la",
    "bn", "bt", "mv", "pk", "af", "iq", "ir", "sa", "ae", "qa", "kw",
    "bh", "om", "jo", "lb", "sy", "ye", "eg", "ly", "dz", "ma", "tn", "ng",
    "ke", "gh", "tz", "ug", "zw", "zm", "mw", "bi", "rw", "cv", "gw",
    "sn", "mr", "ml", "bf", "ne", "tg", "sc", "mu", "mz", "ao", "cm", "cf",
    "td", "cg", "cd", "lr", "sl", "ss", "sd", "so", "dj", "er", "et",
    "tech", "store", "site", "online", "blog", "cloud", "digital", "media",
    "network", "social", "software", "systems", "works", "zone",
    "top", "win", "bid", "stream", "download", "run", "review", "country",
    "loan", "men", "click", "trade", "webcam", "space", "guru", "today",
    "tips", "style", "world", "watch", "wiki", "work",
    "yachts", "yahoo", "yoga", "yokohama", "you", "yt", "yun", "zappos",
    "zara", "zero", "zip", "zuerich",
    # Special-use TLDs / pseudo-TLDs for hostname matching
    "test", "invalid", "localhost", "local", "internal",
}

# -- Public suffix list (multi-part suffixes) --------------------------------
PUBLIC_SUFFIXES = {
    "co.uk", "co.au", "co.jp", "co.br", "co.in", "co.cn", "co.za", "co.kr",
    "co.id", "co.th", "co.nz", "com.au", "com.br", "com.cn", "com.mx",
    "net.br", "net.cn", "org.cn", "gov.cn", "gov.uk", "gov.au", "gov.br",
    "org.uk", "org.au", "org.br", "net.uk", "net.au", "net.za",
    "ac.uk", "ac.in", "ac.th", "ne.jp", "or.jp", "go.jp",
    "asn.au", "net.au", "org.au", "edu.au",
    "ltd.uk", "plc.uk", "sch.uk", "nic.uk",
    "ac.za", "web.za",
    "com.in", "net.in", "org.in", "gov.in", "edu.in", "res.in", "firm.in",
    "gen.in", "ind.in", "mil.in", "tv.in",
    "ne.jp",
    "kawasaki.jp", "kitakyushu.jp", "kobe.jp", "nagoya.jp", "sapporo.jp",
    "sendai.jp", "takamatsu.jp", "tokyo.jp", "yamaguchi.jp", "okinawa.jp",
    "city.kawasaki.jp", "city.kobe.jp", "city.nagoya.jp", "city.okinawa.jp",
    "city.sapporo.jp", "city.sendai.jp", "city.takamatsu.jp",
    "city.tokyo.jp", "city.yamaguchi.jp",
    "pref.aichi.jp", "pref.akita.jp", "pref.aomori.jp", "pref.chiba.jp",
    "pref.ehime.jp", "pref.fukui.jp", "pref.fukuoka.jp", "pref.fukushima.jp",
    "pref.gifu.jp", "pref.gunma.jp", "pref.hiroshima.jp", "pref.hyogo.jp",
    "pref.ibaraki.jp", "pref.ishikawa.jp", "pref.iwate.jp", "pref.kanagawa.jp",
    "pref.kochi.jp", "pref.kumamoto.jp", "pref.kyoto.jp", "pref.mie.jp",
    "pref.miyagi.jp", "pref.miyazaki.jp", "pref.nagano.jp", "pref.nagasaki.jp",
    "pref.nara.jp", "pref.niigata.jp", "pref.oita.jp", "pref.okayama.jp",
    "pref.sizuoka.jp", "pref.tottori.jp", "pref.toyama.jp", "pref.wakayama.jp",
    "pref.yamagata.jp", "pref.yamanashi.jp",
    "gc.ca",
}

# Test/staging domain suffixes and host keywords
TEST_DOMAIN_SUFFIXES = {".test", ".invalid", ".localhost", ".example"}
TEST_HOST_LABELS = frozenset({
    "test", "testing", "staging", "stage", "stg", "dev", "develop",
    "qa", "uat", "sandbox", "internal", "intranet", "localhost", "local",
    "preprod", "canary",
})

# Execution string patterns (rule_id, regex, confidence)
EXECUTION_PATTERNS = [
    ("exec_osascript", re.compile(r"osascript\b", re.IGNORECASE), "high"),
    ("exec_do_shell_script", re.compile(r"do shell script", re.IGNORECASE), "high"),
    ("exec_admin_priv", re.compile(r"with administrator privileges", re.IGNORECASE), "high"),
    ("exec_bin_sh", re.compile(r"^/bin/sh\s+-c\b", re.MULTILINE), "high"),
    ("exec_bin_bash", re.compile(r"^/bin/bash\s+-c\b", re.MULTILINE), "high"),
    ("exec_sh_c", re.compile(r"(?<!\S)sh\s+-c\b", re.IGNORECASE), "high"),
    ("exec_system", re.compile(r"\bsystem\s*\(", re.IGNORECASE), "high"),
    ("exec_popen", re.compile(r"\bpopen\s*\(", re.IGNORECASE), "high"),
    ("exec_curl_sh", re.compile(r"curl\s+.*\|\s*sh\b", re.IGNORECASE), "high"),
    ("exec_wget_sh", re.compile(r"wget\s+.*\|\s*sh\b", re.IGNORECASE), "high"),
    ("exec_base64_d", re.compile(r"base64\s+-d\b", re.IGNORECASE), "high"),
    ("exec_base64_dec", re.compile(r"base64\s+--decode\b", re.IGNORECASE), "high"),
    ("exec_chmod_x", re.compile(r"chmod\s+\+x\b", re.IGNORECASE), "high"),
    ("exec_chmod_777", re.compile(r"chmod\s+777\b", re.IGNORECASE), "high"),
    ("exec_sudo", re.compile(r"\bsudo\b", re.IGNORECASE), "medium"),
    ("exec_nohup", re.compile(r"\bnohup\b", re.IGNORECASE), "medium"),
    ("exec_dyld", re.compile(r"DYLD_INSERT_LIBRARIES", re.IGNORECASE), "high"),
    ("exec_ld_preload", re.compile(r"LD_PRELOAD", re.IGNORECASE), "high"),
    ("exec_powershell", re.compile(r"\bpowershell\b", re.IGNORECASE), "high"),
    ("exec_cmd_exe", re.compile(r"cmd\.exe\s+/c", re.IGNORECASE), "high"),
    ("exec_mshta", re.compile(r"\bmshta\b", re.IGNORECASE), "high"),
    ("exec_rundll32", re.compile(r"\brundll32\b", re.IGNORECASE), "high"),
    ("exec_regsvr32", re.compile(r"\bregsvr32\b", re.IGNORECASE), "high"),
]

# Persistence string patterns (rule_id, regex, confidence)
PERSISTENCE_PATTERNS = [
    ("persist_launchctl", re.compile(r"\blaunchctl\b", re.IGNORECASE), "high"),
    ("persist_launchagents", re.compile(r"LaunchAgents", re.IGNORECASE), "high"),
    ("persist_launchdaemons", re.compile(r"LaunchDaemons", re.IGNORECASE), "high"),
    ("persist_lib_dir", re.compile(r"~/Library/", re.IGNORECASE), "high"),
    ("persist_run_at_load", re.compile(r"\bRunAtLoad\b"), "high"),
    ("persist_keepalive", re.compile(r"\bKeepAlive\b"), "high"),
    ("persist_crontab", re.compile(r"\bcrontab\b", re.IGNORECASE), "high"),
    ("persist_etc_cron", re.compile(r"/etc/cron", re.IGNORECASE), "high"),
    ("persist_systemctl", re.compile(r"\bsystemctl\b", re.IGNORECASE), "high"),
    ("persist_systemd", re.compile(r"/etc/systemd", re.IGNORECASE), "high"),
    ("persist_rc_local", re.compile(r"/etc/rc\.local", re.IGNORECASE), "high"),
    ("persist_schtasks", re.compile(r"\bschtasks\b", re.IGNORECASE), "high"),
    ("persist_reg_run", re.compile(r"reg\s+add.*CurrentVersion\\Run", re.IGNORECASE), "high"),
    ("persist_authorized_keys", re.compile(r"authorized_keys", re.IGNORECASE), "high"),
    ("persist_bashrc", re.compile(r"\.bashrc\b", re.IGNORECASE), "medium"),
    ("persist_zshrc", re.compile(r"\.zshrc\b", re.IGNORECASE), "medium"),
    ("persist_login_items", re.compile(r"login items", re.IGNORECASE), "high"),
    ("persist_smappservice", re.compile(r"SMAppService", re.IGNORECASE), "high"),
    ("persist_lssharedfilelist", re.compile(r"LSSharedFileList", re.IGNORECASE), "high"),
]

# URL scheme: http, https, ftp, ws, wss
_URL_SCHEME = r"(?:https?|ftp|wss?)"
_URL_RE = re.compile(
    r"\b(" + _URL_SCHEME + r"://)" +                    # scheme://
    r"([^\s\"'<>]+?)" +                                   # host and rest (non-greedy)
    r"(?=[\s\"'<>]|$)",                                   # end on whitespace/quote
    re.IGNORECASE
)

# Bare hostname: label.label.tld
_TLD_ALTERNATION = "|".join(sorted(TLD_SET, key=len, reverse=True))
_HOSTNAME_RE = re.compile(
    r"\b(?<![\w.])"
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+"
    r"(?:" + _TLD_ALTERNATION + r"))"
    r"(?![\w.])",
    re.IGNORECASE
)

# IPv4: four octets 0-255, not part of a longer dotted sequence
_IPV4_RE = re.compile(
    r"(?<!\d\.)(?<!\d)"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?!\.?\d)(?!\.\d)",
)

# IPv6 in brackets - match hex:colon pattern inside []
_IPV6_BRACKET_RE = re.compile(
    r"\[([0-9a-fA-F]*:[0-9a-fA-F:.]*:[0-9a-fA-F:.]*)\]"
)

# Bare IPv6 (full form: 8 groups of hex digits)
_IPV6_BARE_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
)


def _registrable_domain(host):
    """Given a hostname, return (registrable_domain, suffix).

    e.g. 'a.b.example.co.uk' -> ('b.example', 'co.uk')
    e.g. 'cdn.vendor.com' -> ('vendor.com', 'com')
    """
    parts = host.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return host, ""

    # Check multi-part suffixes first (longest match)
    for suffix_len in range(min(4, len(parts)), 1, -1):
        suffix = ".".join(parts[-suffix_len:])
        if suffix in PUBLIC_SUFFIXES:
            if len(parts) > suffix_len:
                registrable = ".".join(parts[-(suffix_len + 1):])
                return registrable, suffix

    # Single-label TLD
    tld = parts[-1]
    if tld in TLD_SET and len(parts) >= 2:
        return ".".join(parts[-2:]), tld

    return host, ""


def _is_test_host(host):
    """Check if a hostname is a test/staging host."""
    host_lower = host.lower().rstrip(".")

    # Check for RFC 2606 / reserved domains
    for suffix in TEST_DOMAIN_SUFFIXES:
        if host_lower.endswith(suffix) or host_lower == suffix.lstrip("."):
            return True
    if host_lower.startswith("example."):
        return True

    # Check labels for test/staging keywords
    for label in host_lower.split("."):
        for token in re.split(r"[-_]+", label):
            if token.rstrip("0123456789") in TEST_HOST_LABELS:
                return True

    return False


def _ipv4_class(octets):
    """Determine IP class for IPv4 octets [a, b, c, d]."""
    a, b = octets[0], octets[1]

    # Loopback
    if a == 127:
        return "loopback"

    # Link-local
    if a == 169 and b == 254:
        return "link-local"

    # Private ranges
    if a == 10:
        return "private"
    if a == 172 and 16 <= b <= 31:
        return "private"
    if a == 192 and b == 168:
        return "private"

    # CGNAT (100.64.0.0/10)
    if a == 100 and 64 <= b <= 127:
        return "cgnat"

    # Multicast (224.0.0.0/4)
    if 224 <= a <= 239:
        return "multicast"

    # Reserved / documentation (192.0.2/24, 198.51.100/24, 203.0.113/24)
    if a == 192 and b == 0 and octets[2] == 2:
        return "reserved"
    if a == 198 and b == 51 and octets[2] == 100:
        return "reserved"
    if a == 203 and b == 0 and octets[2] == 113:
        return "reserved"

    # Other reserved ranges
    if a == 0:
        return "reserved"
    if a >= 240:
        return "reserved"

    return "public"


def _classify_ipv4(ip_str):
    """Classify an IPv4 address string. Returns (class_name, low_signal)."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return "invalid", False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return "invalid", False

    # Low-information values
    low_signal_vals = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
    if ip_str in low_signal_vals:
        return _ipv4_class(octets), True

    return _ipv4_class(octets), False


def _classify_ipv6(ip_str):
    """Classify an IPv6 address. Returns (class_name, low_signal)."""
    try:
        addr = ipaddress.IPv6Address(ip_str)
    except ValueError:
        return "invalid", False

    if addr.is_loopback:
        return "loopback", False
    if addr.is_link_local:
        return "link-local", False
    if addr.is_multicast:
        return "multicast", False
    # Documentation range (2001:db8::/32)
    if addr in ipaddress.IPv6Network("2001:db8::/32"):
        return "documentation", False
    # Unique local addresses (fc00::/7)
    if addr in ipaddress.IPv6Network("fc00::/7"):
        return "unique-local", False
    if addr.is_unspecified:
        return "reserved", True
    if addr.is_reserved:
        return "reserved", False

    return "public", False


_FILE_EXTS = {
    ".dylib", ".plist", ".c", ".h", ".o", ".so", ".a", ".dll", ".exe",
    ".bin", ".dat", ".txt", ".log", ".xml", ".json", ".yaml", ".yml",
    ".html", ".htm", ".css", ".js", ".py", ".rb", ".go", ".swift",
    ".m", ".mm", ".cpp", ".cc", ".cxx", ".rs", ".java", ".class",
    ".jar", ".war", ".zip", ".tar", ".gz", ".bz2", ".mp3", ".mp4",
    ".avi", ".mov", ".wav", ".ogg", ".flac", ".png", ".jpg", ".jpeg",
    ".gif", ".bmp", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
}


def _is_file_name(s):
    """Check if a string ends with a common file extension."""
    lower = s.lower()
    for ext in _FILE_EXTS:
        if lower.endswith(ext):
            return True
    return False


def _is_identifier(s):
    """Check if string looks like a Go/ObjC identifier with dots (main.main, NSString.length).

    Only returns True for identifiers that are NOT domains (i.e. the last segment
    is not a known TLD).
    """
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_.]*$", s):
        return False
    # If the last part is a TLD, it looks like a domain, not an identifier
    tld = s.rsplit(".", 1)[-1].lower()
    if tld in TLD_SET:
        return False
    return True


# Short TLDs that are also ordinary words and identifier suffixes (errors.is, sync.mu, reflect.int, flag.ro):
# a bare name ending in one of these is far more often code than a host.
WEAK_TLDS = frozenset({"is", "in", "it", "at", "as", "no", "do", "my", "am", "by", "so", "to", "mu", "ro", "run",
                       "int", "name", "zero", "ms", "id", "go", "be", "he", "on", "me", "io_", "sh", "py",
                       "pl", "rs", "cc", "ax", "mn", "ps", "tk", "ml", "ga", "cf", "gq"})


def _plausible_bare_host(host):
    """A bare (not inside a URL) hostname must not look like a code identifier."""
    labels = host.split(".")
    tld = labels[-1]
    if not (tld.islower() or tld.isupper()):
        return False                                   # Value.Int, errors.Is
    if any(re.search(r"[a-z][A-Z]", label) for label in labels):
        return False                                   # camelCase labels
    if tld.lower() in WEAK_TLDS:
        return False                                   # real hosts on these TLDs are still found inside URLs
    return True


def _looks_like_hostname(s):
    """Basic check that a string looks like it could be a hostname."""
    if not s or "." not in s:
        return False
    return bool(re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$",
        s
    ))


def _cap(items, limit):
    """Cap a list to limit items. Returns (items, truncated, total)."""
    total = len(items)
    truncated = total > limit
    return items[:limit], truncated, total


def _build_finding(category, value, source, addresses, rule, confidence):
    """Build a standard finding dict."""
    return {
        "category": category,
        "value": value,
        "source": source,
        "addresses": sorted(addresses),
        "rule": rule,
        "confidence": confidence,
    }


def _build_domain_finding(key, v):
    """Build a domain finding with grouped hosts/urls/addresses."""
    reg, suffix = key
    return {
        "category": "domain",
        "value": reg,
        "source": v["source"],
        "addresses": sorted(v["addresses"]),
        "rule": "domain_group",
        "confidence": "high",
        "hosts": sorted(v["hosts"]),
        "urls": v["urls"],
        "registrable_domain": reg,
        "suffix": suffix,
        "count": len(v["addresses"]),
    }


def _add_url(urls_map, domains_map, test_hosts_map, url, host, text, addr):
    """Add a URL finding and its associated domain/test-host groupings."""
    key = url
    if key not in urls_map:
        urls_map[key] = {
            "value": url, "source": text, "host": host, "addresses": []
        }
    if addr not in urls_map[key]["addresses"]:
        urls_map[key]["addresses"].append(addr)

    # Also extract domain from the URL's host
    host_lower = host.lower().rstrip(".")
    if _looks_like_hostname(host_lower) and not _is_file_name(host):
        reg, suffix = _registrable_domain(host)
        if reg and suffix:
            reg_key = (reg, suffix)
            if reg_key not in domains_map:
                domains_map[reg_key] = {"source": text, "addresses": [], "urls": [], "hosts": set()}
            if host not in domains_map[reg_key]["hosts"]:
                domains_map[reg_key]["hosts"].add(host)
            if url not in domains_map[reg_key]["urls"]:
                domains_map[reg_key]["urls"].append(url)
            for a in urls_map[key]["addresses"]:
                if a not in domains_map[reg_key]["addresses"]:
                    domains_map[reg_key]["addresses"].append(a)

        # Check for test hosts from URL host
        if _is_test_host(host_lower):
            th_key = host_lower
            if th_key not in test_hosts_map:
                test_hosts_map[th_key] = {"value": host, "source": text, "addresses": []}
            for a in urls_map[key]["addresses"]:
                if a not in test_hosts_map[th_key]["addresses"]:
                    test_hosts_map[th_key]["addresses"].append(a)


def _add_bare_host(domains_map, test_hosts_map, host, text, addr):
    """Add a bare hostname finding and its domain/test-host groupings."""
    host_lower = host.lower().rstrip(".")
    reg, suffix = _registrable_domain(host)
    if reg and suffix:
        reg_key = (reg, suffix)
        if reg_key not in domains_map:
            domains_map[reg_key] = {"source": text, "addresses": [], "urls": [], "hosts": set()}
        if host not in domains_map[reg_key]["hosts"]:
            domains_map[reg_key]["hosts"].add(host)
        if addr not in domains_map[reg_key]["addresses"]:
            domains_map[reg_key]["addresses"].append(addr)

    if _is_test_host(host_lower):
        key = host_lower
        if key not in test_hosts_map:
            test_hosts_map[key] = {"value": host, "source": text, "addresses": []}
        if addr not in test_hosts_map[key]["addresses"]:
            test_hosts_map[key]["addresses"].append(addr)


def _add_ipv4(ips_map, ip_str, text, addr):
    """Add an IPv4 finding."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return
    if any(o < 0 or o > 255 for o in octets):
        return
    ip_class, low_signal = _classify_ipv4(ip_str)
    key = ip_str
    if key not in ips_map:
        ips_map[key] = {
            "value": ip_str, "source": text, "ip_class": ip_class,
            "low_signal": low_signal, "addresses": []
        }
    if addr not in ips_map[key]["addresses"]:
        ips_map[key]["addresses"].append(addr)


def _add_ipv6(ips_map, ip_str, text, addr):
    """Add an IPv6 finding."""
    import ipaddress
    try:
        ipaddress.IPv6Address(ip_str)
    except ValueError:
        return
    ip_class, low_signal = _classify_ipv6(ip_str)
    key = ip_str
    if key not in ips_map:
        ips_map[key] = {
            "value": ip_str, "source": text, "ip_class": ip_class,
            "low_signal": low_signal, "addresses": []
        }
    if addr not in ips_map[key]["addresses"]:
        ips_map[key]["addresses"].append(addr)


def extract(strings, limit=200):
    """Extract IOCs from a list of string entries.

    Args:
        strings: list of {"addr": int, "text": str} dicts
        limit: maximum items per category (default 200)

    Returns:
        dict with keys: urls, domains, ips, test_hosts, execution,
        persistence, summary.
    """
    urls_map = {}
    domains_map = {}
    ips_map = {}
    test_hosts_map = {}
    execution_list = []
    persistence_list = []

    for entry in strings:
        addr = entry["addr"]
        text = entry["text"]

        if not text:
            continue

        # --- URLs ---
        for m in _URL_RE.finditer(text):
            scheme = m.group(1)
            host_part = m.group(2)
            url = scheme + host_part
            host = host_part.split("/")[0].split("@")[-1].split(":")[0]
            _add_url(urls_map, domains_map, test_hosts_map, url, host, text, addr)

        # --- Bare hostnames ---
        for m in _HOSTNAME_RE.finditer(text):
            host = m.group(1)
            start = m.start(1)
            if start >= 7 and text[start - 7:start].lower().endswith("://"):
                continue
            if _is_file_name(host) or _is_identifier(host) or not _plausible_bare_host(host):
                continue
            _add_bare_host(domains_map, test_hosts_map, host, text, addr)

        # --- IPv4 ---
        for m in _IPV4_RE.finditer(text):
            _add_ipv4(ips_map, m.group(0), text, addr)

        # --- IPv6 (bracketed) ---
        for m in _IPV6_BRACKET_RE.finditer(text):
            _add_ipv6(ips_map, m.group(1), text, addr)

        # --- IPv6 (bare, full form) ---
        for m in _IPV6_BARE_RE.finditer(text):
            _add_ipv6(ips_map, m.group(0), text, addr)

        # --- Execution strings ---
        for rule_id, pattern, confidence in EXECUTION_PATTERNS:
            for m in pattern.finditer(text):
                execution_list.append(_build_finding(
                    "execution", m.group(0), text, [addr], rule_id, confidence))

        # --- Persistence strings ---
        for rule_id, pattern, confidence in PERSISTENCE_PATTERNS:
            for m in pattern.finditer(text):
                persistence_list.append(_build_finding(
                    "persistence", m.group(0), text, [addr], rule_id, confidence))

    # KeepAlive and RunAtLoad are launchd plist keys but also ordinary words: without any other launchd
    # evidence in the binary they are reported at low confidence.
    plist_keys = {"persist_keepalive", "persist_run_at_load"}
    if not any(f["rule"] not in plist_keys for f in persistence_list):
        for f in persistence_list:
            f["confidence"] = "low"

    # Build result lists
    url_list = [_build_finding("url", v["value"], v["source"], v["addresses"],
                               "url_regex", "high")
                for v in urls_map.values()]
    url_list.sort(key=lambda x: min(x["addresses"]))

    domain_list = [_build_domain_finding(k, v) for k, v in domains_map.items()]
    domain_list.sort(key=lambda x: min(x["addresses"]))

    ip_list = [_build_finding("ip", v["value"], v["source"], v["addresses"],
                              "ipv4_regex", "low" if v["low_signal"] else "high")
               for v in ips_map.values()]
    for i, v in enumerate(ips_map.values()):
        if i < len(ip_list):
            ip_list[i]["ip_class"] = v["ip_class"]
            ip_list[i]["low_signal"] = v["low_signal"]
    ip_list.sort(key=lambda x: min(x["addresses"]))

    test_host_list = [_build_finding("test_host", v["value"], v["source"],
                                     v["addresses"], "test_host_label", "high")
                      for v in test_hosts_map.values()]
    test_host_list.sort(key=lambda x: min(x["addresses"]))

    # Deduplicate execution and persistence by (value, source)
    seen_exec = set()
    dedup_exec = []
    for f in execution_list:
        key = (f["value"], f["source"])
        if key not in seen_exec:
            seen_exec.add(key)
            dedup_exec.append(f)

    seen_persist = set()
    dedup_persist = []
    for f in persistence_list:
        key = (f["value"], f["source"])
        if key not in seen_persist:
            seen_persist.add(key)
            dedup_persist.append(f)

    # Cap and truncate
    urls, urls_trunc, urls_total = _cap(url_list, limit)
    domains, domains_trunc, domains_total = _cap(domain_list, limit)
    ips, ips_trunc, ips_total = _cap(ip_list, limit)
    test_hosts, th_trunc, th_total = _cap(test_host_list, limit)
    execution, exec_trunc, exec_total = _cap(dedup_exec, limit)
    persistence, persist_trunc, persist_total = _cap(dedup_persist, limit)

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "test_hosts": test_hosts,
        "execution": execution,
        "persistence": persistence,
        "summary": {
            "urls": {"total": urls_total, "truncated": urls_trunc},
            "domains": {"total": domains_total, "truncated": domains_trunc},
            "ips": {"total": ips_total, "truncated": ips_trunc},
            "test_hosts": {"total": th_total, "truncated": th_trunc},
            "execution": {"total": exec_total, "truncated": exec_trunc},
            "persistence": {"total": persist_total, "truncated": persist_trunc},
        },
    }


CATEGORIES = ("urls", "domains", "ips", "test_hosts", "execution", "persistence")


def attach_functions(result, prog, cap=5):
    """Add `functions`: the names of the functions that load each indicator's string (empty when only data points at it)."""
    from .stringrefs import string_refs
    refs = string_refs(prog)
    for category in CATEGORIES:
        for finding in result[category]:
            names = []
            for addr in finding["addresses"]:
                for r in refs.get(addr, ()):
                    if r["name"] not in names:
                        names.append(r["name"])
            finding["functions"] = names[:cap]
    return result
