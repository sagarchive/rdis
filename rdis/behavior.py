"""Capability summary from what a binary imports, contains and (for Go) links.

Each behavior lists the evidence behind it: the import, string, function name or Go module, its address, and the
functions that use it. Evidence, not a verdict: a capability means the code can do it, not that it does.
"""
import re

# (kind, regex, weight). kinds: import (imported symbol), string, function (a named function in the binary),
# module (Go module path). A behavior is reported when the weights of its evidence add up to at least 2
# (one weak hint alone is noise); 2 = medium, 3+ = high. Go binaries import libc through their standard
# syscall package whatever the program does, so for them imports are not evidence.
RULES = (
    ("admin-rights", "requests administrator rights", (
        ("string", r"with administrator privileges", 2), ("import", r"^(AuthorizationExecuteWithPrivileges|AuthorizationCreate|SMJobBless)$", 2),
        ("import", r"^SMAppService", 1), ("string", r"\bsudo -[A-Za-z]", 1), ("string", r"\brunas\b", 1))),
    ("spawn-process", "spawns child processes", (
        ("import", r"^(posix_spawn|posix_spawnp|execve|execv|execvp|execl|execlp|fork|vfork|popen|system|NSTask|CreateProcess[AW]?|ShellExecute[AW]?|WinExec)$", 2),
        ("function", r"^os/exec\.\(\*Cmd\)\.(Start|Run|Output|CombinedOutput)$", 3), ("string", r"/bin/(ba|z)?sh\b.*-c", 1))),
    ("spawn-helper", "spawns a helper binary", (
        ("string", r"/(Contents/)?(Helpers?|MacOS|Resources)/[\w.-]+", 1), ("string", r"\bhelper\b.*(\.app|/)|[\w-]+[Hh]elper\b", 1))),
    ("http-client", "makes HTTP requests", (
        ("import", r"^(NSURLSession|NSURLConnection|CFURLConnection|curl_easy_perform|WinHttpOpen|InternetOpen[AW]?|URLDownloadToFile[AW]?)$", 2),
        ("string", r"\bNSURLSession\b|\bcurl_easy", 1), ("function", r"^net/http\.\(\*Client\)\.(Do|Get|Post)$", 3),
        ("string", r"https?://", 1))),
    ("network-sockets", "opens network connections", (
        ("import", r"^(socket|connect|getaddrinfo|gethostbyname|WSAStartup|WSASocket[AW]?|CFStreamCreatePairWithSocketToHost)$", 2),
        ("function", r"^net\.(Dial|\(\*Dialer\)\.Dial\w*|Listen)$", 3))),
    ("listens", "listens for incoming connections", (
        ("import", r"^(listen|accept|bind)$", 1), ("function", r"^net\.\(\*ListenConfig\)\.Listen$|^net\.Listen$", 3))),
    ("tls", "uses TLS", (
        ("import", r"^(SSL_new|SSL_connect|SSL_CTX_new|SSLCreateContext|SecTrustEvaluate\w*|mbedtls_ssl_\w+|SChannel\w*)$", 2),
        ("function", r"^crypto/tls\.", 2), ("string", r"TLSv1\.[0-3]", 1))),
    ("upload", "sends data to a server", (
        ("string", r"multipart/form-data", 2), ("string", r"\bPOST\b .*HTTP/1", 2), ("string", r"Content-Type: application/(json|octet-stream)", 1),
        ("function", r"^net/http\.\(\*Client\)\.Post(Form)?$", 2), ("import", r"^curl_formadd$", 2))),
    ("telemetry", "collects diagnostics or telemetry", (
        ("string", r"(?i)\b(telemetry|diagnostics?|crash[ _-]?report|analytics|metrics upload)\b", 1),)),
    ("cryptography", "uses cryptography", (
        ("import", r"^(CCCrypt\w*|CC_SHA\w+|CC_MD5|EVP_\w+|AES_\w+|SecKey\w+|BCrypt\w+|CryptEncrypt|CryptoKit\w*)$", 2),
        ("function", r"^crypto/(aes|cipher|rsa|ecdsa|ed25519|chacha20poly1305|sha256|sha512)\.", 2), ("string", r"\b(AES|ChaCha20|RSA)\b", 1))),
    ("keychain", "reads credentials from the keychain", (
        ("import", r"^(SecItemCopyMatching|SecKeychain\w+|CredRead[AW]?|CryptUnprotectData)$", 3),
        ("string", r"security (find|dump)-(generic|internet)-password|login\.keychain", 3))),
    ("browser-data", "reads browser profile data", (
        ("string", r"Login Data|Cookies\.sqlite|logins\.json|Web Data|Local State|key[34]\.db", 2),
        ("string", r"Google/Chrome|Application Support/(Firefox|BraveSoftware|Microsoft Edge)", 1))),
    ("screen-capture", "captures the screen", (
        ("import", r"^(CGWindowListCreateImage|CGDisplayCreateImage|CGDisplayStream\w+|BitBlt|ScreenCaptureKit\w*|SCStream\w*)$", 3),)),
    ("input-monitoring", "monitors keyboard or mouse input", (
        ("import", r"^(CGEventTapCreate|IOHIDManagerCreate|SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState)$", 3),)),
    ("clipboard", "reads the clipboard", (
        ("import", r"^(GetClipboardData|OpenClipboard)$", 2), ("string", r"NSPasteboard|generalPasteboard", 2))),
    ("system-info", "collects system information", (
        ("import", r"^(sysctlbyname|sysctl|uname|gethostname|IOServiceGetMatchingService|IORegistryEntryCreateCFProperty|GetComputerName[AW]?|GetSystemInfo)$", 1),
        ("string", r"system_profiler|IOPlatformSerialNumber|IOPlatformUUID|hw\.model|kern\.osversion", 2))),
    ("persistence", "installs itself to run at startup", (
        ("string", r"LaunchAgents|LaunchDaemons|launchctl\b", 2), ("string", r"RunAtLoad", 1), ("import", r"^(SMLoginItemSetEnabled|SMAppService\w*|LSSharedFileList\w+)$", 2),
        ("string", r"/etc/cron|crontab\b|systemctl\b|CurrentVersion\\Run|schtasks\b", 2))),
    ("scripting", "runs AppleScript or shell script text", (
        ("string", r"\bosascript\b|do shell script", 2), ("import", r"^NSAppleScript$", 2), ("string", r"powershell|cmd\.exe /c", 2))),
    ("dynamic-code", "loads code at runtime", (
        ("import", r"^(dlopen|dlsym|LoadLibrary[AW]?|GetProcAddress|NSBundle|CFBundleLoadExecutable)$", 1),
        ("import", r"^(mprotect|VirtualProtect|VirtualAlloc)$", 1), ("string", r"DYLD_INSERT_LIBRARIES|LD_PRELOAD", 3))),
    ("anti-debug", "checks for or blocks debuggers", (
        ("import", r"^(ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)$", 2),
        ("string", r"PT_DENY_ATTACH|P_TRACED|kern\.proc\.pid", 2))),
    ("file-deletion", "deletes files", (
        ("import", r"^(unlink|unlinkat|remove|rmdir|DeleteFile[AW]?|NSFileManager)$", 1), ("function", r"^os\.(Remove|RemoveAll)$", 2))),
    ("quarantine", "touches Gatekeeper quarantine", (
        ("string", r"com\.apple\.quarantine|spctl\b", 3),)),
    ("vpn-tunnel", "embeds a VPN or tunnel stack", (
        ("module", r"wireguard|tailscale|openvpn|zerotier", 3), ("function", r"^golang\.zx2c4\.com/wireguard", 3), ("string", r"WireGuard", 1))),
    ("userspace-network", "embeds a userspace network stack", (
        ("module", r"gvisor\.dev/gvisor|lwip", 3), ("function", r"^gvisor\.dev/gvisor/pkg/tcpip", 3))),
    ("service-discovery", "discovers services on the local network", (
        ("module", r"zeroconf|mdns|bonjour|dnssd", 3), ("string", r"_tcp\.local|_udp\.local|\bmDNS\b|Bonjour", 2),
        ("import", r"^(DNSServiceBrowse|DNSServiceRegister|NSNetServiceBrowser)$", 2))),
    ("remote-protocol", "speaks a remote-control or pairing protocol", (
        ("module", r"golang\.org/x/crypto/ssh|libimobiledevice|go-ios|pairing|grpc|quic-go|websocket", 2),
        ("string", r"(?i)\bremote ?pairing\b|\bpair(ing)?_record|lockdown", 2))),
    ("database", "uses an embedded database", (
        ("import", r"^sqlite3_\w+$", 2), ("module", r"sqlite|bolt|badger|leveldb|rocksdb", 2), ("function", r"^database/sql\.", 2))),
    ("compression", "compresses or archives data", (
        ("import", r"^(compress|deflate|inflate|BZ2_\w+|lzma_\w+|ZSTD_\w+|archive_\w+)$", 2), ("function", r"^compress/(gzip|zlib|flate|bzip2)\.", 2))),
)

STRONG = 3
MIN_SCORE = 2


def _import_sites(prog):
    """{import name: [(address, [function names])]} using the xrefs recorded to each import stub."""
    out = {}
    for addr, name in prog.image.imports.items():
        base = name.split("@")[0].lstrip("_")
        names = []
        for site, _kind in prog.xrefs.get(addr, ()):
            fn = prog.function_at(site)
            if fn is not None and prog.display(fn.addr) not in names:
                names.append(prog.display(fn.addr))
        out.setdefault(base, []).append((addr, names))
    for addr, name in prog.names.items():                    # stub names such as `_popen` on functions rdis named
        base = (name or "").lstrip("_")
        if base in out or addr in prog.functions and not name.startswith(("sub_", "j_")):
            continue
    return out


def analyze(prog):
    """{"behaviors": [{id, title, confidence, score, evidence: [...]}], "modules": [...]}"""
    from .gobin import read_build_info
    from .stringrefs import string_refs
    imports = _import_sites(prog)
    strings = prog.strings()
    refs = string_refs(prog, strings)
    funcs = {a: prog.display(a) for a in prog.functions}
    is_go = bool(prog._go_functions())
    modules = []
    try:
        info = read_build_info(prog.image.path, prog.image)
        modules = [d["path"] + (f"@{d['version']}" if d.get("version") else "") for d in (info or {}).get("deps", [])]
        if info and info.get("path"):
            modules.insert(0, info["path"])
    except Exception:
        pass
    found = []
    for rid, title, patterns in RULES:
        evidence, seen, score = [], set(), 0
        for kind, rx, weight in patterns:
            pat = re.compile(rx)
            hits = []
            if kind == "import" and is_go:
                continue
            if kind == "import":
                hits = [{"kind": "import", "value": n, "address": hex(a), "functions": fns[:5]}
                        for n, sites in imports.items() if pat.search(n) for a, fns in sites]
            elif kind == "string":
                hits = [{"kind": "string", "value": t[:120], "address": hex(a), "functions": [r["name"] for r in refs.get(a, ())][:5]}
                        for a, t in strings.items() if len(t) < 4000 and pat.search(t)]
            elif kind == "function":
                hits = [{"kind": "function", "value": n, "address": hex(a), "functions": []}
                        for a, n in funcs.items() if pat.search(n.lstrip("_"))]
            elif kind == "module":
                hits = [{"kind": "module", "value": m, "address": None, "functions": []} for m in modules if pat.search(m)]
            for h in hits[:5]:
                key = (h["kind"], h["value"], h["address"])
                if key not in seen:
                    seen.add(key)
                    evidence.append({**h, "rule_weight": weight})
            if hits:
                score += weight
        if score >= MIN_SCORE:
            found.append({"id": rid, "title": title, "score": score,
                          "confidence": "high" if score >= STRONG else "medium",
                          "evidence": evidence})
    order = {"high": 0, "medium": 1}
    found.sort(key=lambda b: (order[b["confidence"]], -b["score"], b["id"]))
    return {"behaviors": found, "modules": modules,
            "note": "A capability means the code can do it, not that it does. Each line links to its evidence."}
