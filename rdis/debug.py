"""Thin dynamic-analysis wrapper over the system `lldb` in batch mode (macOS/Linux).

Avoids the LLDB Python binding (which is pinned to the OS Python, not this venv) by scripting the
`lldb` CLI non-interactively. Enough to breakpoint, run, and inspect registers/memory/stack.

    dbg = Debugger("/path/to/bin")
    print(dbg.run(["-l"], stop_at="main", show=["registers", "disassemble -c 6"]))

Static analysis stays in the rest of rdis; this is only for live inspection.
"""
import shutil, subprocess, tempfile, os


def _lldb():
    exe = shutil.which("lldb")
    if exe:
        return exe
    r = subprocess.run(["xcrun", "--find", "lldb"], capture_output=True, text=True)
    if r.returncode == 0:
        return r.stdout.strip()
    raise RuntimeError("lldb not found (install Xcode command line tools)")


class Debugger:
    def __init__(self, path):
        self.path = path

    def script(self, commands, timeout=60):
        """Run a list of lldb commands in batch mode and return combined output."""
        lines = [f"target create {self.path!r}"] + list(commands) + ["quit"]
        with tempfile.NamedTemporaryFile("w", suffix=".lldb", delete=False) as f:
            f.write("\n".join(lines) + "\n")
            src = f.name
        try:
            r = subprocess.run([_lldb(), "--batch", "--source", src],
                               capture_output=True, text=True, timeout=timeout)
            return r.stdout + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
        finally:
            os.unlink(src)

    def run(self, args=None, stop_at=None, show=None, timeout=25):
        """Launch the target, optionally breaking at a symbol, then run inspection commands.

        First launch on macOS raises a one-time "Developer Tools Access" TCC prompt; approve it
        interactively (or run `DevToolsSecurity -enable` once) or this blocks until timeout.
        Non-launch inspection (`script(["disassemble --name f"])`) never triggers the prompt.
        """
        cmds = []
        if stop_at:
            cmds.append(f"breakpoint set --name {stop_at}")
        cmds.append("run " + " ".join(args or []))
        cmds += show or []
        return self.script(cmds, timeout)

    def registers(self, stop_at="main"):
        return self.run(stop_at=stop_at, show=["register read"])

    def disassemble_live(self, stop_at="main", count=10):
        return self.run(stop_at=stop_at, show=[f"disassemble --count {count} --pc"])

    def memory(self, expr, count=16, stop_at="main"):
        return self.run(stop_at=stop_at, show=[f"memory read --count {count} {expr}"])

    def backtrace(self, stop_at="main"):
        return self.run(stop_at=stop_at, show=["bt"])
