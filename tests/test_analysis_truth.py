"""Independent truth fixtures for basic-block edges and function-start discovery.

The AArch64 oracle is hand-encoded and referenced to Arm's A-profile Architecture Reference
Manual. The x86-64 corpus uses compiler symbols from the original executable as the independent
function-start oracle, then strips the binary and evaluates RDIS's symbol-free discovery path.
The reported precision/recall is for this small fixture, not a broad architecture claim.
"""
import json
import platform
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from rdis.analysis import Program
from rdis.arch import make
from rdis.loader import Image, Section, open_image


BASE = 0x1000
EXPECTED_FUNCTION_NAMES = {
    "truth_leaf",
    "truth_branch_loop",
    "truth_switch",
    "truth_tail",
    "truth_address_taken",
    "truth_indirect",
    "truth_entry",
}


def _hex_fixture(filename):
    fixture = Path(__file__).resolve().parent / "fixtures" / filename
    encoded = []
    for line in fixture.read_text(encoding="utf-8").splitlines():
        payload = line.split("#", 1)[0].strip()
        if payload:
            encoded.extend(payload.split())
    return bytes.fromhex(" ".join(encoded))


def _arm64_fixture():
    return _hex_fixture("arm64_branch_fixture.hex")


def _x86_64_loop_fixture():
    return _hex_fixture("x86_64_loop_fixture.hex")


def _precision_recall_f1(expected, observed):
    true_positives = len(expected & observed)
    precision = true_positives / len(observed) if observed else 0.0
    recall = true_positives / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "expected": len(expected),
        "observed": len(observed),
        "true_positives": true_positives,
        "false_positives": sorted(observed - expected),
        "false_negatives": sorted(expected - observed),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


class IndependentControlFlowTruthTests(unittest.TestCase):
    def test_hand_encoded_aarch64_cfg_has_exact_edges_and_one_function(self):
        code = _arm64_fixture()
        self.assertEqual(len(code), 24)

        def read(va, size):
            offset = va - BASE
            if offset < 0 or offset >= len(code):
                return b""
            return code[offset:offset + size]

        image = Image(
            "<hand-encoded-arm64-cfg-fixture>",
            "raw",
            make("arm64"),
            BASE,
            BASE,
            [Section(".text", BASE, len(code), 0, True)],
            {},
            {},
            read,
            lambda va: va - BASE if BASE <= va < BASE + len(code) else None,
        )
        program = Program(image).analyze(objc=False, swift=False, prologues=False)
        self.assertEqual(set(program.functions), {BASE})
        func = program.functions[BASE]
        observed_edges = {
            (block.addr, successor)
            for block in func.blocks.values()
            for successor in block.succs
        }
        # Independent control-flow oracle from the encoded instructions:
        # B.EQ at 0x1004 -> target 0x1010 and fall-through 0x1008;
        # B at 0x100c -> 0x1014.
        expected_edges = {
            (0x1000, 0x1008),
            (0x1000, 0x1010),
            (0x1008, 0x1014),
            (0x1010, 0x1014),  # SUB falls through to the shared RET block.
        }
        metrics = _precision_recall_f1(expected_edges, observed_edges)
        print("CFG_EDGE_METRIC " + json.dumps({
            "fixture": "aarch64-branch-cfg-v1",
            "architecture": "arm64",
            **metrics,
        }, sort_keys=True))
        self.assertEqual(observed_edges, expected_edges, json.dumps(metrics, sort_keys=True))
        self.assertEqual(len(func.blocks), 4)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1"], 1.0)

    def test_hand_encoded_x86_64_cfg_has_exact_loop_edges(self):
        code = _x86_64_loop_fixture()
        self.assertEqual(len(code), 9)

        def read(va, size):
            offset = va - BASE
            if offset < 0 or offset >= len(code):
                return b""
            return code[offset:offset + size]

        image = Image(
            "<hand-encoded-x86-64-loop-fixture>",
            "raw",
            make("x86_64"),
            BASE,
            BASE,
            [Section(".text", BASE, len(code), 0, True)],
            {},
            {},
            read,
            lambda va: va - BASE if BASE <= va < BASE + len(code) else None,
        )
        program = Program(image).analyze(objc=False, swift=False, prologues=False)
        self.assertEqual(set(program.functions), {BASE})
        func = program.functions[BASE]
        observed_edges = {
            (block.addr, successor)
            for block in func.blocks.values()
            for successor in block.succs
        }
        # XOR at 0x1000 falls through to the loop body. JL at 0x1006 has both
        # a backward taken edge to 0x1002 and a fall-through edge to RET at 0x1008.
        expected_edges = {
            (0x1000, 0x1002),
            (0x1002, 0x1002),
            (0x1002, 0x1008),
        }
        metrics = _precision_recall_f1(expected_edges, observed_edges)
        print("CFG_EDGE_METRIC " + json.dumps({
            "fixture": "x86-64-loop-cfg-v1",
            "architecture": "x86_64",
            **metrics,
        }, sort_keys=True))
        self.assertEqual(observed_edges, expected_edges, json.dumps(metrics, sort_keys=True))
        self.assertEqual(len(func.blocks), 3)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1"], 1.0)


@unittest.skipUnless(
    platform.system() == "Linux"
    and platform.machine().lower() in ("x86_64", "amd64")
    and all(shutil.which(tool) for tool in ("cc", "nm", "strip")),
    "compiler/symbol/strip truth benchmark currently runs on Linux x86-64",
)
class FunctionDiscoveryPrecisionRecallTests(unittest.TestCase):
    def _symbol_truth(self, binary):
        result = subprocess.run(
            [shutil.which("nm"), "-n", "--defined-only", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
        symbols = {}
        for line in result.stdout.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]+)\s+([Tt])\s+(\S+)\s*$", line)
            if m:
                name = m.group(3)
                if name in EXPECTED_FUNCTION_NAMES:
                    symbols[name] = int(m.group(1), 16)
        self.assertEqual(
            set(symbols),
            EXPECTED_FUNCTION_NAMES,
            "the compiler/symbol oracle must retain every deliberately used fixture function",
        )
        return symbols

    def _analyze_starts(self, binary):
        program = Program(open_image(str(binary), arch="x86_64")).analyze(
            objc=False, swift=False, prologues=True
        )
        return set(program.functions)

    def test_function_start_precision_recall_at_o0_o2_with_and_without_symbols(self):
        source = Path(__file__).resolve().parent / "fixtures" / "function_discovery_fixture.c"
        cc = shutil.which("cc")
        strip = shutil.which("strip")
        with tempfile.TemporaryDirectory(prefix="rdis-function-truth-") as temporary:
            tmp = Path(temporary)
            for optimization in ("-O0", "-O2"):
                binary = tmp / ("fixture-" + optimization[2:])
                command = [
                    cc,
                    optimization,
                    "-fno-inline",
                    "-fno-omit-frame-pointer",
                    "-fno-stack-protector",
                    "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables",
                    "-fno-pie",
                    "-no-pie",
                    "-nostdlib",
                    "-Wl,-e,truth_entry",
                    str(source),
                    "-o",
                    str(binary),
                ]
                built = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(
                    built.returncode, 0,
                    "compiler failed: " + " ".join(command) + "\n" + built.stderr,
                )

                truth = self._symbol_truth(binary)
                expected = set(truth.values())
                for mode, candidate in (("symbols", binary), ("stripped", tmp / ("stripped-" + optimization[2:]))):
                    if mode == "stripped":
                        shutil.copy2(binary, candidate)
                        stripped = subprocess.run(
                            [strip, "--strip-all", str(candidate)], capture_output=True, text=True
                        )
                        self.assertEqual(stripped.returncode, 0, stripped.stderr)
                    observed = self._analyze_starts(candidate)
                    metrics = _precision_recall_f1(expected, observed)
                    report = {
                        "fixture": "function-discovery-v1",
                        "architecture": "x86_64",
                        "optimization": optimization,
                        "mode": mode,
                        "function_names": truth,
                        **metrics,
                    }
                    print("FUNCTION_DISCOVERY_METRIC " + json.dumps(report, sort_keys=True))
                    with self.subTest(optimization=optimization, mode=mode):
                        self.assertEqual(
                            metrics["recall"], 1.0,
                            "a known function start was missed: " + json.dumps(report, sort_keys=True),
                        )
                        self.assertGreaterEqual(
                            metrics["precision"], 0.90,
                            "too many unsupported function starts: " + json.dumps(report, sort_keys=True),
                        )



@unittest.skipUnless(
    platform.system() == "Darwin"
    and platform.machine().lower() in ("arm64", "aarch64")
    and all(shutil.which(tool) for tool in ("cc", "nm", "strip")),
    "Mach-O ARM64 function truth runs on macOS ARM64",
)
class MachOFunctionDiscoveryPrecisionRecallTests(unittest.TestCase):
    def _symbol_truth(self, binary):
        result = subprocess.run(
            [shutil.which("nm"), "-n", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
        symbols = {}
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*([0-9a-fA-F]+)\s+([Tt])\s+(\S+)\s*$", line)
            if match:
                # Mach-O's external C symbols conventionally have one leading underscore.
                name = match.group(3).lstrip("_")
                if name in EXPECTED_FUNCTION_NAMES:
                    symbols[name] = int(match.group(1), 16)
        self.assertEqual(
            set(symbols),
            EXPECTED_FUNCTION_NAMES,
            "the nm symbol oracle must retain every deliberately used ARM64 fixture function",
        )
        return symbols

    def _analyze_starts(self, binary):
        program = Program(open_image(str(binary), arch="arm64")).analyze(
            objc=False, swift=False, prologues=True
        )
        return set(program.functions)

    def test_macho_arm64_function_start_precision_recall_at_o0_o2_with_and_without_symbols(self):
        source = Path(__file__).resolve().parent / "fixtures" / "function_discovery_fixture.c"
        cc, strip = shutil.which("cc"), shutil.which("strip")
        with tempfile.TemporaryDirectory(prefix="rdis-macho-arm64-truth-") as temporary:
            tmp = Path(temporary)
            for optimization in ("-O0", "-O2"):
                binary = tmp / ("fixture-" + optimization[2:])
                command = [
                    cc,
                    "-arch", "arm64",
                    optimization,
                    "-fno-inline",
                    "-fno-omit-frame-pointer",
                    "-fno-stack-protector",
                    "-fno-unwind-tables",
                    "-fno-asynchronous-unwind-tables",
                    "-nostdlib",
                    "-Wl,-e,_truth_entry",
                    "-Wl,-no_function_starts",
                    str(source),
                    "-o",
                    str(binary),
                ]
                built = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(
                    built.returncode,
                    0,
                    "Mach-O compiler/linker failed: " + " ".join(command) + "\n" + built.stderr,
                )
                truth = self._symbol_truth(binary)
                expected = set(truth.values())
                for mode, candidate in (
                    ("symbols", binary),
                    ("stripped", tmp / ("stripped-" + optimization[2:])),
                ):
                    if mode == "stripped":
                        shutil.copy2(binary, candidate)
                        # Mach-O's strip -N may retain externally visible names in some executable
                        # layouts. Remove every truth-function symbol explicitly; the linker was
                        # passed -no_function_starts and unwind tables were disabled, so the
                        # analyzer cannot get these starts from alternate function metadata.
                        symbol_list = tmp / ("remove-symbols-" + optimization[2:] + ".txt")
                        symbol_list.write_text(
                            "\n".join("_" + name for name in sorted(EXPECTED_FUNCTION_NAMES)) + "\n",
                            encoding="utf-8",
                        )
                        stripped = subprocess.run(
                            [strip, "-R", str(symbol_list), str(candidate)],
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(stripped.returncode, 0, stripped.stderr)
                        stripped_symbols = subprocess.run(
                            [shutil.which("nm"), "-n", str(candidate)],
                            check=True,
                            capture_output=True,
                            text=True,
                        ).stdout
                        retained = set()
                        for line in stripped_symbols.splitlines():
                            match = re.match(r"^\s*([0-9a-fA-F]+)\s+([Tt])\s+(\S+)\s*$", line)
                            if match and match.group(3).lstrip("_") in EXPECTED_FUNCTION_NAMES:
                                retained.add(match.group(3).lstrip("_"))
                        self.assertFalse(
                            retained,
                            "truth-function symbol oracle still present after strip -R: " + repr(sorted(retained)),
                        )
                    observed = self._analyze_starts(candidate)
                    metrics = _precision_recall_f1(expected, observed)
                    report = {
                        "fixture": "function-discovery-v1",
                        "architecture": "arm64",
                        "format": "Mach-O",
                        "optimization": optimization,
                        "mode": mode,
                        "function_names": truth,
                        **metrics,
                    }
                    print("FUNCTION_DISCOVERY_METRIC " + json.dumps(report, sort_keys=True))
                    with self.subTest(optimization=optimization, mode=mode):
                        self.assertEqual(
                            metrics["recall"], 1.0,
                            "a known ARM64 function start was missed: " + json.dumps(report, sort_keys=True),
                        )
                        self.assertGreaterEqual(
                            metrics["precision"], 0.90,
                            "too many unsupported ARM64 function starts: " + json.dumps(report, sort_keys=True),
                        )


if __name__ == "__main__":
    unittest.main()
