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

    def test_arm64_gap_scan_finds_stack_allocation_before_frame_save(self):
        # RET; padding NOP; SUB SP,SP,#0x50; STP X29,X30,[SP,#0x40];
        # ADD X29,SP,#0x40; RET. The allocation-first shape is common in large frames.
        code = bytes.fromhex(
            "c0 03 5f d6 1f 20 03 d5 "
            "ff 43 01 d1 fd 7b 04 a9 fd 03 01 91 c0 03 5f d6"
        )

        def read(va, size):
            offset = va - BASE
            if offset < 0 or offset >= len(code):
                return b""
            return code[offset:offset + size]

        image = Image(
            "<arm64-allocation-first-prologue>",
            "raw",
            make("arm64"),
            BASE,
            BASE,
            [Section(".text", BASE, len(code), 0, True)],
            {BASE: "truth_entry"},
            {},
            read,
            lambda va: va - BASE if BASE <= va < BASE + len(code) else None,
        )
        program = Program(image).analyze(objc=False, swift=False, prologues=True)
        self.assertEqual(set(program.functions), {BASE, BASE + 8})
        self.assertNotIn(BASE + 12, program.functions,
                         "the frame-save instruction must not become a false function start")

    def test_arm64_gap_scan_finds_leaf_frame_with_only_stack_spills(self):
        # RET; NOP padding; SUB SP,SP,#48; STR W0,[SP,#44]; LDR W0,[SP,#44]; RET.
        # A leaf may allocate a frame without saving FP/LR, so it has no STP x29,x30.
        code = bytes.fromhex(
            "c0 03 5f d6 1f 20 03 d5 "
            "ff c3 00 d1 e0 2f 00 b9 e0 2f 40 b9 c0 03 5f d6"
        )

        def read(va, size):
            offset = va - BASE
            if offset < 0 or offset >= len(code):
                return b""
            return code[offset:offset + size]

        image = Image(
            "<arm64-leaf-stack-spill-prologue>",
            "raw",
            make("arm64"),
            BASE,
            BASE,
            [Section(".text", BASE, len(code), 0, True)],
            {BASE: "truth_entry"},
            {},
            read,
            lambda va: va - BASE if BASE <= va < BASE + len(code) else None,
        )
        program = Program(image).analyze(objc=False, swift=False, prologues=True)
        self.assertEqual(set(program.functions), {BASE, BASE + 8})
        self.assertNotIn(BASE + 12, program.functions,
                         "an SP-relative store inside a function must not become a new entry")


@unittest.skipUnless(
    platform.system() == "Linux"
    and platform.machine().lower() in ("x86_64", "amd64")
    and all(shutil.which(tool) for tool in ("cc", "nm", "strip", "objdump")),
    "compiler/symbol/strip/objdump truth benchmark currently runs on Linux x86-64",
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


    @staticmethod
    def _objdump_switch_edges(binary):
        """Independent CFG edge oracle from GNU objdump's x86-64 instruction listing."""
        disassembly = subprocess.run(
            [shutil.which("objdump"), "-d", "--disassemble=truth_switch", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        rows = []
        instruction_line = re.compile(
            r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*"
            r"([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
        )
        for line in disassembly.splitlines():
            m = instruction_line.match(line)
            if not m:
                continue
            rows.append({
                "addr": int(m.group(1), 16),
                "size": len(m.group(2).split()),
                "mnemonic": m.group(3).lower(),
                "operands": m.group(4),
            })
        rows.sort(key=lambda row: row["addr"])
        if not rows:
            raise AssertionError("objdump produced no instructions for truth_switch")

        addresses = {row["addr"] for row in rows}
        leaders = {rows[0]["addr"]}
        terminators = set()
        for index, row in enumerate(rows):
            mnemonic = row["mnemonic"]
            is_jump = mnemonic.startswith("j")
            is_return = mnemonic.startswith("ret")
            if not (is_jump or is_return):
                continue
            terminators.add(row["addr"])
            target_match = re.match(r"^\s*([0-9a-fA-F]+)\b", row["operands"])
            if is_jump and target_match and not row["operands"].lstrip().startswith("*"):
                target = int(target_match.group(1), 16)
                if target in addresses:
                    leaders.add(target)
            next_addr = row["addr"] + row["size"]
            if next_addr in addresses:
                leaders.add(next_addr)

        groups = {}
        current = None
        for row in rows:
            if current is None or row["addr"] in leaders:
                current = row["addr"]
                groups[current] = []
            groups[current].append(row)

        expected = set()
        block_starts = set(groups)
        for start, block in groups.items():
            last = block[-1]
            mnemonic = last["mnemonic"]
            next_addr = last["addr"] + last["size"]
            target_match = re.match(r"^\s*([0-9a-fA-F]+)\b", last["operands"])
            target = (
                int(target_match.group(1), 16)
                if target_match and not last["operands"].lstrip().startswith("*")
                else None
            )
            if mnemonic.startswith("ret"):
                continue
            if mnemonic.startswith("jmp"):
                if target in block_starts:
                    expected.add((start, target))
                continue
            if mnemonic.startswith("j"):
                if target in block_starts:
                    expected.add((start, target))
                if next_addr in block_starts:
                    expected.add((start, next_addr))
                continue
            if next_addr in block_starts:
                expected.add((start, next_addr))
        return expected, rows

    def test_compiler_switch_cfg_edges_match_independent_objdump_oracle(self):
        source = Path(__file__).resolve().parent / "fixtures" / "function_discovery_fixture.c"
        with tempfile.TemporaryDirectory(prefix="rdis-switch-cfg-truth-") as temporary:
            binary = Path(temporary) / "switch-o0"
            command = [
                shutil.which("cc"),
                "-O0",
                "-fno-jump-tables",
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
                "switch fixture compiler failed: " + " ".join(command) + "\n" + built.stderr,
            )

            symbols = self._symbol_truth(binary)
            switch_addr = symbols["truth_switch"]
            expected_edges, instructions = self._objdump_switch_edges(binary)
            program = Program(open_image(str(binary), arch="x86_64")).analyze(
                objc=False, swift=False, prologues=True
            )
            self.assertIn(switch_addr, program.functions)
            func = program.functions[switch_addr]
            observed_edges = {
                (block.addr, successor)
                for block in func.blocks.values()
                for successor in block.succs
            }
            metrics = _precision_recall_f1(expected_edges, observed_edges)
            report = {
                "fixture": "compiler-switch-cfg-v1",
                "architecture": "x86_64",
                "compiler": subprocess.run(
                    [shutil.which("cc"), "--version"], check=True,
                    capture_output=True, text=True
                ).stdout.splitlines()[0],
                "oracle": "GNU objdump direct-branch CFG reconstruction",
                "optimization": "-O0",
                "jump_tables": "disabled to isolate direct branch edge semantics",
                "function_addr": hex(switch_addr),
                "oracle_instructions": len(instructions),
                **metrics,
            }
            print("CFG_EDGE_METRIC " + json.dumps(report, sort_keys=True))
            self.assertGreaterEqual(len(expected_edges), 20, json.dumps(report, sort_keys=True))
            self.assertEqual(
                observed_edges, expected_edges,
                "RDIS switch CFG differs from the independent objdump oracle: "
                + json.dumps(report, sort_keys=True)
                + "\nexpected-only=" + repr(sorted(expected_edges - observed_edges))
                + "\nobserved-only=" + repr(sorted(observed_edges - expected_edges)),
            )
            self.assertEqual(metrics["precision"], 1.0, json.dumps(report, sort_keys=True))
            self.assertEqual(metrics["recall"], 1.0, json.dumps(report, sort_keys=True))
            self.assertEqual(metrics["f1"], 1.0, json.dumps(report, sort_keys=True))



@unittest.skipUnless(
    platform.system() == "Linux"
    and platform.machine().lower() in ("x86_64", "amd64")
    and all(shutil.which(tool) for tool in ("cc", "nm", "objdump")),
    "optimized ELF jump-table truth currently runs on Linux x86-64",
)
class OptimizedJumpTableTruthTests(unittest.TestCase):
    """Exercise the relative-offset jump-table recovery path against GNU objdump bytes."""

    CASE_COUNT = 12

    @staticmethod
    def _symbol_address(binary, wanted):
        result = subprocess.run(
            [shutil.which("nm"), "-n", "--defined-only", str(binary)],
            check=True, capture_output=True, text=True,
        )
        symbols = {}
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*([0-9a-fA-F]+)\s+[Tt]\s+(\S+)\s*$", line)
            if match:
                symbols[match.group(2)] = int(match.group(1), 16)
        if wanted not in symbols:
            raise AssertionError(f"nm did not find required symbol {wanted!r}")
        return symbols[wanted]

    @staticmethod
    def _disassembly(binary):
        result = subprocess.run(
            [shutil.which("objdump"), "-d", "--disassemble=truth_switch_jump_table", str(binary)],
            check=True, capture_output=True, text=True,
        )
        pattern = re.compile(
            r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*"
            r"([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
        )
        rows = []
        for line in result.stdout.splitlines():
            match = pattern.match(line)
            if not match:
                continue
            mnemonic = match.group(3).lower()
            operands = match.group(4)
            # GNU objdump may print the legacy branch-not-taken prefix as a separate
            # mnemonic token, e.g. "notrack jmp *%rax". Normalize it so the independently
            # reconstructed CFG sees the same actual indirect JMP instruction bytes.
            if mnemonic in ("notrack", "bnd", "data16"):
                prefixed = re.match(r"^\\s*(jmpq?|callq?)\\s+(.*)$", operands, re.I)
                if prefixed:
                    mnemonic, operands = prefixed.group(1).lower(), prefixed.group(2)
            rows.append({
                "addr": int(match.group(1), 16),
                "size": len(match.group(2).split()),
                "mnemonic": mnemonic,
                "operands": operands,
            })
        rows.sort(key=lambda row: row["addr"])
        if not rows:
            raise AssertionError("GNU objdump produced no instructions for truth_switch_jump_table")
        return rows

    @staticmethod
    def _section_bytes(binary, section_name):
        result = subprocess.run(
            [shutil.which("objdump"), "-s", "-j", section_name, str(binary)],
            check=True, capture_output=True, text=True,
        )
        memory = {}
        # objdump -s prints each row as an address followed by groups of eight hex digits,
        # then an ASCII preview. Only the explicit hexadecimal groups are parsed.
        row_pattern = re.compile(r"^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{8}\s+)+)")
        for line in result.stdout.splitlines():
            match = row_pattern.match(line)
            if not match:
                continue
            start = int(match.group(1), 16)
            raw = bytes.fromhex(match.group(2))
            for offset, value in enumerate(raw):
                memory[start + offset] = value
        if not memory:
            raise AssertionError(f"GNU objdump produced no bytes for section {section_name!r}")
        return memory

    @staticmethod
    def _is_conditional_jump(row):
        mnemonic = row["mnemonic"]
        return mnemonic.startswith("j") and mnemonic not in ("jmp", "jmpq")

    @classmethod
    def _oracle_cfg(cls, binary):
        """Build expected in-function edges from decoded bytes, not from RDIS output.

        GNU objdump supplies instruction boundaries and direct branch destinations. The table
        base is recovered independently from the RIP-relative LEA comment and its 12 signed
        32-bit offsets are read from the ELF .rodata bytes.
        """
        rows = cls._disassembly(binary)
        addresses = {row["addr"] for row in rows}
        by_address = {row["addr"]: row for row in rows}
        start = rows[0]["addr"]

        table_load = next(
            (row for row in rows
             if row["mnemonic"] == "lea" and "(%rip)" in row["operands"] and "#" in row["operands"]),
            None,
        )
        if table_load is None:
            raise AssertionError("compiler did not emit a RIP-relative LEA for the jump-table base")
        table_match = re.search(r"#\s*([0-9a-fA-F]+)\b", table_load["operands"])
        if table_match is None:
            raise AssertionError("could not recover jump-table base from GNU objdump's LEA comment")
        table_base = int(table_match.group(1), 16)

        dispatch = next(
            (row for row in rows
             if row["mnemonic"] in ("jmp", "jmpq") and row["operands"].lstrip().startswith("*")),
            None,
        )
        if dispatch is None:
            raise AssertionError("optimized compiler output contains no indirect jump-table dispatch")
        memory = cls._section_bytes(binary, ".rodata")
        table_targets = []
        for index in range(cls.CASE_COUNT):
            entry = table_base + index * 4
            locations = range(entry, entry + 4)
            if not all(address in memory for address in locations):
                raise AssertionError(f"jump-table entry {index} at {entry:#x} is outside .rodata")
            raw = bytes(memory[address] for address in locations)
            target = table_base + int.from_bytes(raw, "little", signed=True)
            if target not in addresses:
                raise AssertionError(
                    f"jump-table entry {index} resolves to {target:#x}, not an instruction in the function"
                )
            table_targets.append(target)
        if len(set(table_targets)) != cls.CASE_COUNT:
            raise AssertionError(f"the jump table unexpectedly aliases case targets: {table_targets!r}")

        def next_address(row):
            return row["addr"] + row["size"]

        def successors(row):
            address = row["addr"]
            mnemonic = row["mnemonic"]
            operands = row["operands"]
            following = next_address(row)
            if mnemonic.startswith("ret"):
                return set()
            if address == dispatch["addr"]:
                return set(table_targets)
            if mnemonic in ("jmp", "jmpq"):
                # A direct tail jump to another function leaves this function's CFG.
                target_match = re.match(r"^\s*(?:0x)?([0-9a-fA-F]+)\b", operands)
                if target_match:
                    target = int(target_match.group(1), 16)
                    return {target} if target in addresses else set()
                return set()
            if cls._is_conditional_jump(row):
                result = set()
                target_match = re.match(r"^\s*(?:0x)?([0-9a-fA-F]+)\b", operands)
                if target_match:
                    target = int(target_match.group(1), 16)
                    if target in addresses:
                        result.add(target)
                if following in addresses:
                    result.add(following)
                return result
            return {following} if following in addresses else set()

        successors_by_address = {row["addr"]: successors(row) for row in rows}
        reachable = set()
        pending = [start]
        while pending:
            address = pending.pop()
            if address in reachable:
                continue
            reachable.add(address)
            pending.extend(successors_by_address[address] - reachable)

        leaders = {start}
        for row in rows:
            address = row["addr"]
            if address not in reachable:
                continue
            # Only control-flow destinations and conditional fallthroughs start blocks. Ordinary
            # instruction fallthroughs must not turn every instruction into its own basic block.
            if (row["mnemonic"].startswith("j") or row["mnemonic"].startswith("ret")):
                leaders.update(successors_by_address[address] & reachable)

        blocks = {}
        current = None
        previous = None
        for row in rows:
            address = row["addr"]
            if address not in reachable:
                continue
            previous_terminates = (
                previous is not None
                and (previous["mnemonic"].startswith("j") or previous["mnemonic"].startswith("ret"))
            )
            contiguous = previous is not None and next_address(previous) == address
            if current is None or address in leaders or previous_terminates or not contiguous:
                current = address
                blocks[current] = []
            blocks[current].append(row)
            previous = row

        edges = set()
        for block_start, block_rows in blocks.items():
            last = block_rows[-1]
            edges.update(
                (block_start, target)
                for target in successors_by_address[last["addr"]]
                if target in blocks
            )
        return {
            "entry": start,
            "dispatch": dispatch["addr"],
            "table_base": table_base,
            "table_targets": set(table_targets),
            "rows": rows,
            "reachable": reachable,
            "block_starts": set(blocks),
            "edges": edges,
        }

    def test_o2_relative_jump_table_edges_match_independent_rodata_oracle(self):
        source = Path(__file__).resolve().parent / "fixtures" / "switch_jump_table_fixture.c"
        compiler = shutil.which("cc")
        with tempfile.TemporaryDirectory(prefix="rdis-relative-jump-table-") as temporary:
            binary = Path(temporary) / "switch-jump-table-pie"
            command = [
                compiler, "-O2", "-fPIE", "-pie", "-fno-inline",
                "-fno-omit-frame-pointer", "-fno-stack-protector",
                "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                str(source), "-o", str(binary),
            ]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(
                built.returncode, 0,
                "jump-table fixture compiler failed: " + " ".join(command) + "\n" + built.stderr,
            )

            switch_address = self._symbol_address(binary, "truth_switch_jump_table")
            oracle = self._oracle_cfg(binary)
            self.assertEqual(oracle["entry"], switch_address)
            self.assertEqual(len(oracle["table_targets"]), self.CASE_COUNT)
            self.assertGreaterEqual(len(oracle["edges"]), self.CASE_COUNT + 2)

            program = Program(open_image(str(binary), arch="x86_64")).analyze(
                objc=False, swift=False, prologues=True
            )
            self.assertIn(switch_address, program.functions, "RDIS failed to discover the named switch")
            function = program.functions[switch_address]
            observed_edges = {
                (block.addr, successor)
                for block in function.blocks.values()
                for successor in block.succs
            }
            dispatch_block = next(
                (block for block in function.blocks.values()
                 if block.insns and block.insns[-1].address == oracle["dispatch"]),
                None,
            )
            self.assertIsNotNone(dispatch_block, "RDIS CFG omitted the indirect-dispatch block")
            self.assertEqual(
                set(dispatch_block.succs), oracle["table_targets"],
                "RDIS did not resolve every relative jump-table target",
            )
            jump_table = program.jump_tables.get(oracle["dispatch"])
            self.assertIsNotNone(jump_table, "RDIS did not retain decoded jump-table provenance")
            self.assertEqual(set(jump_table["cases"].values()), oracle["table_targets"])

            metrics = _precision_recall_f1(oracle["edges"], observed_edges)
            report = {
                "fixture": "optimized-relative-jump-table-v1",
                "architecture": "x86_64",
                "compiler": subprocess.run(
                    [compiler, "--version"], check=True,
                    capture_output=True, text=True,
                ).stdout.splitlines()[0],
                "oracle": "GNU objdump instruction decode + independently parsed signed int32 .rodata offsets",
                "optimization": "-O2",
                "pie": True,
                "table_base": hex(oracle["table_base"]),
                "dispatch": hex(oracle["dispatch"]),
                "case_count": self.CASE_COUNT,
                "expected_blocks": len(oracle["block_starts"]),
                "expected_edges": len(oracle["edges"]),
                **metrics,
            }
            print("CFG_EDGE_METRIC " + json.dumps(report, sort_keys=True))
            self.assertEqual(
                observed_edges, oracle["edges"],
                "RDIS's optimized jump-table CFG differs from the independent byte oracle: "
                + json.dumps(report, sort_keys=True)
                + "\nexpected-only=" + repr(sorted(oracle["edges"] - observed_edges))
                + "\nobserved-only=" + repr(sorted(observed_edges - oracle["edges"])),
            )
            self.assertEqual(metrics["precision"], 1.0, json.dumps(report, sort_keys=True))
            self.assertEqual(metrics["recall"], 1.0, json.dumps(report, sort_keys=True))
            self.assertEqual(metrics["f1"], 1.0, json.dumps(report, sort_keys=True))


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
                    if mode == "stripped":
                        diagnostic_image = open_image(str(candidate), arch="arm64")
                        target = truth["truth_address_taken"]
                        section = diagnostic_image.section_at(target)
                        section_bytes = (
                            diagnostic_image.read(section.va, section.size) if section else b""
                        )
                        report["address_taken_diagnostic"] = {
                            "prefix_hex": diagnostic_image.read(target, 32).hex(" "),
                            "section": section.name if section else None,
                            "section_va": hex(section.va) if section else None,
                            "section_code": section.code if section else None,
                            "is_code": diagnostic_image.is_code(target),
                            "loader_symbol": diagnostic_image.symbols.get(target),
                            "allocation_first_frame_save_match": (
                                Program(diagnostic_image)._arm64_stack_adjust_then_fp_lr_save(
                                    section_bytes, target - section.va
                                ) if section else False
                            ),
                            "allocation_first_leaf_spill_match": (
                                Program(diagnostic_image)._arm64_stack_adjust_with_stack_access(
                                    section_bytes, target - section.va
                                ) if section else False
                            ),
                            "preceding_16_hex": (
                                diagnostic_image.read(target - 16, 16).hex(" ")
                                if target >= 16 else ""
                            ),
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
