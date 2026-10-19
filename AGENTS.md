# Repository agent instructions

These rules apply to every RDIS-related coding, research, review, planning or product task.

## First action: read the roadmap

Before taking any action, read the complete root-level DEVELOPMENT_ROADMAP.md. Treat its **Current resume cursor**, **Milestone register**, and **Append-only request ledger** as the authority for what is next. Do not rely on chat history alone.

## Required workflow for every RDIS request

1. Fetch current main, the active branch/PR and current CI state. Confirm whether new commits or a merge changed the baseline.
2. Read DEVELOPMENT_ROADMAP.md and the latest request entry. If no active PR exists, create a branch from the exact latest main commit with a conventional, task-specific name. Do not continue work on an obsolete branch without a reason.
3. Append the new RDIS request as a new entry at the end of the roadmap's request ledger before substantial implementation; add new milestones at the end of the milestone register if the request exposes missing work.
4. Select the highest-priority incomplete milestone that unblocks the request. Split it into small atomic changes and define the acceptance test before implementing.
5. Inspect the primary source files, relevant tests, tool documentation and official competitor references. Do not infer unseen source behavior from README claims.
6. Implement the smallest complete increment, add regression coverage for every confirmed defect, and commit with a conventional, specific message. Preserve existing behavior unless the roadmap or tests justify a deliberate change.
7. Test at two levels: the focused regression and the wider affected suite. For UI work, use real browsers and capture screenshots/geometry/accessibility evidence. For analysis correctness, use independent fixtures, runtime equivalence, symbols/debug truth or a carefully adjudicated second-tool comparison.
8. If anything fails, preserve the failure, identify the actual cause, fix it, add a regression, and rerun the failed test plus the relevant wider suite. Never call a test passed if it was not executed.
9. After each meaningful commit, update DEVELOPMENT_ROADMAP.md: milestone status, new evidence URLs, commit SHA, tests and outcomes, unresolved risks, request status and exact next atomic action. The roadmap update is part of the deliverable.
10. Before stopping, leave a resume cursor precise enough that another session can continue without guessing. Report any unresolved failure or blocker.
11. Keep the requested PR open and unmerged. Update its description with changes, evidence, limitations and next gates. Never merge it unless the user explicitly instructs that action.
12. Do not add the internal roadmap to GitHub Pages, the sitemap or docs/llms.txt unless the user expressly asks; main intentionally keeps internal planning out of the marketing/discovery surface.

## Evidence and engineering discipline

- Label claims in working notes as verified, inferred or assumed. Link primary vendor docs and exact repository/CI evidence; vendor pages prove a documented capability, not that the vendor's output is correct.
- Distinguish support for loading a format, decoding instructions, finding functions, recovering correct CFG edges, lifting instructions, producing semantically equivalent output and supporting debugging/types. They are separate support levels.
- Keep “compile rate” separate from semantic-equivalence rate, and both separate from human readability.
- Unknown/ambiguous analysis is preferable to a confident false answer. Expose unsupported operations, unresolved indirect edges, inferred types and low-confidence matches.
- Use the same corpus/options and versions for competitor comparisons where possible; state when a comparison is not reproducible.
- Benchmarks must include input hashes, options, versions, hardware/OS, cold/warm timings, p50/p95, memory and raw outputs.
- Treat uploaded binaries, archives, project files, symbols/comments, graph labels, plugin code, debugger parameters and remote requests as untrusted.
- Every source fix should gain a regression when feasible. Avoid brittle source-string assertions as the only evidence for a real UI/runtime behavior.
- Avoid massive changes without intermediate commits; use focused commits that can be reverted and bisected.
- Do not invent work, results, feature parity or test outcomes. Never claim broad competitor superiority without measured task-level evidence.
- User goal is to pursue combined feature breadth across IDA Pro/Hex-Rays, Ghidra, Binary Ninja, Hopper, radare2/Cutter, angr, RetDec and comparable tools. Treat that as a long-term measured objective, not a single-release promise.

## Resume behavior after retry or interruption

On retry, read DEVELOPMENT_ROADMAP.md first; fetch current main and branch/PR heads; compare those SHAs with the resume cursor; inspect latest CI results; re-run the last failing/uncertain gate if needed; and resume the next atomic action. Never restart the roadmap from zero, discard a failure, or ask the user to restate context that the repository already records.

