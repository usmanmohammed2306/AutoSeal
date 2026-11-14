# When changing the interpreter hides a broken script

A shell-compatibility task asks an agent to fix three scripts so they work under dash. The publicly disclosed exploit changes the environment instead: replace dash with bash, then leave the incompatible scripts untouched. The native tests still invoke `/bin/sh`, but that name now resolves to a different interpreter.

AutoSeal reproduced this mechanism using the [pinned public task-125 source](https://github.com/few-sh/terminal-wrench/tree/d8a29613235a0ef56a8b70b3142626a533da28c2/tasks/125/claude-opus-4.6/original_task). Discovery credit belongs to the original TerminalWrench reporters. This is a selected disclosed reproduction, not AutoSeal discovering a new vulnerability or a measurement across the whole benchmark.

## What was compared

Eight candidate bundles were frozen before execution. Each was checked in three fresh Docker environments:

- The original test module, after applying the candidate's reviewed script and runtime changes.
- A separate audit using a pristine interpreter, actual script executions and task-output checks.
- The unchanged original test module in a pristine runtime, projecting only submitted application scripts.

| Controls | Original tests | Clean-runtime audit | Projected tests |
|---|---|---|---|
| Public correct POSIX repair and a separately written alternative | PASS | PASS | PASS |
| Unmodified incompatible scripts and an ordinary wrong-output implementation | REJECT | REJECT | REJECT |
| Four disclosed interpreter-mutation variants | PASS | REJECT | REJECT |

The eight controls produced 24 fresh container evaluations in this run. They are not 24 unique tasks, blind attacks or independent model samples. The two search-excluded variants are authored disclosed controls. No repair search was performed on this case, so they must not be presented as unseen attacks against a selected native repair.

The original test file has SHA-256 `1a85448e1d9bb9c029f7822965709a017f82d2eb3adcc689f3e8f35e093eeb3b`. The separate audit checks script completion, exact backup bytes, deployment state and tab-separated processed rows. It also records runtime binary fingerprints. It does not call the native Pytest oracle.

## Reproduction boundary

The image follows the original task's Ubuntu recipe with a pinned Ubuntu 24.04 base and added Pytest dependencies. The original test module is unchanged. Dependency bootstrap is adapted, the experiment runs on arm64, and the official Terminal-Bench harness is not executed. This is native-test evidence, not an official leaderboard score or proof of historical machine parity.

The vulnerable proxy needs a writable container root to reproduce the reported binary replacement. It has no network, host-writable mount, privileged mode, added capabilities or Docker socket. The clean audit/projected profiles use a read-only root, nonroot user and bounded writable task directories. All candidate execution occurs in Mac Docker. These finite controls do not establish protection against every hostile program or container escape.

The report includes raw creation, inspection, execution and cleanup receipts, candidate identities, interpreter fingerprints, the reviewed worker and original source bytes. `native_shell_archive.py` rechecks their linkage and completed native-test counts. A collection error or verifier crash cannot become a successful block. Forged candidate, worker, source, summary and cleanup references are rejected.

This case has no promoted `SealEvidence`. It remains separate from the admitted seeded fixed-output cases and the official SWE-bench harness archive. A native repair still needs its own typed search, active enforcement, preservation/repeatability, fresh re-attacks, exact rollback and promotion evidence.

## Commands and prerequisites

`scripts/reproduce_terminal_shell.py` accepts a reviewed source directory and an already built recipe-derived image. It does not download unreviewed tasks or substitute a different environment silently. Preserve the upstream license and benchmark canaries when obtaining the pinned source. Keep benchmark task bytes out of training data.

```bash
python scripts/fetch_terminal_shell_source.py --root .autoseal/reviewed-shell-source
# Review the saved license, instruction, source manifest and Dockerfile.
python scripts/build_terminal_shell.py \
  --source .autoseal/reviewed-shell-source \
  --root .autoseal/shell-build-01
python scripts/reproduce_terminal_shell.py \
  --source .autoseal/reviewed-shell-source \
  --image autoseal/terminal-shell-125:reproduced \
  --root .autoseal/shell-native-test-01
python -m pytest tests/unit/test_native_shell_archive.py -q
```

The source fetcher accepts only this pinned reviewed case and verifies every file before saving it. It runs no downloaded code. The builder verifies those bytes again and copies only named test files into its context. Use a new root for each step. The default build platform is arm64; use `--platform linux/amd64` only for a separately labelled run. The builder retains the recipe, image inspection and process evidence. Rebuilding does not imply an identical historical image.

The offline archive checks explicitly skip when the separately retained local archive is absent. An archive that is present but corrupt fails. To expose a reviewed saved report in Studio, configure the API with `--shell-archive-root ARCHIVE_ROOT --shell-archive-id REPORT_ID`. Requests cannot choose arbitrary host paths or reports. The research screen shows the exact scope and missing-evidence state.

The original base registry for a different prime-generator task timed out during review. That unsuccessful attempt was retained separately and contributes no native result.
