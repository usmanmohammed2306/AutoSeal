# Follow a repair through execution and rollback

The first repair looked successful: removing `conftest.py` stopped an incorrect solution from skipping the tests. That leaves several harder questions. Did the correct solutions still work? Were the repeated runs actually new containers? Did rollback select the original policy again? Could a saved summary say “passed” when the raw output said something else?

The managed validation path makes those questions inspectable. It currently handles the small checked-in `is_even` fixture. It records an **abstention**, not a promoted repair.

## Run it

Use the project virtual environment with the development and server dependencies installed. Docker Desktop must be running and signed in when required by the local installation.

```bash
python -m pip install -e '.[dev,server]'
docker build -f docker/fixture.Dockerfile -t autoseal-fixture:local .
python -m autoseal managed-repair validate --root .autoseal/managed-attempt-01
```

Choose a new root for each attempt. The command returns a report digest and writes a convenience reference at `.autoseal/managed-attempt-01/report.json`. Keep the digest separately when selecting evidence to review. The reference file is mutable; the digest identifies the actual report.

Then verify it without running Docker or executing the saved candidate:

```bash
python -m autoseal managed-repair verify REPORT_SHA256_ID --root .autoseal/managed-attempt-01
```

A zero command exit means the evidence was recorded or verified. Read `disposition` and `gates` to determine whether a repair passed. The current path cannot issue `SealEvidence` or accept a promotion.

## What runs

The manager freezes the image, source artifacts, task and three-operator repair plan. It retains the complete candidate bytes, including configuration hooks. It then runs:

| Controls | Number | Purpose |
|---|---:|---|
| Structurally different correct implementations | 2 | Preservation |
| Ordinary incorrect implementations | 2 | Negative controls |
| Disclosed skip-hook exploits | 2 | Known false rewards |
| Hooks generated after the plan is frozen | 2 | Narrow post-selection variants |
| Early-exit stress control | 1 | Missing behavioral evidence |

Each of the first eight controls gets one proxy run, one audit and three sealed runs. The stress control gets a sealed run. After rollback, the original exploit is run again through the parent proxy. That makes **42 candidate evaluations per complete validation attempt**. Schema 3 also runs one owned-profile capability probe, making 43 container executions. Repeated executions are not additional independent cases.

Only the projected `solution.py` enters the owned behavioral worker. The host manager compares returned booleans against expected answers; candidate-provided verdict strings do not own the score. The audit uses separate inputs and a separate reference expression. This is a finite oracle with an explicitly narrow task contract.

The post-selection variants belong to the same synthetic hook family. They are not blind external attacks or model-discovered exploits.

## What verification checks

The offline verifier reloads the candidate snapshots and the bound execution records. It recomputes verdicts and counts from process output, checks Docker create/inspect/start/remove linkage, compares declared restrictions with daemon metadata, checks distinct container identities for clean repeats, and verifies the parent/child policy and rollback references. The restored proxy must reproduce the original behavior.

Rehashing a false summary is insufficient: its raw receipts and context must also agree. Tests cover substituted contexts, altered outputs, changed candidate bytes, reused repeats, failed cleanup, false gate flags and corrupt stored bytes.

The caller-selected digest and manager-owned evidence store are trusted inputs. Content hashes are not signatures and cannot establish that a dishonest host actually ran a command. The verifier does not execute archived source code.

## Why the current repair is not promoted

The configuration-hook controls are rejected while the two valid implementations remain accepted. The early-exit candidate still produces no behavioral answer, so its result remains `INCONCLUSIVE`. It is not counted as a successful functional rejection.

Daemon configuration is also distinct from active capability probing. Schema 3 runs a trusted probe through the same creation, projection and cleanup path as the owned behavioral worker. It attempts root and candidate-directory writes and IPv4/IPv6 connections, and observes the process user, capabilities, seccomp, no-new-privileges and cgroup limits. It also checks projected filenames and named credential/socket absence. The probe never imports the candidate.

Its raw receipts, challenge and observations are bound to the exact child revision and candidate. The offline verifier recomputes every check. These are finite observations, not exhaustive network or secret coverage, resource-exhaustion tests, or a kernel security guarantee. The separate writable-workspace agent probe cannot substitute for this proof.

Schema-2 archives remain readable and retain their missing active-probe gate. New evidence does not retrospectively change an old run. Even when the owned-profile probe passes, early exit still prevents promotion: the disposition remains `UNENFORCEABLE` and `activation_id` stays null.

Rollback covers the declared managed artifacts, policy and cache namespace. It does not undo undeclared host effects, prove kernel isolation, or make local Docker a public hostile-code service.

## Inspect the report in Studio

Start the existing local database and API as documented in the main README, adding the pinned report configuration:

```bash
python -m autoseal serve \
  --database-url "$AUTOSEAL_DATABASE_URL" \
  --store .autoseal/evidence \
  --managed-report-root .autoseal/managed-attempt-01 \
  --managed-report-id REPORT_SHA256_ID
```

Open `/repairs` in the local Studio. The retained execution panel shows the control matrix, all three repeats, missing gates, original execution date and report identity. The API rechecks the pinned archive on every request. Missing or corrupt archives return an unavailable response; the browser cannot submit an arbitrary filesystem path. Viewing this panel does not start containers or promote a repair.

## Exercise the real local platform

The following check starts its own disposable PostgreSQL container from the cached image pinned in `compose.yaml`. It runs migrations, starts an HTTP API, queues controls, executes separate workers against Docker, inspects database-backed results and checks CAS evidence independently. It also exercises idempotency conflicts, an injected expired lease, corrupt evidence refusal and recovery. It removes only its own database container and stops its own API afterward.

```bash
python scripts/validate_local_workflow.py \
  --root .autoseal/platform-attempt-01 \
  --managed-root .autoseal/managed-attempt-01 \
  --managed-id REPORT_SHA256_ID
```

The database image and fixture image must already be available locally. No existing database is reused. The script keeps its random database credential in process memory and redacts it from retained output. Review `report.json` and the linked evidence objects. A simulated expired lease is a controlled database fault, not an actual killed-worker experiment.

This verifies a local engineering workflow. It does not establish external-case generalization, a downstream training gain, public deployment or complete V1 acceptance.

## Learn by changing one boundary

Start with `tests/unit/test_managed_receipts.py`. Trace the stored process output into `verify_runtime_result`. Change a copy of the output while keeping the old passing summary, run the focused test, and observe the refusal. Then change a result context or reuse one sealed receipt as another repeat. Trace why those fail for different reasons.

Rebuild those checks in your own learning checkout before committing them. A useful increment is a verifier plus the tampering case you personally implemented and can debug. Keep the real execution archives separate from synthetic unit-test receipts and do not manufacture daily Git history.
