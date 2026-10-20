# Run and inspect AutoSeal

Use Python 3.12, Node.js 24, pnpm, and Docker Desktop for the local platform. The process and synthetic-fixture checks run without a GPU. The API and Studio bind to localhost and are intended for local research.

## Source checks

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev,server]'
python -m pytest -q -m 'not docker'
python -m autoseal demo --summary
python -m autoseal conformance process-evidence
pnpm --dir apps/studio install --frozen-lockfile
pnpm --dir apps/studio typecheck
pnpm --dir apps/studio build
```

Host-side demo commands accept reviewed checked-in fixtures only. Run generated or untrusted candidates through the Docker boundary, never through the host fixture path. See the root README for PostgreSQL, migration, API, worker, and browser setup.

The GitHub workflow is manually triggered. Publishing source does not launch hosted tests, Docker jobs, cluster requests, or model training automatically. A configured workflow alone is not a passing hosted CI result.

On October 20, 2026, a clean export without the local raw archives passed **172 tests**, skipped **21 archive-dependent checks**, and deselected **27 Docker checks** under `-m 'not docker'`. The original working checkout, with its local archives present, passed **193 tests** under the same selection. Studio type checking and the production build passed. These were local checks using the existing environment; no hosted CI, fresh dependency installation, Docker evaluation, or GPU experiment ran for this source publication. The first export omitted the migration directory and failed its migration check; including the required files resolved that failure before the final clean run.

## Optional experiment archives

The checkout omits raw content-addressed stores under `examples/model_agent/evidence/`, `examples/upstream_swebench/native/evidence/`, and `examples/training_pilot/*/objects/`. Compact indexes and summary reports retain their historical identities and limitations. Those references do not imply the raw blobs are publicly downloadable.

Tests requiring these stores carry the `archive` marker. They skip with an explicit reason when the corresponding store is absent. If a store is present, integrity checks still run and reject modified bytes. To focus on source-only checks, use `python -m pytest -q -m 'not docker and not archive'`. To validate an authorized local archive, restore its original bytes at the documented path and run `python -m pytest -q -m archive`. Do not reconstruct missing blobs from a summary or change a digest to make a check pass.

The native evidence API returns unavailable when the original store is absent or invalid. Studio preserves this distinction. Existing raw archives are retained locally without rewriting their identities.

## Configure the trusted Sol relay

The relay uses configuration supplied by its operator rather than personal machine paths:

```bash
export AUTOSEAL_SOL_HOST=YOUR_USER@login.sol.rc.asu.edu
export AUTOSEAL_SOL_CONTROL=/absolute/path/to/your/ssh/control/socket
export AUTOSEAL_REMOTE_PYTHON=/absolute/path/to/remote/environment/bin/python
export AUTOSEAL_REMOTE_HELPER=/absolute/path/to/autoseal/scripts/sol/reward_exchange.py
export AUTOSEAL_EXCHANGE_BASE=/absolute/path/to/your/autoseal/bridge
```

The exchange base must be an absolute trusted remote directory. The Mac relay passes that base to the remote helper and accepts only validated exchange names beneath it. Existing historical experiment manifests bind older driver bytes; changing configuration or driver code requires a new frozen manifest before another run. No training job is required to inspect the public implementation.

## Attribution and evidence

See [third-party notices](../THIRD_PARTY_NOTICES.md) for the pinned grader excerpts and original disclosures. [Results](RESULTS.md) distinguishes recorded outcomes from the remaining research gates. Checkpoints, private data, credentials, local plans, and personal interview records are not part of the release.
