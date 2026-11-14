"""Fail-closed V1 evidence inspection.

Release status is derived by registered receipt verifiers. A caller cannot
provide passing booleans, waive a requirement or relabel a calibration study.
Unsupported or missing proof remains an open gate.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from autoseal.artifact_cases import registered_tasks
from autoseal.artifact_pipeline import _manager, verify_artifact_validation
from autoseal.native_scorecard import score_native_archive
from autoseal.native_shell_archive import verify_shell_report
from autoseal.sft_archive import verify_sft_evaluation
from autoseal.storage import ContentAddressedStore, IntegrityError


DIGEST = r"^sha256:[0-9a-f]{64}$"
PROJECT = Path(__file__).resolve().parents[2]


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directory: str = Field(min_length=1, max_length=512)
    identity: str = Field(pattern=DIGEST)


class ReleaseCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["autoseal_release_candidate"] = "autoseal_release_candidate"
    schema_version: Literal[1] = 1
    authored_corpus: Optional[EvidenceReference] = None
    native_shell: Optional[EvidenceReference] = None
    native_swebench_directory: Optional[str] = None
    sft_calibration: Optional[EvidenceReference] = None


def _directory(root, relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts) or str(path) != relative:
        raise IntegrityError("release evidence directory must be canonical and relative")
    resolved = root.resolve() / relative
    # Evidence inputs are not allowed to escape the declared archive root.
    if root.resolve() not in resolved.resolve().parents or resolved.is_symlink():
        raise IntegrityError("release evidence escapes its archive root")
    return resolved


def _authored(root, reference):
    directory = _directory(root, reference.directory)
    store = ContentAddressedStore(directory / "evidence")
    report = store.get_json(reference.identity)
    if report["kind"] != "authored_artifact_corpus_validation" or report["schema_version"] != 1:
        raise IntegrityError("unsupported authored-corpus receipt")
    tasks = registered_tasks()
    rows = report["cases"]
    if (report["status"] != "PASSED" or len(rows) != len(tasks)
            or {row["case"] for row in rows} != set(tasks)):
        raise IntegrityError("authored corpus omits, repeats or substitutes a registered case")
    checked = []
    current = {str(path.relative_to(PROJECT)): path.read_bytes() for path in sorted((PROJECT / 'src/autoseal').glob('*.py'))}
    for row in rows:
        case_store = ContentAddressedStore(directory / row["case"] / "evidence")
        validation = case_store.get_json(row["validation_id"])
        result = verify_artifact_validation(case_store, row["validation_id"])
        task = case_store.get_json(validation['case_id'])['task']
        if task != tasks[row['case']].model_dump(mode='json') or not all(result['gates'].values()):
            raise IntegrityError("authored corpus summary contradicts verified task gates")
        child = _manager(case_store).load(validation['child_revision'])
        frozen = {name: case_store.get_bytes(ref) for name, ref in child.artifacts.items() if name.startswith('src/autoseal/')}
        checked.append({'case': row['case'], 'validation_id': row['validation_id'],
            'source_current': frozen == current, 'gates': result['gates']})
    return {'cases': checked, 'distinct_seeded_cases': len(checked),
        'all_sources_current': all(row['source_current'] for row in checked),
        'scope': 'Eight authored finite output tasks; external cases remain separate.'}


def inspect_release(root: Path, candidate: ReleaseCandidate):
    """Read retained evidence only. Never launches Docker, training or cloud."""
    gates, evidence = [], {}
    def gate(name, state, detail):
        gates.append({'id': name, 'status': state, 'detail': detail})
    def inspect(name, reference, verifier):
        if reference is None:
            gate(name, 'MISSING', 'No supported immutable evidence reference supplied.')
            return None
        try:
            value = verifier(reference)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            gate(name, 'FAILED', f'{type(exc).__name__}: {exc}')
            return None
        evidence[name] = value
        gate(name, 'VERIFIED', 'Retained receipt and its linked evidence verified; see the bounded scope.')
        return value
    authored = inspect('seeded_repair_admission', candidate.authored_corpus, lambda ref: _authored(root, ref))
    gate('release_source_binding', 'PASSED' if authored and authored['all_sources_current'] else 'MISSING',
        'Every admission must bind the complete current runtime source inventory; historical archives remain valid historical evidence.')
    shell = inspect('external_shell_reproduction', candidate.native_shell, lambda ref:
        verify_shell_report(ContentAddressedStore(_directory(root, ref.directory) / 'evidence'), ref.identity))
    native = inspect('external_swebench_reproduction', candidate.native_swebench_directory, lambda directory:
        score_native_archive(_directory(root, directory)))
    calibration = inspect('sft_format_calibration', candidate.sft_calibration, lambda ref:
        verify_sft_evaluation(ContentAddressedStore(_directory(root, ref.directory) / 'evidence'), ref.identity))
    # These receipts establish reproduction or calibration. They do not carry
    # the missing promotion, hidden-audit or operated-delivery obligations.
    gate('external_corpus_and_native_repairs', 'MISSING',
        f'{int(shell is not None) + int(native is not None)} distinct native reproduction archives checked; '
        'require 3 to 5 admitted external exploit-bearing cases, valid/invalid alternatives, committed re-attacks and upstream baselines. '
        'Reproduction alone cannot satisfy repair admission.')
    gate('clean_and_nonrepairable_corpus', 'MISSING',
        'Require at least three clean and two to three explicitly nonrepairable cases with checked routing receipts.')
    gate('matched_training_and_hidden_audits', 'MISSING',
        'Require a frozen vulnerable/sealed study, at least three seeds per arm, matched starting checkpoint and budgets, '
        'raw reward/checkpoint lineage, frozen hidden audits, all failures/exclusions and seed-level analysis. '
        + ('The supplied single-seed SFT calibration does not meet this requirement.' if calibration else 'No complete study receipt supplied.'))
    for name, detail in (
        ('repair_and_training_ablations', 'Require the frozen repair and training ablation tables derived from checked raw receipts.'),
        ('authenticated_end_to_end_product', 'Require the release-bound CLI/API/PostgreSQL/CAS/worker/browser path including denial, cancellation and recovery.'),
        ('security_and_recovery', 'Require release-bound hostile-artifact, migration, backup/restore, process cleanup and rollback evidence.'),
        ('scale_and_performance', 'Require source-bound property, scale, latency and resource-budget measurements.'),
        ('clean_room_reproduction', 'Require a new-environment reproduction with pinned dependencies and final source identity.'),
        ('aws_operated_delivery', 'Require authorized HTTPS delivery, least privilege, backup/restore, rollback, measured reliability, costs and teardown evidence.'),
        ('technical_and_learning_acceptance', 'Require the reviewed technical package, research/model limitations, proof walkthrough and separate personal ownership evidence.'),
        ('final_regression_and_publication', 'Require the final full checks on the release commit, reviewed public artifacts and verified repository visibility.'),
    ):
        gate(name, 'MISSING', detail)
    return {'kind': 'autoseal_release_check', 'schema_version': 1, 'release_eligible': False,
        'status': 'INCOMPLETE', 'gates': gates, 'evidence': evidence,
        'limitations': ['Read-only retained-evidence inspection. VERIFIED means the named bounded receipt, not V1 acceptance.',
            'Missing proof protocols remain explicit blockers; no caller-supplied PASS or waiver is accepted.',
            'The complete charter remains binding. This checker currently cannot issue a complete V1 release certificate.']}
