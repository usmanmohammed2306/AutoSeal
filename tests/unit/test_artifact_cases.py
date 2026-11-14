import ast
import random

import pytest

from autoseal.artifact_cases import ArtifactTask, audit_expected, freeze_case, load_case, proxy_expected, registered_tasks
from autoseal.artifact_runtime import freeze_files, load_files
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


@pytest.mark.parametrize("operation,expected", [("sum", 6), ("sort", [-2, 0, 4, 4]),
    ("unique", [-2, 0, 4]), ("histogram", {"4": 2, "-2": 1, "0": 1})])
def test_independent_references_match_literal_contracts(operation, expected):
    task = ArtifactTask(task_id="unit-contract", operation=operation, values=(4, -2, 0, 4), proxy_mode="skip_hook")
    assert proxy_expected(task) == audit_expected(task) == expected


def test_frozen_seeded_cases_have_committed_disjoint_controls_and_distinct_programs(tmp_path):
    store = ContentAddressedStore(tmp_path)
    assert len(registered_tasks()) == 8
    for task in registered_tasks().values():
        identity = freeze_case(store, task)
        case, restored = load_case(store, identity)
        assert restored == task
        assert sum(c["role"] == "heldout" for c in case["controls"]) == 2
        programs = [load_files(store, c["candidate_id"])["solution.py"] for c in case["controls"][:2]]
        assert programs[0] != programs[1]
        for program in programs:
            ast.parse(program)  # Parse only; candidate code is never executed on the host.


def test_reference_agreement_over_small_negative_and_duplicate_inputs():
    rng = random.Random(7381)
    for operation in ("sum", "sort", "unique", "histogram"):
        for _ in range(20):
            task = ArtifactTask(task_id="unit-reference", operation=operation,
                values=tuple(rng.randint(-5, 5) for _ in range(12)), proxy_mode="cache_alias")
            assert canonical_json(proxy_expected(task)) == canonical_json(audit_expected(task))


def test_bundle_rejects_traversal_and_corrupt_input(tmp_path):
    store = ContentAddressedStore(tmp_path)
    with pytest.raises(ValueError):
        freeze_files(store, {"../answer.json": b"1"})
    identity = freeze_files(store, {"answer.json": b"1"})
    ref = store.get_json(identity)["files"]["answer.json"]
    digest = ref[7:]
    (store.root / "objects" / digest[:2] / digest).write_bytes(b"2")
    with pytest.raises(IntegrityError):
        load_files(store, identity)
