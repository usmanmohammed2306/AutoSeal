import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError, VerificationSnapshot


def test_new_verification_request_rechecks_disk_and_refuses_corruption(tmp_path):
    store = ContentAddressedStore(tmp_path)
    identity = store.put_json({"verdict": "REJECT"})
    snapshot = VerificationSnapshot(store)
    assert snapshot.get_json(identity) == {"verdict": "REJECT"}
    store._path(identity).write_bytes(b'{"verdict":"PASS"}')
    # The in-flight traversal keeps its verified original bytes. A separate
    # operation cannot inherit that cache or silently trust the changed file.
    assert snapshot.get_json(identity) == {"verdict": "REJECT"}
    with pytest.raises(IntegrityError):
        VerificationSnapshot(store).get_json(identity)


def test_json_mutation_cannot_change_later_checks(tmp_path):
    store = ContentAddressedStore(tmp_path)
    identity = store.put_json({"gates": {"preserved": False}})
    snapshot = VerificationSnapshot(store)
    snapshot.get_json(identity)["gates"]["preserved"] = True
    assert snapshot.get_json(identity)["gates"]["preserved"] is False


def test_budget_exhaustion_preserves_integrity_checks(tmp_path):
    store = ContentAddressedStore(tmp_path)
    identity = store.put_bytes(b"larger than budget")
    snapshot = VerificationSnapshot(store, max_bytes=0)
    assert snapshot.get_bytes(identity) == b"larger than budget"
    store._path(identity).write_bytes(b"corrupt")
    with pytest.raises(IntegrityError):
        snapshot.get_bytes(identity)
