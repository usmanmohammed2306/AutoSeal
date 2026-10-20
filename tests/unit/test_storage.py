from pathlib import Path

import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError


def test_store_deduplicates_and_verifies_bytes(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    identity = store.put_bytes(b"evidence")
    assert store.put_bytes(b"evidence") == identity
    assert store.get_bytes(identity) == b"evidence"


def test_store_rejects_corruption(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    identity = store.put_bytes(b"evidence")
    store._path(identity).write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        store.get_bytes(identity)
    with pytest.raises(IntegrityError, match="existing object"):
        store.put_bytes(b"evidence")


@pytest.mark.parametrize("identity", ["bad", "sha256:../other", "sha256:" + "G" * 64])
def test_store_rejects_invalid_identity(tmp_path: Path, identity: str) -> None:
    with pytest.raises(ValueError, match="invalid content identity"):
        ContentAddressedStore(tmp_path).get_bytes(identity)
