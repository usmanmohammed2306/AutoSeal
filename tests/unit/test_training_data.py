import pytest

from autoseal.storage import ContentAddressedStore
from autoseal.training_data import DatasetRevision, DatasetItem, Split, store_dataset, load_dataset


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def test_dataset_revision_rejects_split_and_source_leakage(tmp_path) -> None:
    base = [
        DatasetItem(task_id="task-a", content_id=_digest("a"), source_identity=_digest("c"), split=Split.TRAIN),
        DatasetItem(task_id="task-b", content_id=_digest("b"), source_identity=_digest("d"), split=Split.AUDIT),
    ]
    assert len(DatasetRevision(items=base).items) == 2
    with pytest.raises(ValueError, match="task appears"):
        DatasetRevision(items=[base[0], base[1].model_copy(update={"task_id": "task-a"})])
    with pytest.raises(ValueError, match="source trajectory"):
        DatasetRevision(items=[base[0], base[1].model_copy(update={"source_identity": _digest("c")})])
    with pytest.raises(ValueError, match="train split"):
        DatasetRevision(items=[base[1]])


def test_dataset_store_requires_real_content_and_detects_corruption(tmp_path) -> None:
    store = ContentAddressedStore(tmp_path)
    content_id = store.put_json({"prompt": "task", "completion": "solution"})
    dataset = DatasetRevision(items=[DatasetItem(
        task_id="task-a", content_id=content_id, source_identity=_digest("c"), split=Split.TRAIN,
    )])
    identity = store_dataset(store, dataset)
    assert load_dataset(store, identity) == dataset
    store._path(content_id).write_bytes(b"bad")
    with pytest.raises(ValueError, match="digest mismatch"):
        load_dataset(store, identity)
