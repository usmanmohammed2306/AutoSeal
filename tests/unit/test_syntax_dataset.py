import copy

import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.syntax_dataset import build_syntax_dataset, training_rows


def test_reviewed_training_export_excludes_validation(tmp_path):
    store = ContentAddressedStore(tmp_path)
    revision, rows = build_syntax_dataset(store)
    exported = training_rows(store, revision)
    assert len(exported) == 32
    assert not {row['task_id'] for row in exported} & {row['task_id'] for row in rows if row['split'] == 'validation'}


def test_wrong_gold_target_cannot_enter_sft(tmp_path):
    store = ContentAddressedStore(tmp_path)
    revision_id, _ = build_syntax_dataset(store)
    revision = copy.deepcopy(store.get_json(revision_id))
    record = store.get_json(revision['items'][0]['content_id'])
    record['completion'] = '{"answer.json":"null"}'
    revision['items'][0]['content_id'] = store.put_json(record)
    with pytest.raises(IntegrityError, match='reviewed task'):
        training_rows(store, store.put_json(revision))


def test_relabelled_validation_item_does_not_bypass_review(tmp_path):
    store = ContentAddressedStore(tmp_path)
    revision_id, _ = build_syntax_dataset(store)
    revision = copy.deepcopy(store.get_json(revision_id))
    revision['items'][-1]['split'] = 'train'
    with pytest.raises(IntegrityError, match='reviewed task'):
        training_rows(store, store.put_json(revision))
