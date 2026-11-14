"""Study membership and reward isolation without allocating a GPU."""

import pytest

from autoseal.artifact_study import (StudyManifest, StudyRequest, StudyRewardWorker, TaskBinding,
    freeze_task_pack, load_training_tasks)
from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.training_data import DatasetRevision, Split


def configured(tmp_path):
    store = ContentAddressedStore(tmp_path / 'evidence')
    dataset, hidden = freeze_task_pack(store)
    rows = load_training_tasks(store, dataset)
    # Deliberately unissued validation/seal IDs: membership checks may run,
    # but no reward can be executed with this unit-only manifest.
    dummy = 'sha256:' + 'a' * 64
    manifest = StudyManifest(scope='REWARD_PREFLIGHT', dataset_revision=dataset, hidden_commitment=hidden,
        starting_checkpoint=dummy, training_configuration_id=dummy, seeds=(11,), max_batches_per_seed=2,
        tasks={row['task_id']: TaskBinding(case_id=dummy, validation_id=dummy, parent_revision=dummy,
            child_revision='sha256:' + 'b' * 64, prompt_id=row['prompt_id'], seal_id=dummy, activation_id=dummy) for row in rows})
    identity = store.put_json(manifest.model_dump(mode='json'))
    return store, dataset, hidden, rows, identity


def test_hidden_tasks_never_enter_reward_membership(tmp_path):
    store, dataset, hidden, rows, identity = configured(tmp_path)
    worker = StudyRewardWorker(tmp_path, identity)
    concealed = store.get_json(hidden)['records'][0]
    request = StudyRequest(bridge_manifest_id=identity, arm='vulnerable', seed=11, batch=0,
        task_id=concealed['task_id'], prompt_id=concealed['prompt_id'], completions=('{}',) * 4)
    with pytest.raises(IntegrityError, match='train membership'):
        worker.validate_request(request)
    assert concealed['task_id'] not in worker.tasks
    revision = DatasetRevision.model_validate(store.get_json(dataset))
    assert sum(item.split is Split.TRAIN for item in revision.items) == 8
    assert len(rows) == 8 and len(store.get_json(hidden)['records']) == 8


def test_prompt_v1_keeps_historical_dataset_and_hidden_identities(tmp_path):
    store = ContentAddressedStore(tmp_path / 'evidence')
    dataset, hidden = freeze_task_pack(store)
    assert dataset == 'sha256:703ea37c08be88c22fda83d251e3a5a5161e10ae215175667784929356cb2d32'
    assert hidden == 'sha256:18180e8222862c9c4f1ea653cc503bdde3829248a0909584b6795b9c98f89e6f'


def test_prompt_v2_changes_only_prompt_records_not_task_inputs(tmp_path):
    store = ContentAddressedStore(tmp_path / 'evidence')
    old, old_hidden = freeze_task_pack(store)
    new, new_hidden = freeze_task_pack(store, prompt_version=2)
    first, second = load_training_tasks(store, old), load_training_tasks(store, new)
    assert old != new and old_hidden != new_hidden
    assert [row['task'] for row in first] == [row['task'] for row in second]
    assert all(a['prompt_id'] != b['prompt_id'] for a, b in zip(first, second))
    assert 'Do not wrap it in a report about other operations.' in second[0]['prompt']
    assert 'Use a JSON number for sum, a sorted JSON array for sort/unique' not in second[0]['prompt']


def test_difficulty_change_creates_a_separate_reviewed_population(tmp_path):
    store = ContentAddressedStore(tmp_path / 'evidence')
    old, hidden = freeze_task_pack(store, prompt_version=2)
    shorter, concealed = freeze_task_pack(store, prompt_version=2, input_count=12)
    assert old != shorter and hidden != concealed
    assert {len(row['task']['values']) for row in load_training_tasks(store, shorter)} == {12}
    assert len({row['task_id'] for row in store.get_json(concealed)['records']}) == 8
    assert freeze_task_pack(store, prompt_version=2, input_count=12) == (shorter, concealed)


@pytest.mark.parametrize('count', [True, 3, 33, 12.5])
def test_unbounded_or_noninteger_difficulty_is_refused(tmp_path, count):
    with pytest.raises(ValueError, match='input count'):
        freeze_task_pack(ContentAddressedStore(tmp_path / 'evidence'), input_count=count)


@pytest.mark.parametrize('change', ['prompt', 'seed', 'budget', 'manifest'])
def test_reward_request_cannot_cross_frozen_condition(tmp_path, change):
    store, _, _, rows, identity = configured(tmp_path)
    worker = StudyRewardWorker(tmp_path, identity)
    request = StudyRequest(bridge_manifest_id=identity, arm='sealed', seed=11, batch=0,
        task_id=rows[0]['task_id'], prompt_id=rows[0]['prompt_id'], completions=('{}',) * 4)
    update = {'prompt': {'prompt_id': 'sha256:' + 'f' * 64}, 'seed': {'seed': 22},
        'budget': {'batch': 2}, 'manifest': {'bridge_manifest_id': 'sha256:' + 'f' * 64}}[change]
    with pytest.raises(IntegrityError):
        worker.validate_request(request.model_copy(update=update))


def test_one_seed_preflight_cannot_be_relabelled_as_final_study(tmp_path):
    store, _, _, _, identity = configured(tmp_path)
    manifest = store.get_json(identity)
    manifest['scope'] = 'FROZEN_PAIRED_STUDY'
    with pytest.raises(ValueError, match='three seeds'):
        StudyManifest.model_validate(manifest)


def test_manifest_cannot_replace_a_reviewed_train_prompt(tmp_path):
    store, _, _, rows, identity = configured(tmp_path)
    manifest = store.get_json(identity)
    manifest['tasks'][rows[0]['task_id']]['prompt_id'] = store.put_bytes(b'an unreviewed prompt')
    with pytest.raises(IntegrityError, match='reviewed train split'):
        StudyRewardWorker(tmp_path, store.put_json(manifest))


def test_reviewed_test_task_cannot_be_moved_into_train(tmp_path):
    store, dataset, _, _, _ = configured(tmp_path)
    revision = store.get_json(dataset)
    revision['items'][8]['split'] = 'train'
    with pytest.raises(IntegrityError, match='reviewed task and split'):
        load_training_tasks(store, store.put_json(revision))


def test_missing_admission_proof_cannot_produce_even_invalid_output_reward(tmp_path):
    store, _, _, rows, identity = configured(tmp_path)
    worker = StudyRewardWorker(tmp_path, identity)
    request = StudyRequest(bridge_manifest_id=identity, arm='sealed', seed=11, batch=0,
        task_id=rows[0]['task_id'], prompt_id=rows[0]['prompt_id'], completions=('not json',) * 4)
    with pytest.raises(FileNotFoundError):
        worker.evaluate(store.put_json(request.model_dump(mode='json')))
