import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location('training_runtime', Path(__file__).resolve().parents[2] / 'scripts/sol/training_runtime.py')
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


def checkpoint(root):
    root.mkdir()
    (root / 'trainer_state.json').write_text(json.dumps({'global_step': 8}))
    (root / 'optimizer.pt').write_bytes(b'trusted-unit-test-placeholder-not-a-real-optimizer')
    proof = {'configuration_id': 'config-a', 'dataset_id': 'data-a', 'base_identity': 'base-a',
             'global_step': 8, 'checkpoint_files': RUNTIME.files_manifest(root)}
    RUNTIME.write_new(root / 'autoseal-resume.json', proof)


def test_resume_refuses_wrong_dataset_before_loading_optimizer(tmp_path):
    root = tmp_path / 'checkpoint'; checkpoint(root)
    assert RUNTIME.verify_resume(root, configuration_id='config-a', dataset_id='data-a', base_identity='base-a')['global_step'] == 8
    with pytest.raises(ValueError, match='another configuration, dataset or base'):
        RUNTIME.verify_resume(root, configuration_id='config-a', dataset_id='data-b', base_identity='base-a')


def test_resume_refuses_modified_optimizer_before_deserialization(tmp_path):
    root = tmp_path / 'checkpoint'; checkpoint(root)
    (root / 'optimizer.pt').write_bytes(b'changed-bytes')
    with pytest.raises(ValueError, match='bytes changed'):
        RUNTIME.verify_resume(root, configuration_id='config-a', dataset_id='data-a', base_identity='base-a')


def test_completion_only_loss_requires_the_actual_preprocessed_mask():
    assert RUNTIME.loss_token_counts([{'input_ids': [1, 2, 3, 4], 'completion_mask': [0, 0, 1, 1]}], completion_only=True) == [2]
    for row in [{'input_ids': [1, 2]}, {'input_ids': [1, 2], 'completion_mask': [0, 0]},
                {'input_ids': [1, 2], 'completion_mask': [1, 1]}, {'input_ids': [1, 2], 'completion_mask': [1, 0]}]:
        with pytest.raises(ValueError, match='loss mask'):
            RUNTIME.loss_token_counts([row], completion_only=True)
