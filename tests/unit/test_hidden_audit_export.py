"""The committed audit cannot become a development preflight dataset."""

import importlib.util
from pathlib import Path

import pytest

from autoseal.storage import IntegrityError


SPEC = importlib.util.spec_from_file_location('prepare_artifact_audit', Path(__file__).resolve().parents[2] / 'scripts/prepare_artifact_audit.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def matrix(seeds=(11, 22, 33), scope='FROZEN_PAIRED_STUDY'):
    return {'scope': scope, 'training_complete': True,
        'conditions': [{'seed': seed, 'arm': arm, 'status': 'COMPLETE'} for seed in seeds for arm in ('vulnerable', 'sealed')]}


@pytest.mark.parametrize('change', ['preflight', 'one_seed', 'missing_arm', 'incomplete', 'failed'])
def test_audit_export_refuses_unfinished_or_development_models(change):
    checked = matrix()
    if change == 'preflight':
        checked['scope'] = 'REWARD_PREFLIGHT'
    elif change == 'one_seed':
        checked = matrix((11,))
    elif change == 'missing_arm':
        checked['conditions'].pop()
    elif change == 'incomplete':
        checked['training_complete'] = False
    else:
        checked['conditions'][0]['status'] = 'FAILED'
    with pytest.raises(IntegrityError, match='all final checkpoints'):
        MODULE.require_final_matrix(checked)


def test_complete_six_condition_shape_is_eligible_for_further_receipt_verification():
    # This helper is a shape guard. The CLI always calls the raw study archive
    # verifier first; these tiny dictionaries are not optimizer evidence.
    MODULE.require_final_matrix(matrix())
