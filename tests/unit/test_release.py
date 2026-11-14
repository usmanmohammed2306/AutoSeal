"""Incomplete, forged or out-of-root evidence cannot become V1 completion."""

import json

import pytest
from pydantic import ValidationError

from autoseal.cli import main
from autoseal.release import EvidenceReference, ReleaseCandidate, inspect_release


def test_empty_manifest_names_frozen_obligations_and_fails_cli(tmp_path, capsys):
    manifest = tmp_path / 'candidate.json'
    manifest.write_text(json.dumps({'kind': 'autoseal_release_candidate', 'schema_version': 1}))
    assert main(['release-check', '--root', str(tmp_path), '--manifest', str(manifest)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['release_eligible'] is False
    required = {'matched_training_and_hidden_audits', 'external_corpus_and_native_repairs',
                'aws_operated_delivery', 'clean_room_reproduction'}
    assert required <= {g['id'] for g in report['gates'] if g['status'] == 'MISSING'}


@pytest.mark.parametrize('extra', [{'release_eligible': True}, {'skip_training': True}, {'gates': {'training': 'PASS'}}])
def test_no_boolean_or_waiver_can_bypass_release(extra):
    with pytest.raises(ValidationError):
        ReleaseCandidate.model_validate(extra)


@pytest.mark.parametrize('directory', ['../outside', '/tmp/elsewhere', './archive', 'archive/../other'])
def test_release_does_not_follow_untrusted_archive_paths(tmp_path, directory):
    candidate = ReleaseCandidate(native_shell=EvidenceReference(directory=directory, identity='sha256:' + 'a' * 64))
    report = inspect_release(tmp_path, candidate)
    assert next(g for g in report['gates'] if g['id'] == 'external_shell_reproduction')['status'] == 'FAILED'
    assert report['release_eligible'] is False


def test_symlinked_evidence_cannot_escape_root(tmp_path):
    (tmp_path / 'elsewhere').symlink_to('/private/tmp', target_is_directory=True)
    candidate = ReleaseCandidate(native_swebench_directory='elsewhere')
    report = inspect_release(tmp_path, candidate)
    assert next(g for g in report['gates'] if g['id'] == 'external_swebench_reproduction')['status'] == 'FAILED'
