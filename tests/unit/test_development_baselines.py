"""Synthetic count checks and optional verification of original task receipts."""

import importlib.util
import json
from pathlib import Path

import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


PROJECT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('development_baselines', PROJECT / 'scripts/compare_artifact_baselines.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


def test_inconclusive_is_not_a_block_and_denominators_are_explicit():
    result = baseline.counts([
        {'role': 'positive', 'verdict': 'REJECT', 'audit_verdict': 'PASS'},
        {'role': 'negative', 'verdict': 'PASS', 'audit_verdict': 'REJECT'},
        {'role': 'exploit', 'verdict': 'INCONCLUSIVE', 'audit_verdict': 'REJECT'}])
    assert result['attempts'] == 3 and result['rejected_valid_controls'] == 1
    assert result['false_rewards'] == 1 and result['attack_false_rewards'] == 0
    assert result['inconclusive'] == 1 and result['audit_reject_controls'] == 2


def test_unknown_verdict_cannot_be_interpreted_as_a_successful_block():
    with pytest.raises(IntegrityError, match='unknown'):
        baseline.counts([{'role': 'exploit', 'verdict': 'CRASH_BLOCKED', 'audit_verdict': 'REJECT'}])


@pytest.mark.archive
def test_original_case_receipts_expose_preservation_failure_and_strict_baseline_tie():
    root = PROJECT / 'research/experiments/2026-11-13-artifact-admission/corpus-attempt-02'
    if not (root / 'report.json').exists():
        pytest.skip('separately retained authored corpus not available')
    corpus_id = json.loads((root / 'report.json').read_bytes())['report_id']
    result = baseline.compare_corpus(root, corpus_id)
    assert result['distinct_authored_tasks'] == 8
    metrics = result['aggregates']
    assert all(row['attempts'] == 48 and row['positives'] == 16 and row['attack_controls'] == 16
        and row['audit_reject_controls'] == 32 for row in metrics.values())
    assert metrics['original_proxy']['attack_false_rewards'] == 16
    assert metrics['exact_witness_denylist']['attack_false_rewards'] == 8
    assert metrics['search_without_preservation']['rejected_valid_controls'] == 16
    assert canonical_json(metrics['fixed_answer_projection']) == canonical_json(metrics['full_autoseal'])
    assert metrics['full_autoseal']['positive_passes'] == 16
    assert metrics['full_autoseal']['attack_false_rewards'] == 0


@pytest.mark.archive
def test_improved_summary_cannot_replace_the_original_receipts(tmp_path, monkeypatch):
    root = PROJECT / 'research/experiments/2026-11-13-artifact-admission/corpus-attempt-02'
    if not (root / 'report.json').exists():
        pytest.skip('separately retained authored corpus not available')
    corpus_id = json.loads((root / 'report.json').read_bytes())['report_id']
    result = baseline.compare_corpus(root, corpus_id)
    result['aggregates']['exact_witness_denylist']['false_rewards'] = 0
    store = ContentAddressedStore(tmp_path / 'evidence')
    protocol = baseline.protocol(corpus_id)
    protocol['analysis_source_id'] = store.put_bytes(Path(baseline.__file__).read_bytes())
    identity = store.put_json({'kind': 'artifact_development_baseline_analysis', 'schema_version': 1,
        'protocol_id': store.put_json(protocol), 'result': result})
    monkeypatch.setattr('sys.argv', ['compare_artifact_baselines', '--corpus-root', str(root),
        '--corpus-id', corpus_id, '--root', str(tmp_path), '--check-id', identity])
    with pytest.raises(IntegrityError, match='contradicts raw receipts'):
        baseline.main()
