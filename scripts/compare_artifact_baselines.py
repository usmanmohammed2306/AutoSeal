"""Retrospective matched-development baselines from actual retained receipts.

No candidate execution, model call, repair promotion or blind-holdout claim.
The common population is the six development controls in each authored case.
Search-excluded controls cannot silently become extra baseline observations.
"""

import argparse
from collections import Counter
import json
from pathlib import Path

from autoseal.artifact_cases import load_case, registered_tasks
from autoseal.artifact_pipeline import resolve_artifact, verify_artifact_validation
from autoseal.artifact_runtime import load_files
from autoseal.repair import RepairOperator
from autoseal.repair_engine import TypedRepairPlan
from autoseal.storage import ContentAddressedStore, IntegrityError, VerificationSnapshot, canonical_json


METHODS = ('original_proxy', 'exact_witness_denylist', 'fixed_answer_projection',
    'search_without_preservation', 'search_with_one_positive', 'full_autoseal')


def require(condition, message):
    if not condition:
        raise IntegrityError(message)


def protocol(corpus_id):
    return {'kind': 'artifact_development_baseline_protocol', 'schema_version': 1,
        'corpus_id': corpus_id, 'analysis_source_id': None,
        'timing': 'Retrospective: the author has already seen these development and validation outcomes.',
        'population': 'Exactly six original development controls per authored case; two positives, two ordinary negatives, primary exploit and development variant.',
        'selectors': {
            'original_proxy': 'Original proxy, without a repair.',
            'exact_witness_denylist': 'Reject a candidate containing every minimized non-answer witness file at its original path with exact bytes; otherwise retain the original proxy verdict. Scope the rule to this case.',
            'fixed_answer_projection': 'Fixed answer.json allowlist plus trusted verdict ownership and result binding, without data-directed plan selection.',
            'search_without_preservation': 'First frozen search plan that rejects the primary exploit. Positive and ordinary-negative preservation do not select it.',
            'search_with_one_positive': 'First frozen plan preserving only the first positive and rejecting the primary exploit.',
            'full_autoseal': 'The admitted development-only winner already bound by the original validation.'},
        'search_order': 'Original frozen three-plan order. No held-out outcome selects a plan.',
        'denominators': 'Tasks are separate rows; artifact counts are selected controls, not independent benchmark tasks.',
        'limitations': ['Authored fixed-output tasks. Optional program files are not the task interface.',
            'This offline development comparison cannot satisfy the frozen final baseline/ablation or external-corpus gate.']}


def counts(rows):
    require(all(row['role'] in {'positive', 'negative', 'exploit', 'development'}
        and row['verdict'] in {'PASS', 'REJECT', 'INCONCLUSIVE'}
        and row['audit_verdict'] in {'PASS', 'REJECT', 'INCONCLUSIVE'} for row in rows),
        'baseline summary contains an unknown role or verdict')
    roles = Counter(row['role'] for row in rows)
    decisive = {'PASS', 'REJECT'}
    return {'attempts': len(rows), 'positives': roles['positive'], 'ordinary_negatives': roles['negative'],
        'attack_controls': roles['exploit'] + roles['development'],
        'audit_pass_controls': sum(row['audit_verdict'] == 'PASS' for row in rows),
        'audit_reject_controls': sum(row['audit_verdict'] == 'REJECT' for row in rows),
        'positive_passes': sum(row['role'] == 'positive' and row['verdict'] == 'PASS' for row in rows),
        'ordinary_negative_rejections': sum(row['role'] == 'negative' and row['verdict'] == 'REJECT' for row in rows),
        'false_rewards': sum((row['verdict'], row['audit_verdict']) == ('PASS', 'REJECT') for row in rows),
        'attack_false_rewards': sum(row['role'] in {'exploit', 'development'}
            and (row['verdict'], row['audit_verdict']) == ('PASS', 'REJECT') for row in rows),
        'rejected_valid_controls': sum(row['audit_verdict'] == 'PASS' and row['verdict'] == 'REJECT' for row in rows),
        'inconclusive': sum(row['verdict'] not in decisive or row['audit_verdict'] not in decisive for row in rows)}


def compare_case(root, validation_id):
    store = VerificationSnapshot(ContentAddressedStore(root / 'evidence'))
    report = verify_artifact_validation(store, validation_id)
    require(all(report['gates'].values()), 'baseline input is not a fully checked validation')
    case, task = load_case(store, report['case_id'])
    expected = registered_tasks()
    require(task.task_id in expected and task == expected[task.task_id], 'baseline task differs from the registered fixed input')
    controls = case['controls'][:6]
    require([row['role'] for row in controls] == ['positive', 'positive', 'negative', 'negative', 'exploit', 'development'],
        'matched development population changed')
    def outcome(ref, control, revision, channel):
        return resolve_artifact(store, ref, case_id=report['case_id'], candidate_id=control['candidate_id'],
            revision_id=revision, channel=channel)['verdict']
    original = [outcome(row['proxy'], control, report['parent_revision'], 'proxy')
        for row, control in zip(report['baseline'][:6], controls)]
    audit = [outcome(row['audit'], control, report['parent_revision'], 'audit')
        for row, control in zip(report['baseline'][:6], controls)]
    search = store.get_json(report['search_id'])
    plans = []
    for row in search['search']:
        plan = TypedRepairPlan.model_validate(store.get_json(row['plan_id']))
        verdicts = [outcome(ref, control, row['child_revision'], 'sealed')
            for ref, control in zip(row['development'], controls)]
        plans.append((row, plan, verdicts))
    strict = [row for row, plan, _ in plans if len(plan.steps) == 3
        and plan.steps[0].operator is RepairOperator.ARTIFACT_PROJECTION
        and plan.steps[0].allowed_files == ('answer.json',)]
    require(len(strict) == 1, 'no unique matching fixed strict-hardening receipt')
    def select(predicate):
        options = [row for row, _plan, verdicts in plans if predicate(row, verdicts)]
        require(bool(options), 'matched baseline has no eligible retained search plan')
        return options[0]['plan_id']
    chosen = {'fixed_answer_projection': strict[0]['plan_id'],
        'search_without_preservation': select(lambda row, verdicts: verdicts[4] == 'REJECT'),
        'search_with_one_positive': select(lambda row, verdicts: verdicts[0] == 'PASS' and verdicts[4] == 'REJECT'),
        'full_autoseal': report['plan_id']}
    plan_verdicts = {row['plan_id']: verdicts for row, _, verdicts in plans}
    witness = load_files(store, report['witness_id'])
    graph = store.get_json(report['graph_id'])
    denylist = {name: witness[name] for name in graph['causal_files']}
    require(bool(denylist) and 'answer.json' not in denylist, 'denylist requires the isolated non-answer witness')
    def denied(control):
        files = load_files(store, control['candidate_id'])
        return all(files.get(name) == raw for name, raw in denylist.items())
    selected = {'original_proxy': original,
        'exact_witness_denylist': ['REJECT' if denied(control) else value
            for control, value in zip(controls, original)],
        **{method: plan_verdicts[plan_id] for method, plan_id in chosen.items()}}
    rows = {method: [{'control': control['name'], 'role': control['role'], 'candidate_id': control['candidate_id'],
        'verdict': verdict, 'audit_verdict': audit_verdict}
        for control, verdict, audit_verdict in zip(controls, selected[method], audit)] for method in METHODS}
    return {'task_id': task.task_id, 'validation_id': validation_id, 'case_id': report['case_id'],
        'selected_plans': chosen, 'denylist_witness_id': report['witness_id'], 'denylist_paths': sorted(denylist),
        'rows': rows, 'counts': {method: counts(value) for method, value in rows.items()}}


def compare_corpus(root, corpus_id):
    store = ContentAddressedStore(root / 'evidence')
    report = store.get_json(corpus_id)
    require(report['kind'] == 'authored_artifact_corpus_validation' and report['schema_version'] == 1
        and report['status'] == 'PASSED', 'baseline corpus lacks a successful original validation')
    tasks = registered_tasks()
    rows = report['cases']
    require(len(rows) == len(tasks) and {row['case'] for row in rows} == set(tasks), 'baseline corpus membership changed')
    cases = [compare_case(root / row['case'], row['validation_id']) for row in rows]
    require({row['task_id'] for row in cases} == set(tasks), 'baseline receipt task identity changed')
    aggregates = {method: counts([row for case in cases for row in case['rows'][method]]) for method in METHODS}
    return {'cases': cases, 'distinct_authored_tasks': len(cases), 'aggregates': aggregates,
        'unavailable_comparators': [
            {'method': 'released_separation_baseline', 'status': 'UNAVAILABLE',
                'reason': 'No matched replay of a released separation implementation is supplied by this archive. No favorable approximation is substituted.'},
            {'method': 'released_hacker_fixer_patch', 'status': 'UNAVAILABLE',
                'reason': 'These authored cases have no matched released patch receipt. Native compatibility still needs its own checked comparison.'}],
        'scope': 'Retrospective matched development receipts only; not fresh execution, blind re-attacks, external benchmarks or final release acceptance.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, required=True)
    parser.add_argument('--corpus-id', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--check-id', help='Recompute an existing saved analysis instead of writing another.')
    args = parser.parse_args()
    if args.check_id:
        store = ContentAddressedStore(args.root / 'evidence')
        record = store.get_json(args.check_id)
        require(record['kind'] == 'artifact_development_baseline_analysis' and record['schema_version'] == 1,
            'unsupported baseline analysis')
        expected = protocol(args.corpus_id)
        expected['analysis_source_id'] = store.put_bytes(Path(__file__).read_bytes())
        require(record['protocol_id'] == store.put_json(expected), 'baseline analysis source/protocol changed')
        checked = compare_corpus(args.corpus_root, args.corpus_id)
        require(canonical_json(record['result']) == canonical_json(checked), 'saved baseline table contradicts raw receipts')
    else:
        args.root.mkdir(parents=True, exist_ok=False)
        store = ContentAddressedStore(args.root / 'evidence')
        frozen = protocol(args.corpus_id)
        frozen['analysis_source_id'] = store.put_bytes(Path(__file__).read_bytes())
        protocol_id = store.put_json(frozen)
        (args.root / 'protocol.json').write_bytes(canonical_json({'protocol_id': protocol_id, **frozen}))
        checked = compare_corpus(args.corpus_root, args.corpus_id)
        identity = store.put_json({'kind': 'artifact_development_baseline_analysis', 'schema_version': 1,
            'protocol_id': protocol_id, 'result': checked})
        (args.root / 'analysis.json').write_bytes(canonical_json({'analysis_id': identity, **checked}))
    print(json.dumps({'authored_tasks': checked['distinct_authored_tasks'], 'aggregates': checked['aggregates']}, indent=2))


if __name__ == '__main__':
    main()
