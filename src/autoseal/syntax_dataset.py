"""Reviewed synthetic wire-format data, separate from benchmark and audit data."""

import json
import random

from autoseal.artifact_cases import ArtifactTask, audit_expected, proxy_expected
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json
from autoseal.training_data import DatasetItem, DatasetRevision, Split


SYSTEM = 'Return one JSON object mapping relative file names to UTF-8 file contents. No Markdown or explanations.'


def task_prompt(task):
    contract = {'sum': 'the sum as one JSON integer',
        'sort': 'the input integers sorted in increasing order as a JSON array, preserving duplicates',
        'unique': 'the distinct input integers sorted in increasing order as a JSON array',
        'histogram': 'a JSON object mapping each integer, as a string key, to its occurrence count'}[task.operation]
    return (f'Write answer.json containing {contract} for the input {list(task.values)}. '
        'Return one JSON object mapping the file name answer.json to its UTF-8 text contents. '
        'Do not create other files. Do not include Markdown or explanations.')


def build_syntax_dataset(store: ContentAddressedStore, *, seed=20261113):
    randomizer = random.Random(seed)
    rows, items, seen = [], [], set()
    for index in range(40):
        operation = ('sum', 'sort', 'unique', 'histogram')[index % 4]
        while True:
            values = tuple(randomizer.randint(-9, 9) for _ in range(3 + index % 6))
            if (operation, values) not in seen:
                seen.add((operation, values)); break
        task = ArtifactTask(task_id=f'syntax-{index:03d}', operation=operation, values=values, proxy_mode='skip_hook')
        reference = proxy_expected(task)
        if canonical_json(reference) != canonical_json(audit_expected(task)):
            raise IntegrityError('reference computations disagree; refuse training example')
        task_id = store.put_json(task.model_dump(mode='json'))
        files = {'answer.json': canonical_json(reference).decode()}
        example = {'task_id': task_id, 'system': SYSTEM, 'prompt': task_prompt(task),
                   'completion': canonical_json(files).decode()}
        split = Split.TRAIN if index < 32 else Split.VALIDATION
        review_id = store.put_json({'kind': 'syntax_example_review', 'decision': 'ACCEPT', 'task_id': task_id,
            'split': split.value,
            'reviewer': 'AI-assisted reference author', 'reference_agreement': True,
            'reason': 'Authored finite output contract; two reference calculations agree; exact JSON wire target checked.',
            'limitations': 'Reference review, not a human annotation campaign, preference pair or model-generated solution.'})
        content_id = store.put_json({**example, 'review_id': review_id})
        items.append(DatasetItem(task_id=task.task_id, source_identity=task_id, content_id=content_id, split=split))
        rows.append({**example, 'review_id': review_id, 'split': split.value, 'content_id': content_id})
    revision = DatasetRevision(items=items)
    revision_id = store.put_json(revision.model_dump(mode='json'))
    return revision_id, rows


def training_rows(store, revision_id):
    revision = DatasetRevision.model_validate(store.get_json(revision_id))
    rows = []
    for item in revision.items:
        if item.split is not Split.TRAIN:
            continue
        record = store.get_json(item.content_id)
        review = store.get_json(record['review_id'])
        task = ArtifactTask.model_validate(store.get_json(record['task_id']))
        expected = {'answer.json': canonical_json(audit_expected(task)).decode()}
        if (record['task_id'] != item.source_identity or task.task_id != item.task_id
                or review['decision'] != 'ACCEPT' or review['task_id'] != record['task_id']
                or review['split'] != 'train'
                or json.loads(record['completion']) != expected or record['prompt'] != task_prompt(task)
                or record['system'] != SYSTEM):
            raise IntegrityError('syntax example does not match its reviewed task and wire target')
        rows.append({key: record[key] for key in ['task_id', 'system', 'prompt', 'completion']})
    return rows
