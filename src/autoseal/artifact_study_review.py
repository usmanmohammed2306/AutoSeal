"""Read-only product view of a verified post-checkpoint model comparison."""

from pathlib import Path

from autoseal.artifact_audit import verify_hidden_evaluation
from autoseal.artifact_study_archive import require, verify_study_archive
from autoseal.storage import ContentAddressedStore, VerificationSnapshot
from autoseal.training_data import DatasetRevision


def require_analysis_source(store, protocol, evaluation):
    ref = protocol['implementation_id']
    require(evaluation['analysis_implementation_id'] == ref
        and store.get_bytes(ref) == Path(__file__).with_name('artifact_audit.py').read_bytes(),
        'hidden analysis differs from the implementation frozen before training')


def study_review(root, evaluation_id):
    store = VerificationSnapshot(ContentAddressedStore(Path(root) / 'evidence'))
    evaluation = store.get_json(evaluation_id)
    require(evaluation['kind'] == 'artifact_study_hidden_evaluation' and evaluation['schema_version'] == 1,
        'unsupported saved model comparison')
    generation = store.get_json(evaluation['generation_archive_id'])
    config = store.get_json(generation['configuration_id'])
    archive = store.get_json(config['training_archive_id'])
    manifest = store.get_json(archive['manifest_id'])
    training_config = store.get_json(manifest['training_configuration_id'])
    protocol = training_config['analysis_protocol']
    require_analysis_source(store, protocol, evaluation)
    summary = verify_hidden_evaluation(store, evaluation_id)
    training = verify_study_archive(store, config['training_archive_id'])
    starting = store.get_json(manifest['starting_checkpoint'])
    sft = store.get_json(starting['parent_sft_archive_id'])
    sft_config = store.get_json(sft['configuration_id'])
    sft_data = DatasetRevision.model_validate(store.get_json(sft_config['dataset_revision']))
    study_data = DatasetRevision.model_validate(store.get_json(manifest['dataset_revision']))
    def inputs(items):
        return {(store.get_json(item.source_identity)['operation'],
            tuple(store.get_json(item.source_identity)['values'])) for item in items}
    overlap = inputs(sft_data.items) & inputs(study_data.items)
    require(not overlap, 'study inputs overlap the known SFT calibration population')
    paired = []
    for seed in manifest['seeds']:
        identities = [archive['conditions'][f'{arm}-{seed}']['adapter_files']['adapter_model.safetensors']
            for arm in ('vulnerable', 'sealed')]
        paired.append({'seed': seed, 'same_adapter_bytes': identities[0] == identities[1]})
    return {'source': 'verified_saved_model_study', 'scope': 'Frozen paired study on authored finite output tasks',
        'evaluation_id': evaluation_id, 'generation_archive_id': evaluation['generation_archive_id'],
        'training_archive_id': config['training_archive_id'], 'manifest_id': config['manifest_id'],
        'dataset_revision': manifest['dataset_revision'], 'hidden_commitment': manifest['hidden_commitment'],
        'starting_checkpoint': manifest['starting_checkpoint'], 'model_source': training_config['model_source'],
        'seeds': manifest['seeds'], 'steps_per_condition': manifest['max_batches_per_seed'],
        'training_conditions': training['conditions'], 'paired_adapter_identity': paired,
        'analysis_protocol': protocol, 'summary': summary,
        'input_overlap_check': {'sft_known_instances': len(sft_data.items), 'study_instances': len(study_data.items),
            'exact_operation_input_overlaps': len(overlap), 'scope': 'Exact operation and ordered input equality, not semantic-equivalence or benchmark-contamination proof.'},
        'verification': 'Raw generation, model/checkpoint, admitted reward, audit and scheduler receipts rechecked. No new execution or training.'}
