"""Trusted multi-task GRPO with admitted Mac Docker rewards and resume guards.

No candidate code executes on Sol. The configuration contains training tasks
only; hidden audit inputs are committed elsewhere and never loaded here.
"""

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import signal
import time

from artifact_reward_client import ArtifactRewardClient
from training_runtime import canonical, check_sources, files_manifest, identity, staged_model, verify_resume, write_new


def check_resume_condition(proof, *, manifest_id, arm, seed):
    if any(proof.get(key) != value for key, value in {'manifest_id': manifest_id, 'arm': arm, 'seed': seed}.items()):
        raise ValueError('GRPO checkpoint belongs to another reward arm, seed or study manifest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--warm-adapter', type=Path, required=True)
    parser.add_argument('--exchange', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--arm', choices=['vulnerable', 'sealed'], required=True)
    parser.add_argument('--seed', type=int, required=True)
    parser.add_argument('--resume-from', type=Path)
    args = parser.parse_args()
    envelope = json.loads(args.config.read_bytes())
    config, manifest = envelope['training_configuration'], envelope['manifest']
    config_id, manifest_id = identity(canonical(config)), identity(canonical(manifest))
    if (config_id != envelope['configuration_id'] or manifest_id != envelope['manifest_id']
            or manifest['training_configuration_id'] != config_id
            or config['kind'] != 'artifact_grpo_training' or config['schema_version'] != 1
            or manifest['kind'] != 'artifact_study_manifest' or manifest['schema_version'] != 1
            or manifest['scope'] not in {'REWARD_PREFLIGHT', 'FROZEN_PAIRED_STUDY'}
            or args.seed not in manifest['seeds'] or config['max_steps'] != manifest['max_batches_per_seed']
            or config['starting_checkpoint'] != manifest['starting_checkpoint']
            or not 1 <= config['max_steps'] <= 32 or manifest['batch_size'] != 4
            or not 1 <= config['max_completion_tokens'] <= 384
            or not 128 <= config['max_prompt_tokens'] <= 2048 or len(config['tasks']) != 8
            or not 0 < config['learning_rate'] <= .001 or not 0 < config['temperature'] <= 2):
        raise ValueError('GRPO configuration differs from its frozen bounded manifest')
    if manifest['scope'] == 'FROZEN_PAIRED_STUDY' and len(set(manifest['seeds'])) < 3:
        raise ValueError('the final study requires three seeds per arm')
    check_sources(Path(__file__).resolve().parent, config['sources'])
    resume = verify_resume(args.resume_from, configuration_id=config_id,
        dataset_id=manifest['dataset_revision'], base_identity=manifest['starting_checkpoint']) if args.resume_from else None
    if resume:
        check_resume_condition(resume, manifest_id=manifest_id, arm=args.arm, seed=args.seed)
    receipts = json.loads((args.resume_from / 'autoseal-reward-receipts.json').read_bytes()) if resume else []
    if resume and len(receipts) != resume['global_step']:
        raise ValueError('resumed optimizer step and reward history differ')
    args.output.mkdir(parents=True, exist_ok=False)
    write_new(args.output / 'configuration.json', envelope)
    report = {'kind': 'artifact_grpo_training_report', 'schema_version': 1, 'scope': manifest['scope'],
        'status': 'FAILED', 'configuration_id': config_id, 'manifest_id': manifest_id,
        'arm': args.arm, 'seed': args.seed, 'starting_checkpoint': manifest['starting_checkpoint'],
        'dataset_revision': manifest['dataset_revision'], 'hidden_commitment': manifest['hidden_commitment'],
        'slurm_job_id': os.environ.get('SLURM_JOB_ID'), 'global_step': 0,
        'resumed_from_step': resume['global_step'] if resume else None, 'error': None,
        'limitations': ['Authored finite output tasks, not external benchmark or algorithm generalization.',
            'Independent audit inputs and outcomes never enter this reward callback.',
            'Training completion does not establish downstream efficacy; final hidden evaluation is separate.']}
    started = time.monotonic()
    client = ArtifactRewardClient(args.exchange, manifest, manifest_id, config['tasks'],
        arm=args.arm, seed=args.seed, receipts=receipts)
    def progress(stage, details=None):
        print(json.dumps({'stage': stage, 'seconds': time.monotonic() - started, **(details or {})}), flush=True)
    def terminated(_signal, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminated)
    try:
        import torch
        from datasets import Dataset
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainerCallback, set_seed
        from trl import GRPOConfig, GRPOTrainer
        if version('trl') != '0.18.2' or not torch.cuda.is_available() or not os.environ.get('SLURM_JOB_ID'):
            raise RuntimeError('the scheduled tested TRL/CUDA environment is required')
        set_seed(args.seed); torch.set_num_threads(4)
        report['packages'] = {name: version(name) for name in ('torch', 'transformers', 'trl', 'peft', 'datasets')}
        report['gpu'] = torch.cuda.get_device_name(0)
        progress('CUDA_READY', {'gpu': report['gpu']})
        with staged_model(args.model, config['model_files'], progress=progress) as base, staged_model(
                args.warm_adapter, config['warm_adapter_files'], max_bytes=128 * 1024**2,
                progress=lambda stage, details=None: progress(stage, {'component': 'shared_warm_adapter', **(details or {})})) as warm:
            tokenizer = AutoTokenizer.from_pretrained(base, local_files_only=True, trust_remote_code=False)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            model = AutoModelForCausalLM.from_pretrained(base, local_files_only=True, trust_remote_code=False,
                use_safetensors=True, torch_dtype=torch.bfloat16, attn_implementation='sdpa')
            model = PeftModel.from_pretrained(model, warm, is_trainable=True, local_files_only=True)
            model.config.use_cache = False
            model.enable_input_require_grads()
            rows = []
            for task in config['tasks']:
                prompt = [{'role': 'system', 'content': task['system']}, {'role': 'user', 'content': task['prompt']}]
                text = tokenizer.apply_chat_template(prompt, tokenize=False, add_generation_prompt=True)
                if len(tokenizer(text)['input_ids']) > config['max_prompt_tokens']:
                    raise ValueError('refuse silently truncated study prompts')
                if identity(task['prompt'].encode()) != task['prompt_id']:
                    raise ValueError('train prompt differs from the committed membership')
                rows.append({'prompt': prompt, 'task_id': task['task_id']})
            class Checkpoint(TrainerCallback):
                def on_save(self, arguments, state, control, **kwargs):
                    directory = Path(arguments.output_dir) / f'checkpoint-{state.global_step}'
                    if len(client.receipts) != state.global_step:
                        raise ValueError('optimizer save is not aligned with completed reward groups')
                    write_new(directory / 'autoseal-reward-receipts.json', client.receipts)
                    proof = {'configuration_id': config_id, 'dataset_id': manifest['dataset_revision'],
                        'base_identity': manifest['starting_checkpoint'], 'global_step': state.global_step,
                        'manifest_id': manifest_id, 'arm': args.arm, 'seed': args.seed,
                        'checkpoint_files': files_manifest(directory)}
                    write_new(directory / 'autoseal-resume.json', proof)
                    return control
            def mac_reward(completions, **kwargs):
                return client(completions, **kwargs)
            trainer = GRPOTrainer(model=model, processing_class=tokenizer, train_dataset=Dataset.from_list(rows),
                reward_funcs=mac_reward, callbacks=[Checkpoint()],
                args=GRPOConfig(output_dir=str(args.output / 'trainer'), max_steps=config['max_steps'],
                    per_device_train_batch_size=4, gradient_accumulation_steps=1, num_generations=4,
                    generation_batch_size=4, max_prompt_length=config['max_prompt_tokens'],
                    max_completion_length=config['max_completion_tokens'], learning_rate=config['learning_rate'],
                    temperature=config['temperature'], beta=0., bf16=True, gradient_checkpointing=True,
                    use_vllm=False, save_strategy='steps', save_steps=1, save_total_limit=2,
                    logging_steps=1, report_to='none', seed=args.seed, data_seed=args.seed, optim='adamw_torch'))
            trainer.model.peft_config['default'].base_model_name_or_path = config['model_source']['repository']
            trainer.model.peft_config['default'].revision = config['model_source']['revision']
            progress('TRAINING', {'arm': args.arm, 'seed': args.seed})
            trained = trainer.train(resume_from_checkpoint=str(args.resume_from) if resume else None)
            step = trainer.state.global_step
            if step != config['max_steps'] or len(client.receipts) != step:
                raise ValueError('GRPO did not complete its frozen optimizer/reward budget')
            trainer.save_model(str(args.output / 'adapter')); tokenizer.save_pretrained(args.output / 'adapter')
            checkpoint = args.output / 'trainer' / f'checkpoint-{step}'
            proof = verify_resume(checkpoint, configuration_id=config_id,
                dataset_id=manifest['dataset_revision'], base_identity=manifest['starting_checkpoint'])
            report.update(status='COMPLETE', global_step=step, training_loss=trained.training_loss,
                log_history=trainer.state.log_history, peak_gpu_bytes=torch.cuda.max_memory_allocated(),
                trainable_parameters=sum(p.numel() for p in trainer.model.parameters() if p.requires_grad),
                adapter_files=files_manifest(args.output / 'adapter'), checkpoint_manifest=proof,
                checkpoint_relative_path=f'trainer/checkpoint-{step}')
    except BaseException as exc:
        report['status'] = 'INTERRUPTED' if isinstance(exc, (SystemExit, KeyboardInterrupt)) else 'FAILED'
        report['error'] = f'{type(exc).__name__}: {exc}'
        if 'trainer' in locals():
            report['global_step'] = trainer.state.global_step
            report['log_history'] = trainer.state.log_history
    report.update(batch_receipts=client.receipts, seconds=time.monotonic() - started,
        nonconstant_reward_groups=sum(row['nonconstant'] for row in client.receipts))
    write_new(args.output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'global_step': report['global_step'],
        'reward_groups': len(client.receipts), 'error': report['error']}), flush=True)
    return 0 if report['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
