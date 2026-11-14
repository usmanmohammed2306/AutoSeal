"""Trusted format warm start with byte-bound checkpoint/resume and validation.

Uses TRL/PEFT on Sol. Model outputs remain text for separate Mac Docker checks.
Calibration and shared-study warm starts have different declared scopes.
"""

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import signal
import time

from training_runtime import canonical, check_sources, files_manifest, identity, loss_token_counts, staged_model, verify_resume, write_new


def validate_configuration(config):
    if config['kind'] != 'artifact_sft_training' or config['schema_version'] != 1:
        raise ValueError('unsupported SFT configuration')
    if config['scope'] not in {'FORMAT_CALIBRATION', 'SHARED_STUDY_WARMSTART'}:
        raise ValueError('SFT scope must be explicit')
    if not 1 <= config['max_steps'] <= 128 or not 128 <= config['max_length'] <= 1024:
        raise ValueError('SFT budget exceeds the supported bound')
    if not 1 <= config['batch_size'] <= 4 or not 0 < config['learning_rate'] <= .001:
        raise ValueError('unsupported SFT optimization settings')
    if identity(canonical(config['training_examples'])) != config['dataset_bytes_id']:
        raise ValueError('SFT training data changed after freeze')
    if len(config['training_examples']) > 128 or len(config['validation_requests']) > 8:
        raise ValueError('SFT data/validation budget exceeded')
    if type(config.get('completion_only_loss', False)) is not bool:
        raise ValueError('SFT loss scope must be an explicit boolean')
    for row in config['training_examples']:
        if set(row) != {'task_id', 'system', 'prompt', 'completion'} or any(not isinstance(value, str) for value in row.values()):
            raise ValueError('invalid reviewed training example')
    return identity(canonical(config['model_files']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pause-at-step', type=int)
    parser.add_argument('--resume-from', type=Path)
    args = parser.parse_args()
    raw = args.config.read_bytes(); config = json.loads(raw)
    base_identity = validate_configuration(config)
    configuration_id = identity(raw)
    check_sources(Path(__file__).resolve().parent, config['sources'])
    resume = verify_resume(args.resume_from, configuration_id=configuration_id,
        dataset_id=config['dataset_revision'], base_identity=base_identity) if args.resume_from else None
    if args.pause_at_step is not None and not 0 < args.pause_at_step < config['max_steps']:
        raise ValueError('pause point must be inside the frozen update budget')
    args.output.mkdir(parents=True, exist_ok=False)
    write_new(args.output / 'configuration.json', config)
    started = time.monotonic()
    report = {'kind': 'artifact_sft_training_report', 'schema_version': 1, 'status': 'FAILED',
        'scope': config['scope'], 'configuration_id': configuration_id, 'dataset_revision': config['dataset_revision'],
        'dataset_bytes_id': config['dataset_bytes_id'], 'base_identity': base_identity, 'seed': config['seed'],
        'slurm_job_id': os.environ.get('SLURM_JOB_ID'), 'resumed_from_step': resume['global_step'] if resume else None,
        'global_step': 0, 'error': None,
        'limitations': ['Authored synthetic output/wire examples; no external benchmark data or preference pairs.',
            'Warm-start calibration is not a multi-seed GRPO comparison or a reward-hacking reduction result.',
            'Generated validation files require separate Mac Docker evaluation.']}
    def progress(stage, details=None):
        print(json.dumps({'stage': stage, 'seconds': time.monotonic() - started, **(details or {})}), flush=True)
    def terminated(_signum, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminated)
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainerCallback, set_seed
        from trl import SFTConfig, SFTTrainer
        if version('trl') != '0.18.2' or not torch.cuda.is_available() or not os.environ.get('SLURM_JOB_ID'):
            raise RuntimeError('the scheduled tested TRL/CUDA environment is required')
        set_seed(config['seed']); torch.set_num_threads(4)
        report['packages'] = {name: version(name) for name in ['torch', 'transformers', 'trl', 'peft', 'datasets']}
        report['gpu'] = torch.cuda.get_device_name(0)
        progress('CUDA_READY', {'gpu': report['gpu']})
        with staged_model(args.model, config['model_files'], progress=progress) as model_root:
            tokenizer = AutoTokenizer.from_pretrained(model_root, local_files_only=True, trust_remote_code=False)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            model = AutoModelForCausalLM.from_pretrained(model_root, local_files_only=True,
                trust_remote_code=False, use_safetensors=True, torch_dtype=torch.bfloat16,
                attn_implementation='sdpa').to('cuda')
            def generate(current):
                current.eval(); current.config.use_cache = True; set_seed(config['validation_seed'])
                samples = []
                for request in config['validation_requests']:
                    text = tokenizer.apply_chat_template([{'role': 'system', 'content': config['system']},
                        {'role': 'user', 'content': request['prompt']}], tokenize=False, add_generation_prompt=True)
                    inputs = tokenizer(text, return_tensors='pt')
                    if inputs['input_ids'].shape[1] > 2048:
                        raise ValueError('validation input exceeds the frozen supported bound')
                    inputs = {key: value.to('cuda') for key, value in inputs.items()}
                    with torch.inference_mode():
                        output = current.generate(**inputs, do_sample=True, temperature=config['temperature'],
                            top_p=.95, max_new_tokens=384, pad_token_id=tokenizer.eos_token_id)
                    tokens = output[0, inputs['input_ids'].shape[1]:]
                    samples.append({'request_id': request['id'], 'case': request['case'], 'mode': request['mode'],
                        'prompt_id': identity(request['prompt'].encode()), 'completion': tokenizer.decode(tokens, skip_special_tokens=True),
                        'input_tokens': inputs['input_ids'].shape[1], 'output_tokens': tokens.shape[0]})
                return samples
            if resume:
                baseline = json.loads((args.resume_from / 'autoseal-baseline.json').read_bytes())
            else:
                progress('BASELINE_GENERATION')
                baseline = generate(model)
            write_new(args.output / 'baseline.json', baseline)
            set_seed(config['seed']); model.train(); model.config.use_cache = False
            texts = [tokenizer.apply_chat_template([{'role': 'system', 'content': row['system']},
                {'role': 'user', 'content': row['prompt']}, {'role': 'assistant', 'content': row['completion']}],
                tokenize=False) for row in config['training_examples']]
            encoded_lengths = [len(tokenizer(text)['input_ids']) for text in texts]
            if any(length > config['max_length'] for length in encoded_lengths):
                raise ValueError('refuse silently truncated SFT examples')
            completion_only = config.get('completion_only_loss', False)
            data = ([{'prompt': [{'role': 'system', 'content': row['system']}, {'role': 'user', 'content': row['prompt']}],
                      'completion': [{'role': 'assistant', 'content': row['completion']}]} for row in config['training_examples']]
                    if completion_only else [{'text': text} for text in texts])
            class Pause(TrainerCallback):
                def on_step_end(self, arguments, state, control, **kwargs):
                    if args.pause_at_step is not None and state.global_step >= args.pause_at_step:
                        control.should_save = control.should_training_stop = True
                    return control
            trainer = SFTTrainer(model=model, processing_class=tokenizer,
                train_dataset=Dataset.from_list(data),
                args=SFTConfig(output_dir=str(args.output / 'trainer'), max_steps=config['max_steps'],
                    max_length=config['max_length'], per_device_train_batch_size=config['batch_size'],
                    gradient_accumulation_steps=1, learning_rate=config['learning_rate'], bf16=True,
                    gradient_checkpointing=True, save_strategy='steps', save_steps=8, save_total_limit=2,
                    logging_steps=1, report_to='none', seed=config['seed'], data_seed=config['seed'],
                    dataset_num_proc=1, optim='adamw_torch', packing=False, completion_only_loss=completion_only),
                peft_config=LoraConfig(r=8, lora_alpha=16, lora_dropout=0., bias='none',
                    task_type='CAUSAL_LM', target_modules=['q_proj', 'v_proj']), callbacks=[Pause()])
            report['supervised_tokens_per_example'] = loss_token_counts(trainer.train_dataset, completion_only=completion_only)
            report['completion_only_loss'] = completion_only
            trainer.model.peft_config['default'].base_model_name_or_path = config['model_source']['repository']
            trainer.model.peft_config['default'].revision = config['model_source']['revision']
            progress('TRAINING', {'resume_step': report['resumed_from_step']})
            trained = trainer.train(resume_from_checkpoint=str(args.resume_from) if args.resume_from else None)
            step = trainer.state.global_step
            report.update(global_step=step, training_loss=trained.training_loss, log_history=trainer.state.log_history,
                trainable_parameters=sum(parameter.numel() for parameter in trainer.model.parameters() if parameter.requires_grad),
                tokenized_example_lengths=encoded_lengths, peak_gpu_bytes=torch.cuda.max_memory_allocated())
            checkpoint = args.output / 'trainer' / f'checkpoint-{step}'
            if not checkpoint.is_dir():
                raise ValueError('training did not retain its resumable optimizer checkpoint')
            write_new(checkpoint / 'autoseal-baseline.json', baseline)
            proof = {'configuration_id': configuration_id, 'dataset_id': config['dataset_revision'],
                'base_identity': base_identity, 'global_step': step, 'checkpoint_files': files_manifest(checkpoint)}
            write_new(checkpoint / 'autoseal-resume.json', proof)
            report['checkpoint_manifest'] = proof
            report['checkpoint_relative_path'] = f'trainer/checkpoint-{step}'
            if step == config['max_steps']:
                trainer.save_model(str(args.output / 'adapter')); tokenizer.save_pretrained(args.output / 'adapter')
                report['adapter_files'] = files_manifest(args.output / 'adapter')
                progress('POST_TRAINING_GENERATION')
                report['samples'] = generate(trainer.model)
                write_new(args.output / 'validation.json', report['samples'])
                report['status'] = 'COMPLETE'
            elif args.pause_at_step == step:
                report['status'] = 'PAUSED_AT_CHECKPOINT'
            else:
                raise ValueError('training stopped before its frozen step budget')
    except BaseException as exc:
        report['status'] = 'INTERRUPTED' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'FAILED'
        report['error'] = f'{type(exc).__name__}: {exc}'
    report['seconds'] = time.monotonic() - started
    write_new(args.output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'global_step': report['global_step'], 'error': report['error']}), flush=True)
    return 0 if report['status'] in {'COMPLETE', 'PAUSED_AT_CHECKPOINT'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
