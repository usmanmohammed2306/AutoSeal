"""Inference-only evaluation of the frozen shared baseline and trained arms.

All models receive the same committed prompts and greedy token budget. This
job never loads an optimizer, runs generated files or computes an audit label.
"""

import argparse
from importlib.metadata import version
import json
import os
from pathlib import Path
import signal
import time

from training_runtime import canonical, check_sources, identity, staged_model, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.config.read_bytes(); config = json.loads(raw)
    models, requests = config['models'], config['requests']
    expected = {('baseline', None), *[(arm, seed) for arm in ('vulnerable', 'sealed') for seed in config['seeds']]}
    if (config['kind'] != 'artifact_study_audit_generation' or config['schema_version'] != 1
            or config['scope'] != 'POST_CHECKPOINT_HIDDEN_AUDIT' or len(set(config['seeds'])) < 3
            or len(models) != len(expected) or {(row['arm'], row['seed']) for row in models} != expected
            or len({row['model_id'] for row in models}) != len(models) or not 7 <= len(models) <= 17
            or len(requests) != 8 or len({row['request_id'] for row in requests}) != 8
            or config['decoding']['do_sample'] is not False
            or not 1 <= config['decoding']['max_new_tokens'] <= 256
            or not 128 <= config['decoding']['max_input_tokens'] <= 2048):
        raise ValueError('audit inference differs from its frozen bounded final matrix')
    check_sources(Path(__file__).resolve().parent, config['sources'])
    args.output.mkdir(parents=True, exist_ok=False)
    write_new(args.output / 'configuration.json', config)
    report = {'kind': 'artifact_study_audit_generation_report', 'schema_version': 1,
        'configuration_id': identity(raw), 'training_archive_id': config['training_archive_id'],
        'manifest_id': config['manifest_id'], 'hidden_commitment': config['hidden_commitment'],
        'status': 'FAILED', 'error': None, 'samples': [], 'models': [],
        'slurm_job_id': os.environ.get('SLURM_JOB_ID'), 'limitations': config['limitations']}
    started = time.monotonic()
    def progress(stage, details=None):
        print(json.dumps({'stage': stage, 'seconds': time.monotonic() - started, **(details or {})}), flush=True)
    def terminated(_signal, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminated)
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed
        if not torch.cuda.is_available() or not os.environ.get('SLURM_JOB_ID'):
            raise RuntimeError('audit generation requires an explicitly scheduled CUDA allocation')
        torch.set_num_threads(4)
        report['packages'] = {name: version(name) for name in ('torch', 'transformers', 'peft')}
        report['gpu'] = torch.cuda.get_device_name(0)
        progress('CUDA_READY', {'gpu': report['gpu']})
        with staged_model(args.model, config['model_files'], progress=progress) as base:
            tokenizer = AutoTokenizer.from_pretrained(base, local_files_only=True, trust_remote_code=False)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            base_model = AutoModelForCausalLM.from_pretrained(base, local_files_only=True, trust_remote_code=False,
                use_safetensors=True, torch_dtype=torch.bfloat16, attn_implementation='sdpa').to('cuda')
            model = None
            for index, subject in enumerate(models):
                progress('SUBJECT', {'model_id': subject['model_id']})
                with staged_model(Path(subject['remote_path']), subject['adapter_files'], max_bytes=128 * 1024**2,
                        progress=lambda stage, details=None: progress(stage, {'component': subject['model_id'], **(details or {})})) as adapter:
                    name = 'subject' + str(index)
                    if model is None:
                        model = PeftModel.from_pretrained(base_model, adapter, adapter_name=name,
                            is_trainable=False, local_files_only=True, use_safetensors=True)
                    else:
                        model.load_adapter(adapter, adapter_name=name, is_trainable=False,
                            local_files_only=True, use_safetensors=True)
                    model.set_adapter(name)
                model.eval(); model.config.use_cache = True
                for parameter in model.parameters():
                    parameter.requires_grad_(False)
                set_seed(config['decoding']['seed'])
                report['models'].append({'model_id': subject['model_id'], 'arm': subject['arm'], 'seed': subject['seed'],
                    'adapter_inventory_id': identity(canonical(subject['adapter_files']))})
                for request in requests:
                    if identity(request['prompt'].encode()) != request['prompt_id']:
                        raise ValueError('hidden prompt differs from its committed identity')
                    prompt = tokenizer.apply_chat_template([{'role': 'system', 'content': config['system']},
                        {'role': 'user', 'content': request['prompt']}], tokenize=False, add_generation_prompt=True)
                    inputs = tokenizer(prompt, return_tensors='pt')
                    if inputs['input_ids'].shape[1] > config['decoding']['max_input_tokens']:
                        raise ValueError('refuse silently truncated hidden prompts')
                    inputs = {key: value.to('cuda') for key, value in inputs.items()}
                    with torch.inference_mode():
                        output = model.generate(**inputs, do_sample=False,
                            max_new_tokens=config['decoding']['max_new_tokens'], pad_token_id=tokenizer.eos_token_id)
                    tokens = output[0, inputs['input_ids'].shape[1]:]
                    eos = model.generation_config.eos_token_id
                    eos_ids = eos if isinstance(eos, list) else [eos]
                    sample = {'model_id': subject['model_id'], 'arm': subject['arm'], 'seed': subject['seed'],
                        'request_id': request['request_id'], 'task_id': request['task_id'], 'prompt_id': request['prompt_id'],
                        'completion': tokenizer.decode(tokens, skip_special_tokens=True),
                        'input_tokens': inputs['input_ids'].shape[1], 'output_tokens': tokens.shape[0],
                        'ended_with_eos': bool(tokens.shape[0] and tokens[-1].item() in eos_ids)}
                    write_new(args.output / f'sample-{len(report["samples"]):03d}.json', sample)
                    report['samples'].append(sample)
                    progress('SAMPLE', {'model_id': subject['model_id'], 'request_id': request['request_id'],
                        'output_tokens': sample['output_tokens']})
            report['status'] = 'COMPLETE'
            report['peak_gpu_bytes'] = torch.cuda.max_memory_allocated()
    except BaseException as exc:
        report['status'] = 'INTERRUPTED' if isinstance(exc, (SystemExit, KeyboardInterrupt)) else 'FAILED'
        report['error'] = f'{type(exc).__name__}: {exc}'
    report['seconds'] = time.monotonic() - started
    write_new(args.output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'samples': len(report['samples']), 'error': report['error']}), flush=True)
    return 0 if report['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
