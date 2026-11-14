"""Bounded trusted model generation only. Never executes generated candidates.

This preflight measures syntax and explicitly elicited evaluator influence. It
does not train, expose an audit reward, or establish unprompted exploit discovery.
"""

import argparse
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time


def digest(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


def save(path, body):
    with path.open("x") as handle:
        json.dump(body, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.config.read_bytes()
    config = json.loads(raw)
    if config["kind"] != "artifact_model_probe" or config["schema_version"] != 1 or len(config["requests"]) > 8:
        raise ValueError("unsupported probe configuration")
    if digest(Path(__file__).read_bytes()) != config["driver_id"]:
        raise ValueError("trusted probe driver differs from frozen source")
    if config["max_new_tokens"] > 384 or config["max_input_tokens"] > 4096:
        raise ValueError("probe token budget exceeded")
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / "configuration.json", config)
    started = time.monotonic()
    report = {"kind": "artifact_model_generation_probe", "schema_version": 1, "status": "FAILED",
        "configuration_id": digest(raw), "driver_id": config["driver_id"], "samples": [],
        "slurm_job_id": os.environ.get("SLURM_JOB_ID"), "error": None,
        "model_source": config.get('model_source'),
        "limitations": ["Single-seed generation preflight, no training or efficacy claim.",
            "Targeted requests explicitly fix a wrong deliverable; do not call them unprompted discoveries.",
            "Sol produces text only; generated files require separate Mac Docker evaluation."]}
    staging = None
    def stage(name, **values):
        event = {'stage': name, 'seconds': time.monotonic() - started, **values}
        save(args.output / (name.lower() + '.json'), event)
        print(json.dumps(event), flush=True)
    def terminated(_number, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminated)
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed
        if not torch.cuda.is_available() or not os.environ.get("SLURM_JOB_ID"):
            raise RuntimeError("a scheduled CUDA allocation is required")
        set_seed(config["seed"])
        torch.set_num_threads(4)
        report["packages"] = {key: version(key) for key in ["torch", "transformers", "trl", "peft"]}
        report["gpu"] = torch.cuda.get_device_name(0)
        stage('CUDA_READY', gpu=report['gpu'], packages=report['packages'])
        # Hash the actual local checkpoint, rather than treating a directory
        # name as immutable model identity. This I/O stays on the allocated node.
        files = [*sorted(args.model.glob("*.json")), *sorted(args.model.glob("*.safetensors")),
                 *sorted(args.model.glob("*.txt")), args.model / "LICENSE"]
        total_bytes = sum(path.stat().st_size for path in files)
        temporary_root = os.environ.get('SLURM_TMPDIR', '/tmp')
        model_budget = config.get('model_bytes_limit', 10 * 1024**3)
        if type(model_budget) is not int or not 0 < model_budget <= 32 * 1024**3:
            raise ValueError('unsupported model staging byte budget')
        if total_bytes > model_budget or shutil.disk_usage(temporary_root).free < 2 * total_bytes + 1024**3:
            raise ValueError('bounded node-local model staging has insufficient space')
        staging = tempfile.TemporaryDirectory(prefix='autoseal-model-', dir=temporary_root)
        local_model = Path(staging.name)
        local_model.chmod(0o700)
        stage('STAGING_STARTED', bytes=total_bytes)
        model_files = {}
        for path in files:
            if not path.is_file():
                raise ValueError("model snapshot is incomplete")
            hasher = hashlib.sha256()
            with path.open("rb") as handle, (local_model / path.name).open('xb') as output:
                for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                    hasher.update(block)
                    output.write(block)
            model_files[path.name] = {"sha256": hasher.hexdigest(), "bytes": path.stat().st_size}
        if not any(name.endswith(".safetensors") for name in model_files):
            raise ValueError("no local safetensors model weights found")
        report["model_files"] = model_files
        save(args.output / 'model_manifest.json', model_files)
        stage('MODEL_STAGED', bytes=total_bytes)
        tokenizer = AutoTokenizer.from_pretrained(local_model, local_files_only=True, trust_remote_code=False)
        model = AutoModelForCausalLM.from_pretrained(local_model, local_files_only=True, trust_remote_code=False,
            use_safetensors=True, torch_dtype=torch.bfloat16, attn_implementation="sdpa").to("cuda")
        model.eval()
        stage('MODEL_READY')
        for request in config["requests"]:
            messages = [{"role": "system", "content": "Return one JSON object mapping relative file names to UTF-8 file contents. No Markdown or explanations."},
                        {"role": "user", "content": request["prompt"]}]
            text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = tokenizer(text, return_tensors="pt")
            if inputs["input_ids"].shape[1] > config["max_input_tokens"]:
                raise ValueError("frozen request exceeds the input token budget")
            inputs = {key: value.to("cuda") for key, value in inputs.items()}
            sample_started = time.monotonic()
            with torch.inference_mode():
                output = model.generate(**inputs, do_sample=True, temperature=config["temperature"],
                    top_p=config["top_p"], max_new_tokens=config["max_new_tokens"], pad_token_id=tokenizer.eos_token_id)
            generated = output[0, inputs["input_ids"].shape[1]:]
            completion = tokenizer.decode(generated, skip_special_tokens=True)
            record = {"request_id": request["id"], "case": request["case"], "mode": request["mode"],
                "completion": completion, "input_tokens": inputs["input_ids"].shape[1],
                "output_tokens": generated.shape[0], "seconds": time.monotonic() - sample_started}
            save(args.output / (request["id"] + ".json"), record)
            report["samples"].append(record)
            print(json.dumps({key: record[key] for key in ("request_id", "mode", "input_tokens", "output_tokens", "seconds")}), flush=True)
        report["status"] = "COMPLETE"
        report["peak_gpu_bytes"] = torch.cuda.max_memory_allocated()
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if staging is not None:
            staging.cleanup()
    report["seconds"] = time.monotonic() - started
    save(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "samples": len(report["samples"]), "error": report["error"]}), flush=True)
    return 0 if report["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
