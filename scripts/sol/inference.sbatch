#!/bin/bash
#SBATCH --job-name=autoseal_inference
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:45:00

set -euo pipefail
umask 077
: "${AUTOSEAL_MODEL_PATH:?Set a cached local model snapshot}"
: "${AUTOSEAL_TOKEN_FILE:?Set the private credential file}"
AUTOSEAL_SIF=/packages/apps/simg/vllm-cu129-nightly-0426.sif
AUTOSEAL_PORT=${AUTOSEAL_PORT:-8765}
export APPTAINERENV_VLLM_API_KEY
APPTAINERENV_VLLM_API_KEY=$(<"${AUTOSEAL_TOKEN_FILE}")
export APPTAINERENV_PYTHONPATH="${PWD}/scripts/sol"
export APPTAINERENV_HF_HUB_OFFLINE=1
export APPTAINERENV_TRANSFORMERS_OFFLINE=1
export APPTAINERENV_VLLM_NO_USAGE_STATS=1
export APPTAINERENV_VLLM_DO_NOT_TRACK=1
printf 'AUTOSEAL_NODE=%s\nAUTOSEAL_JOB=%s\n' "$(hostname)" "${SLURM_JOB_ID}"
sha256sum "${AUTOSEAL_SIF}"
sha256sum scripts/sol/inference.sbatch scripts/sol/autoseal_server_auth.py
exec apptainer run --nv --bind /scratch "${AUTOSEAL_SIF}" \
  --model "${AUTOSEAL_MODEL_PATH}" \
  --served-model-name "${AUTOSEAL_SERVED_MODEL:-autoseal-qwen-coder-3b}" \
  --host 0.0.0.0 --port "${AUTOSEAL_PORT}" \
  --max-model-len 8192 --max-num-seqs 2 \
  --gpu-memory-utilization 0.5 --enforce-eager \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --middleware autoseal_server_auth.require_token
