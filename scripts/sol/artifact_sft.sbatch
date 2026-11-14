#!/bin/bash
#SBATCH --job-name=autoseal_syntax_sft
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:10:00

set -euo pipefail
umask 077
: "${AUTOSEAL_SFT_ROOT:?Set the frozen SFT directory}"
: "${AUTOSEAL_MODEL_PATH:?Set the existing cached base model}"
: "${AUTOSEAL_MAMBA_ENV:?Set the existing trusted training environment}"
: "${AUTOSEAL_SFT_OUTPUT:?Set a new attempt output directory}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
AUTOSEAL_ARGS=(--config "${AUTOSEAL_SFT_ROOT}/configuration.json" --model "${AUTOSEAL_MODEL_PATH}" --output "${AUTOSEAL_SFT_OUTPUT}")
if [[ -n "${AUTOSEAL_PAUSE_STEP:-}" ]]; then AUTOSEAL_ARGS+=(--pause-at-step "${AUTOSEAL_PAUSE_STEP}"); fi
if [[ -n "${AUTOSEAL_RESUME_FROM:-}" ]]; then AUTOSEAL_ARGS+=(--resume-from "${AUTOSEAL_RESUME_FROM}"); fi
python "${AUTOSEAL_SFT_ROOT}/artifact_sft.py" "${AUTOSEAL_ARGS[@]}"
