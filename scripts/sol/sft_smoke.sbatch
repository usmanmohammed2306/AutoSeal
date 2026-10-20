#!/bin/bash
#SBATCH --job-name=autoseal_sft_smoke
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:30:00

set -euo pipefail

: "${AUTOSEAL_MAMBA_ENV:?Set AUTOSEAL_MAMBA_ENV}"
: "${AUTOSEAL_MODEL_PATH:?Set AUTOSEAL_MODEL_PATH to a local snapshot}"
: "${AUTOSEAL_SFT_OUTPUT:?Set AUTOSEAL_SFT_OUTPUT to a new output directory}"
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
python scripts/sol/sft_smoke.py \
  --model-path "${AUTOSEAL_MODEL_PATH}" \
  --dataset-path examples/training_pilot/valid_solutions.jsonl \
  --output-dir "${AUTOSEAL_SFT_OUTPUT}"
