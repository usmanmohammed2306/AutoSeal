#!/bin/bash
#SBATCH --job-name=autoseal_grpo_bridge
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:30:00

set -euo pipefail
umask 077
: "${AUTOSEAL_MAMBA_ENV:?Set the existing trusted training environment}"
: "${AUTOSEAL_MODEL_PATH:?Set the pinned cached model snapshot}"
: "${AUTOSEAL_BRIDGE_CONFIG:?Set the frozen bridge configuration}"
: "${AUTOSEAL_BRIDGE_EXCHANGE:?Set the named scratch exchange directory}"
: "${AUTOSEAL_GRPO_OUTPUT:?Set a new output directory}"
: "${AUTOSEAL_GRPO_ARM:?Set vulnerable or sealed}"
: "${AUTOSEAL_GRPO_SEED:?Set the frozen seed}"
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
python scripts/sol/grpo_bridge.py \
  --config "${AUTOSEAL_BRIDGE_CONFIG}" --model-path "${AUTOSEAL_MODEL_PATH}" \
  --exchange "${AUTOSEAL_BRIDGE_EXCHANGE}" --output "${AUTOSEAL_GRPO_OUTPUT}" \
  --arm "${AUTOSEAL_GRPO_ARM}" --seed "${AUTOSEAL_GRPO_SEED}"
