#!/bin/bash
#SBATCH --job-name=autoseal_hidden_audit
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:20:00

set -euo pipefail
umask 077
: "${AUTOSEAL_AUDIT_ROOT:?Set the frozen post-checkpoint audit directory}"
: "${AUTOSEAL_MODEL_PATH:?Set the existing cached base model}"
: "${AUTOSEAL_MAMBA_ENV:?Set the existing trusted model environment}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
python "${AUTOSEAL_AUDIT_ROOT}/artifact_audit.py" --config "${AUTOSEAL_AUDIT_ROOT}/configuration.json" \
  --model "${AUTOSEAL_MODEL_PATH}" --output "${AUTOSEAL_AUDIT_ROOT}/generation-01"
