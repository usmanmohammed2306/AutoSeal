#!/bin/bash
#SBATCH --job-name=autoseal_artifact_probe
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=24G
#SBATCH --time=00:05:00

set -euo pipefail
umask 077
: "${AUTOSEAL_PROBE_ROOT:?Set the new frozen probe directory}"
: "${AUTOSEAL_MODEL_PATH:?Set the existing local model snapshot}"
: "${AUTOSEAL_MAMBA_ENV:?Set the existing trusted environment}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
python "${AUTOSEAL_PROBE_ROOT}/artifact_probe.py" --config "${AUTOSEAL_PROBE_ROOT}/configuration.json" \
  --model "${AUTOSEAL_MODEL_PATH}" --output "${AUTOSEAL_PROBE_ROOT}/output"
