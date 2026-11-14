#!/bin/bash
#SBATCH --job-name=autoseal_artifact_grpo
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=48G
#SBATCH --time=00:15:00

set -euo pipefail
umask 077
: "${AUTOSEAL_STUDY_ROOT:?Set the frozen exported study directory}"
: "${AUTOSEAL_MODEL_PATH:?Set the existing cached model}"
: "${AUTOSEAL_WARM_ADAPTER:?Set the verified shared SFT adapter}"
: "${AUTOSEAL_EXCHANGE_ROOT:?Set the owned exchange directory}"
: "${AUTOSEAL_MAMBA_ENV:?Set the existing trusted training environment}"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
python "${AUTOSEAL_STUDY_ROOT}/artifact_campaign.py" \
  --config "${AUTOSEAL_STUDY_ROOT}/configuration.json" \
  --model "${AUTOSEAL_MODEL_PATH}" --warm-adapter "${AUTOSEAL_WARM_ADAPTER}" \
  --exchange "${AUTOSEAL_EXCHANGE_ROOT}" --output "${AUTOSEAL_STUDY_ROOT}/campaign-01"
