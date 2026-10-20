#!/bin/bash
#SBATCH --job-name=autoseal_training_preflight
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=4
#SBATCH --mem=24G
#SBATCH --time=00:10:00

set -euo pipefail

: "${AUTOSEAL_MAMBA_ENV:?Set AUTOSEAL_MAMBA_ENV to an existing environment name}"
module load mamba/latest
source activate "${AUTOSEAL_MAMBA_ENV}"
python scripts/sol/training_preflight.py
