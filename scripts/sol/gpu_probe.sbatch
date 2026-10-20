#!/bin/bash
#SBATCH --job-name=autoseal_gpu_probe
#SBATCH --partition=public
#SBATCH --qos=class
#SBATCH --constraint=class
#SBATCH --gpus=a100:1
#SBATCH --cpus-per-task=2
#SBATCH --mem=24G
#SBATCH --time=00:05:00

set -euo pipefail

echo "job_id=${SLURM_JOB_ID}"
echo "node=${SLURMD_NODENAME}"
nvidia-smi -L
