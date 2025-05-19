#!/bin/bash
#SBATCH --gres=gpu:1
#SBATCH --mail-type=ALL
#SBATCH --mail-user=rg721
export PATH=/vol/bitbucket/rg721/FinalYearProject/venv/bin/:$PATH
source activate
/usr/bin/nvidia-smi
uptime
python /vol/bitbucket/rg721/FinalYearProject/DeepSeek7B/deepseek.py