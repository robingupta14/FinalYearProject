#!/bin/bash
#SBATCH --gres=gpu:1
#SBATCH --mail-type=ALL # required to send email notifcations
#SBATCH --mail-user=rg721 # required to send email notifcations - please replace <your_username> with your college login name or email address
export PATH=/vol/bitbucket/rg721/FinalYearProject/venv/bin/:$PATH
source activate
/usr/bin/nvidia-smi
uptime
python /vol/bitbucket/rg721/FinalYearProject/DeepSeek7B/deepseek.py
