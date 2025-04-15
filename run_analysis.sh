#!/bin/bash

set -e
DATASET_PATH="../Datasets/dataset_final_sorted"
PYTHON_SCRIPT="semgrep_analysis.py"

echo "[*] Installing Semgrep..."
if ! command -v semgrep &> /dev/null; then
    pip install semgrep
else
    echo "[*] Semgrep already installed."
fi

SEMGREP_APP_TOKEN=bcb655c4d07ee63e5cae0352b42c0e9ff345f4003bb6920eb84a95c1750f5870 semgrep login

echo "[*] Running Semgrep analysis..."
python3 $PYTHON_SCRIPT

echo "[*] Analysis complete. Output saved to semgrep_analysis_results.csv"