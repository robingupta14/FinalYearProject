#!/bin/bash

set -e
PYTHON_SCRIPT="semgrep_analysis.py"

echo "[*] Installing Semgrep..."
if ! command -v semgrep &> /dev/null; then
    pip install semgrep
else
    echo "[*] Semgrep already installed."
fi

if [[ -z "$SEMGREP_APP_TOKEN" ]]; then
    echo "[!] SEMGREP_APP_TOKEN environment variable is not set. Exiting."
    exit 1
fi

semgrep login --token "$SEMGREP_APP_TOKEN"

echo "[*] Running Semgrep analysis..."
python3 "$PYTHON_SCRIPT"

echo "[*] Analysis complete."