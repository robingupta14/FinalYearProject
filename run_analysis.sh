#!/bin/bash

set -e
JOERN_VERSION="1.1.114"
JOERN_URL="https://github.com/joernio/joern/releases/download/v$JOERN_VERSION/joern-install.sh"
DATASET_PATH="../Datasets/dataset_final_sorted"
PYTHON_SCRIPT="joern_analysis.py"

echo "[*] Installing Joern..."
if [ ! -d "joern" ]; then
    wget "$JOERN_URL" -O joern-install.sh
    chmod +x joern-install.sh
    ./joern-install.sh
else
    echo "[*] Joern already installed."
fi

echo "[*] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
cat << EOF > requirements.txt
requests>=2.28.0
tqdm>=4.64.0
pandas>=1.5.0
EOF

pip install -r requirements.txt

echo "[*] Starting Joern server..."
/home/robin/bin/joern/joern-cli/joern --server > joern_server.log 2>&1 &
JOERN_PID=$!
echo "[*] Joern server running with PID $JOERN_PID"

echo "[*] Waiting for Joern server to be ready..."
until curl -s http://localhost:8080 > /dev/null; do
  sleep 1
done
echo "[*] Joern server is up."

echo "[*] Running Python analysis..."
python3 "$PYTHON_SCRIPT"

echo "[*] Killing Joern server..."
kill $JOERN_PID

echo "[*] Analysis complete. Output saved to joern_analysis_results.csv"