import os
import subprocess
import json
import pandas as pd
from tqdm import tqdm

DATASET_ROOT = "../Datasets/dataset_final_sorted"
ALLOWED_CWE_IDS = {"CWE-22", "CWE-79", "CWE-89", "CWE-787"}
LANGUAGES = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
OUTPUT_CSV = "semgrep_filtered_results.csv"
results = []

def run_semgrep_on_file(file_path):
    try:
        cmd = [
            "semgrep",
            "--config", "p/cwe-top-25",
            "--json",
            file_path
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 and not proc.stdout.strip():
            return []
        json_output = json.loads(proc.stdout)
        return json_output.get("results", [])
    except Exception as e:
        print(f"Failed on {file_path}: {e}")
        return []

def scan_dataset():
    for cwe_dir in ALLOWED_CWE_IDS:
        cwe_path = os.path.join(DATASET_ROOT, cwe_dir)

        for lang in LANGUAGES:
            lang_path = os.path.join(cwe_path, lang)
            for root, _, files in os.walk(lang_path):
                desc = f"Scanning {cwe_dir}/{lang} ({len(files)} files)"
                for file in tqdm(files, desc=desc, leave=False):
                    file_path = os.path.join(root, file)
                    findings = run_semgrep_on_file(file_path)
                    for finding in findings:
                        print(finding)
                        rule_id = finding.get("check_id", "")
                        matched_cwe = [cwe for cwe in ALLOWED_CWE_IDS if cwe in rule_id]
                        if not matched_cwe:
                            continue
                        results.append({
                            "file": file_path,
                            "line": finding.get("start", {}).get("line", -1),
                            "column": finding.get("start", {}).get("col", -1),
                            "message": finding.get("extra", {}).get("message", ""),
                            "severity": finding.get("extra", {}).get("severity", ""),
                            "rule_id": rule_id
                        })

    if results:
        df = pd.DataFrame(results)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"Results saved to {OUTPUT_CSV}")
    else:
        print("No relevant findings detected.")

if __name__ == "__main__":
    scan_dataset()