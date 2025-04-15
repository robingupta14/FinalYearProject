import os
import subprocess
import json
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

DATASET_ROOT = "../Datasets/dataset_final_sorted"
ALLOWED_CWE_IDS = {"CWE-22", "CWE-79", "CWE-89", "CWE-787"}
LANGUAGES = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
OUTPUT_CSV = "semgrep_filtered_results.csv"
BENCHMARK_CSV = "semgrep_benchmark_results.csv"
CONF_MATRIX_CSV = "semgrep_confusion_matrix.csv"
METRICS_CSV = "semgrep_per_cwe_metrics.csv"

results = []
benchmark = []

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
            if not os.path.exists(lang_path):
                continue
    
            for root, _, files in os.walk(lang_path):
                for file in tqdm(files, desc=f"Scanning {lang_path}"):
                    file_path = os.path.join(root, file)
                    label = "bad" if "bad" in file.lower() else "good"

                    findings = run_semgrep_on_file(file_path)

                    found_cwes = {
                        cwe for finding in findings 
                        for cwe in ALLOWED_CWE_IDS 
                        if cwe.lower() in finding.get("check_id", "").lower()
                    }

                    for finding in findings:
                        rule_id = finding.get("check_id", "")
                        results.append({
                            "file": file_path,
                            "line": finding.get("start", {}).get("line", -1),
                            "column": finding.get("start", {}).get("col", -1),
                            "message": finding.get("extra", {}).get("message", ""),
                            "severity": finding.get("extra", {}).get("severity", ""),
                            "rule_id": rule_id
                        })

                    if label == "bad":
                        if not found_cwes:
                            classification = "False Negative"
                        elif cwe_dir in found_cwes:
                            classification = "True Positive"
                        else:
                            classification = "False Negative"
                    else:
                        if not found_cwes:
                            classification = "True Negative"
                        else:
                            classification = "False Positive"

                    benchmark.append({
                        "file": file_path,
                        "label": label,
                        "expected_cwe": cwe_dir,
                        "found_cwes": list(found_cwes),
                        "classification": classification
                    })

    pd.DataFrame(results).to_csv(OUTPUT_CSV, index=False)
    print(f"[+] Findings saved to {OUTPUT_CSV}")
    benchmark_df = pd.DataFrame(benchmark)
    benchmark_df.to_csv(BENCHMARK_CSV, index=False)
    print(f"[+] Benchmark results saved to {BENCHMARK_CSV}")

    y_true = [] 
    y_pred = []

    for row in benchmark_df.itertuples():
        if row.label == "bad":
            y_true.append(1)
            y_pred.append(1 if row.classification == "True Positive" else 0)
        else:
            y_true.append(0)
            y_pred.append(0 if row.classification == "True Negative" else 1)

    cm = confusion_matrix(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)

    print("\n=== Confusion Matrix ===")
    print(pd.DataFrame(cm, index=["Actual Good", "Actual Bad"], columns=["Predicted Good", "Predicted Bad"]))
    print("\n=== Metrics ===")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Accuracy:  {accuracy:.4f}")

    pd.DataFrame(cm, index=["Actual Good", "Actual Bad"], columns=["Predicted Good", "Predicted Bad"]).to_csv(CONF_MATRIX_CSV)
    print(f"[+] Confusion matrix saved to {CONF_MATRIX_CSV}")

    print("\n=== Per-CWE Metrics ===")
    per_cwe_metrics = []

    for cwe in ALLOWED_CWE_IDS:
        cwe_y_true = []
        cwe_y_pred = []
        for row in benchmark_df.itertuples():
            if row.expected_cwe != cwe:
                continue
            if row.label == "bad":
                cwe_y_true.append(1)
                cwe_y_pred.append(1 if cwe in row.found_cwes else 0)
            else:
                cwe_y_true.append(0)
                cwe_y_pred.append(0 if not row.found_cwes else 1)

        if not cwe_y_true:
            continue

        cwe_precision = precision_score(cwe_y_true, cwe_y_pred, zero_division=0)
        cwe_recall = recall_score(cwe_y_true, cwe_y_pred, zero_division=0)
        cwe_f1 = f1_score(cwe_y_true, cwe_y_pred, zero_division=0)
        cwe_accuracy = accuracy_score(cwe_y_true, cwe_y_pred)

        print(f"\n[{cwe}]")
        print(f"  Precision: {cwe_precision:.4f}")
        print(f"  Recall:    {cwe_recall:.4f}")
        print(f"  F1 Score:  {cwe_f1:.4f}")
        print(f"  Accuracy:  {cwe_accuracy:.4f}")

        per_cwe_metrics.append({
            "CWE": cwe,
            "Precision": cwe_precision,
            "Recall": cwe_recall,
            "F1": cwe_f1,
            "Accuracy": cwe_accuracy
        })
        
    pd.DataFrame(per_cwe_metrics).to_csv("semgrep_per_cwe_metrics.csv", index=False)
    print("[+] Per-CWE metrics saved to semgrep_per_cwe_metrics.csv")

if __name__ == "__main__":
    scan_dataset()