import os
import subprocess
import json
import pandas as pd
from random import shuffle
from tqdm import tqdm
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score
from concurrent.futures import ThreadPoolExecutor, as_completed

DATASET_ROOT = "../../Preprocessed/NoRename"
ALLOWED_CWE_IDS = {"CWE-89"} #"CWE-79", "CWE-89", "CWE-787"
LANGUAGES = ['c', 'cpp', 'cs', 'java', 'py', 'php']
OUTPUT_CSV = "semgrep_filtered_results.csv"
BENCHMARK_CSV = "semgrep_benchmark_results.csv"
CONF_MATRIX_CSV = "semgrep_confusion_matrix.csv"
METRICS_CSV =  "semgrep_per_cwe_metrics.csv"

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

def process_file(cwe_dir, file_path):
    ground_truth_label = "bad" if "bad" in file_path.lower() else "good"
    findings = run_semgrep_on_file(file_path)

    file_results = []
    found_cwes = False

    for finding in findings:
        print(finding)
        found_cwes = True
        rule_id = finding.get("check_id", "")
        file_results.append({
            "file": file_path,
            "line": finding.get("start", {}).get("line", -1),
            "column": finding.get("start", {}).get("col", -1),
            "message": finding.get("extra", {}).get("message", ""),
            "severity": finding.get("extra", {}).get("severity", ""),
            "rule_id": rule_id
        })

    if ground_truth_label == "bad":
        if not found_cwes:  # We DID have a CWE, but did not detect one 
            classification = "False Negative"
        else:               # We DID have a CWE, and did detect one
            classification = "True Positive"

    else:
        if not found_cwes:  # We did NOT have a CWE and did not detect one 
            classification = "True Negative"
        else:               # We did NOT have a CWE but did detect one 
            classification = "False Positive"

    benchmark_entry = {
        "file": file_path,
        "label": ground_truth_label,
        "cwe": cwe_dir,
        "classification": classification
    }

    return file_results, benchmark_entry

def scan_dataset():
    all_tasks = []
    for cwe_dir in ALLOWED_CWE_IDS:
        cwe_path = os.path.join(DATASET_ROOT, cwe_dir)
        for lang in LANGUAGES:
            lang_path = os.path.join(cwe_path, lang)
            if not os.path.exists(lang_path):
                continue
            for root, _, files in os.walk(lang_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    all_tasks.append((cwe_dir, file_path))

    print(f"[+] Total files to scan: {len(all_tasks)}")

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(process_file, cwe, path) for cwe, path in all_tasks]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Running Semgrep in parallel"):
            file_results, benchmark_entry = future.result()
            results.extend(file_results)
            benchmark.append(benchmark_entry)
    pd.DataFrame(results).to_csv(OUTPUT_CSV, index=False)
    print(f"[+] Findings saved to {OUTPUT_CSV}")
    benchmark_df = pd.DataFrame(benchmark)
    benchmark_df.to_csv(BENCHMARK_CSV, index=False)
    print(f"[+] Benchmark results saved to {BENCHMARK_CSV}")

    y_true, y_pred = [], []

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
    print(pd.DataFrame(cm, index=["No CWE", "CWE"], columns=["Found no CWE", "Found CWE"]))
    print("\n=== Metrics ===")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Accuracy:  {accuracy:.4f}")

    pd.DataFrame(cm, index=["No CWE", "CWE"], columns=["Found no CWE", "Found CWE"]).to_csv(CONF_MATRIX_CSV)
    print(f"[+] Confusion matrix saved to {CONF_MATRIX_CSV}")

    print("\n=== Per-CWE Metrics ===")
    per_cwe_metrics = []
    for cwe in ALLOWED_CWE_IDS:
        cwe_y_true, cwe_y_pred = [], []
        for row in benchmark_df.itertuples():
            if row.cwe != cwe:
                continue
            if row.label == "bad":
                cwe_y_true.append(1)
                cwe_y_pred.append(1 if row.classification == "True Positive" else 0)
            else:
                cwe_y_true.append(0)
                cwe_y_pred.append(0 if row.classification == "True Negative" else 1)
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

    pd.DataFrame(per_cwe_metrics).to_csv(METRICS_CSV, index=False)
    print(f"[+] Per-CWE metrics saved to {METRICS_CSV}")
    print("\n=== Per-Language Metrics ===")
    per_lang_metrics = []
    for lang in LANGUAGES:
        lang_y_true, lang_y_pred = [], []
        for row in benchmark_df.itertuples():
            if f"/{lang}/" not in row.file:
                continue
            if row.label == "bad":
                lang_y_true.append(1)
                lang_y_pred.append(1 if row.classification == "True Positive" else 0)
            else:
                lang_y_true.append(0)
                lang_y_pred.append(0 if row.classification == "True Negative" else 1)

        if not lang_y_true:
            continue

        cm = confusion_matrix(lang_y_true, lang_y_pred)
        precision = precision_score(lang_y_true, lang_y_pred, zero_division=0)
        recall = recall_score(lang_y_true, lang_y_pred, zero_division=0)
        f1 = f1_score(lang_y_true, lang_y_pred, zero_division=0)
        accuracy = accuracy_score(lang_y_true, lang_y_pred)

        tn, fp, fn, tp = cm.ravel()

        print(f"\n[{lang}]")
        print(pd.DataFrame(cm, index=["No CWE", "CWE"], columns=["Found no CWE", "Found CWE"]))
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1 Score:  {f1:.4f}")
        print(f"  Accuracy:  {accuracy:.4f}")

        per_lang_metrics.append({
            "Language": lang,
            "True Positives": tp,
            "False Positives": fp,
            "True Negatives": tn,
            "False Negatives": fn,
            "Precision": precision,
            "Recall": recall,
            "F1": f1,
            "Accuracy": accuracy
        })

    lang_metrics_csv = "semgrep_per_language_metrics.csv"
    pd.DataFrame(per_lang_metrics).to_csv(lang_metrics_csv, index=False)
    print(f"[+] Per-language metrics and confusion matrices saved to {lang_metrics_csv}")

if __name__ == "__main__":
    scan_dataset()