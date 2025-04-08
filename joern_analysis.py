import os
import requests
import tempfile
import shutil
from tqdm import tqdm
import pandas as pd

CWEs = ['79', '787', '89', '22']
languages = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
dataset_root = "../Datasets/dataset_final_sorted"
JOERN_URL = "http://localhost:8080"

def iter_dataset(dataset_root, CWEs, languages):
    for cwe in CWEs:
        cwe_path = os.path.join(dataset_root, cwe)
        for root, _, files in os.walk(cwe_path):
            for file in files:
                if not any(file.endswith(f".{ext}") for ext in languages):
                    continue
                
                label = 'good' if file.startswith('good_') else 'bad'
                parts = file.split('_')
                
                if len(parts) < 3:
                    continue
                
                commit_id = parts[1]
                file_id = parts[2].split('.')[0]
                full_path = os.path.join(root, file)
                
                with open(full_path, 'r', errors='ignore') as f:
                    source_code = f.read()
                
                yield {
                    "cwe": cwe,
                    "label": label,
                    "commit_id": commit_id,
                    "file_id": file_id,
                    "path": full_path,
                    "source_code": source_code,
                }


def run_joern_analysis(source_code):
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "file.c")
        with open(src_path, "w") as f:
            f.write(source_code)

        import_res = requests.post(f"{JOERN_URL}/importCode", json={"inputPath": tmpdir})
        if import_res.status_code != 200:
            return []

        cpg_id = import_res.json()["cpgId"]

        requests.post(f"{JOERN_URL}/query", json={"cpgId": cpg_id, "query": "loadCweQueries()"})
        
        cwe_queries = [
            "cwe120.findings.l",
            "cwe78.findings.l",
            "cwe89.findings.l",
            "cwe79.findings.l",
        ]

        findings = []
        for q in cwe_queries:
            res = requests.post(f"{JOERN_URL}/query", json={"cpgId": cpg_id, "query": q})
            if res.status_code == 200:
                findings.extend(res.json())

        return findings

results = []

for item in tqdm(iter_dataset(dataset_root, CWEs, languages)):
    findings = run_joern_analysis(item["source_code"])

    results.append({
        "cwe": item["cwe"],
        "label": item["label"],
        "commit_id": item["commit_id"],
        "file_id": item["file_id"],
        "path": item["path"],
        "findings": findings,
    })

df = pd.DataFrame(results)
df.to_csv("joern_analysis_results.csv", index=False)
print("Saved results to joern_analysis_results.csv")