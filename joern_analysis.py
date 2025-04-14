import os
import requests
import tempfile
from tqdm import tqdm
import pandas as pd
from pprint import pprint

CWEs = ['79', '787', '89', '22']
languages = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
dataset_root = "../Datasets/dataset_final_sorted"
JOERN_URL = "http://localhost:8080"

def iter_dataset(dataset_root, CWEs, languages):
    for cwe in CWEs:
        cwe_path = os.path.join(dataset_root, "CWE-"+cwe)
        for language in languages:
            full_path = os.path.join(cwe_path, language)
            for root, _, files in os.walk(full_path):
                for file in files:                    
                    label = 'good' if file.startswith('good_') else 'bad'
                    parts = file.split('_')
                    
                    if len(parts) < 3:
                        continue
                    
                    commit_id = parts[1]
                    file_id = parts[2].split('.')[0]
                    full_path = os.path.join(root, file)
                    
                    with open(full_path, 'r') as f:
                        source_code = f.read()

                    yield {
                        "cwe": cwe,
                        "label": label,
                        "commit_id": commit_id,
                        "file_id": file_id,
                        "path": full_path,
                        "source_code": source_code,
                    }

import os
import tempfile
import subprocess

def run_joern_analysis(source_code):
    with tempfile.TemporaryDirectory() as tmpdir:
        source_path = os.path.join(tmpdir, "file.c")
        with open(source_path, "w") as f:
            f.write(source_code)

        cpg_path = os.path.join(tmpdir, "cpg.bin")
 
        subprocess.run([
            "/home/robin/bin/joern/joern-cli/joern-scan",
            "--input-path", tmpdir,
            "--output-path", cpg_path
        ], check=True)
 
        query_script = os.path.join(tmpdir, "find_cwes.sc")
        with open(query_script, "w") as f:
            f.write("loadCweQueries()\ncwe120.findings.l\n")  

        result = subprocess.run([
            "/home/robin/bin/joern/joern-cli/joern",
            "--script", query_script,
            "--params", f"cpgFile={cpg_path}"
        ], capture_output=True, text=True)

        print(result.stdout)
        return result.stdout


results = []

for item in tqdm(iter_dataset(dataset_root, CWEs, languages)):
    findings = run_joern_analysis(item["source_code"])
    results.append({"findings": findings})

df = pd.DataFrame(results)
df.to_csv("joern_analysis_results.csv", index=False)
print("Saved results to joern_analysis_results.csv")