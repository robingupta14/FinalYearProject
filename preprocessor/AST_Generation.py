import os
from C_Preprocessor import preprocess_c
from CPP_Preprocessor import preprocess_cpp
from CSharp_Preprocessor import preprocess_csharp
from Java_Preprocessor import preprocess_java
from Python_Preprocessor import preprocess_python
from PHP_Preprocessor import preprocess_php
        
DATASET_ROOT = "../../CrossVul"
NEW_DATASET = "../../Preprocessed/NoRename"


CWE_IDS = {"CWE-22", "CWE-79", "CWE-89", "CWE-787"}
LANGUAGES = ['c', 'cpp', 'cs', 'java', 'py', 'php']  


def preprocess(code, lang):
    match lang:
        case 'c':
            return preprocess_c(code)
        case 'cpp':
            return preprocess_cpp(code)
        case 'cs':
            return preprocess_csharp(code)
        case 'java':
            return preprocess_java(code)
        case 'py':
            return preprocess_python(code)
        case 'php':
            return preprocess_php(code)
        case _:
            return code
        
def collect_files_for_cwe(cwe_id):
    total_files = 0
    filepaths = []

    for lang in LANGUAGES:
        lang_dir = os.path.join(DATASET_ROOT, cwe_id, lang)
        if not os.path.isdir(lang_dir):
            continue
        for filename in os.listdir(lang_dir):
            if filename.endswith('.DS_Store'):
                continue
            filepath = os.path.join(lang_dir, filename)
            filepaths.append((lang, filepath, filename))
            total_files += 1

    print(f"[{cwe_id}] Total files to process: {total_files}")
    for idx, (lang, filepath, filename) in enumerate(filepaths, 1):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read().encode()

        out_dir = os.path.join(NEW_DATASET, cwe_id, lang)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)

        preprocessed_code = preprocess(code, lang)

        with open(out_path, 'w', encoding='utf-8') as out_f:
            out_f.write(preprocessed_code)

        print(f"[{cwe_id}] Processed {idx}/{total_files} files", end='\r')
for cwe_id in CWE_IDS:
    collect_files_for_cwe(cwe_id)