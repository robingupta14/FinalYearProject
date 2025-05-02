# Detecting Vulnerabilities in Source Code Using LLMs

This project uses large language models to detect security vulnerabilities with per CWE-classifiers.

# Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd <your-repo-directory>
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. Download the [CrossVul](https://dl.acm.org/doi/10.1145/3468264.3473122) dataset and place it in a folder named Datasets at the same directory level as this repository. The expected structure is:
   ```bash
   parent-directory/
      ├── this-repo/
      └── CrossVul/
   ```

# Running the Semgrep Analysis:
1. This project uses [Semgrep's CWE Top 25 ruleset](https://semgrep.dev/p/cwe-top-25) which has Pro rules that require authentication. Create a free Semgrep account to obtain a token.

2. Authenticate Semgrep:
     ```bash
     export SEMGREP_APP_TOKEN=your_token_here
     ```

3. Run the analysis script within the semgrep-analysis folder
   ```bash
   chmod +x run_analysis.sh
   ./run_analysis.sh
   ```

Note: It's recommended to run all code on a Linux platform device, as you may run into compatability issues. Development was done on a windows machine using [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install).

# Running the CodeBERT and VulBERTa Analysis:
Running the provided Jupyter Notebooks will conduct the analysis in its entirety. Note that finetuning was done on an RTX 4080 Laptop GPU (12 GB VRAM) and took multiple hours to complete. The experiments with frozen weights however take far less VRAM - 2GB should suffice.

# Running the Deepseek Analysis:
Due to the size of the Deepseek model, an NVIDIA A40 was used (48 GB VRAM) for finetuning. It's unlikely a card with less VRAM will be able to tune the model without crashing, as the model has 1.5 billion parameters and as a result requires lots of VRAM to simply store it. WIthin the deepseek_analysis folder, there is a script to install the [deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B](https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B) model locally, and a script that can be dispatched to the GPU cluster via SLURM. Detailed run instructions are within the deepseek folder.


# Preprocessing:
You must install clang 
```bash
sudo apt install clang`
```

You also need to install the various tree-sitter versions for each language, e.g: 
```bash
git clone https://github.com/tree-sitter/tree-sitter-c
python -c "from tree_sitter import Language; Language.build_library('my-languages.so', ['tree-sitter-c'])"
```
