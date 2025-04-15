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
└── Datasets/
  └── crossvul/
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
