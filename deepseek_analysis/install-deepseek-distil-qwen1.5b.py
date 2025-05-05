from huggingface_hub import snapshot_download

model_id = "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"
target_dir = "../deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"

snapshot_download(
    repo_id=model_id,
    local_dir=target_dir,
    local_dir_use_symlinks=False
)

print("Model downloaded and loaded into:", target_dir)