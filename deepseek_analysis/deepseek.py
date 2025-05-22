from transformers import AutoTokenizer, AutoModelForCausalLM, get_cosine_schedule_with_warmup
from torch.optim import AdamW
from tqdm import tqdm
import torch
import os
from datasets import Dataset
import random
from sklearn.metrics import precision_recall_fscore_support, accuracy_score
from tqdm import tqdm
import torch.nn.functional as F
from torch.cuda.amp import autocast
from accelerate import Accelerator
import torch.nn as nn
import sys
from transformers import Qwen2ForCausalLM
from transformers.modeling_outputs import SequenceClassifierOutput
from torch.utils.data import DataLoader

from itertools import product

# CLASS DEFS
class CausalLMWithClassifier(nn.Module):
    def __init__(self, base_model, hidden_size=2, classifier=None, num_labels=2):
        super().__init__()
        self.base_model = base_model
        if classifier is None:
            classifier = nn.Linear(hidden_size, 1)
        self.classifier = classifier

    def forward(self, input_ids=None, attention_mask=None, labels=None, **kwargs):
        outputs = self.base_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_hidden_states=True,
            **kwargs
        )
        hidden_states = outputs.hidden_states[-1]
        pooled_output = hidden_states[:, 0, :]
        pooled_output = pooled_output.to(dtype=self.classifier.weight.dtype) 
        logits = self.classifier(pooled_output).squeeze(-1)

        loss = None
        if labels is not None:
            loss = F.binary_cross_entropy_with_logits(logits, labels.float())

        return SequenceClassifierOutput(
            loss=loss,
            logits=logits.unsqueeze(-1),
            hidden_states=outputs.hidden_states,
            attentions=outputs.attentions if hasattr(outputs, "attentions") else None,
        )

    @classmethod
    def from_pretrained(cls, model_dir):
        base_model = AutoModelForCausalLM.from_pretrained(model_dir)

        classifier_path = os.path.join(model_dir, "classifier.pt")
        if not os.path.exists(classifier_path):
            raise FileNotFoundError(f"Classifier head not found at {classifier_path}")
        classifier = torch.load(classifier_path)

        return cls(base_model=base_model, classifier=classifier)

class Tee(object):
    def __init__(self, filename, mode="a"):
        self.file = open(filename, mode)
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
        self.flush()

    def flush(self):
        self.file.flush()
        self.stdout.flush()

    def close(self):
        if self.file:
            self.file.close()
        sys.stdout = self.stdout
        sys.stderr = self.stderr

def collect_files_for_cwe(cwe_id):
    samples = []
    for lang in LANGUAGES:
        lang_dir = os.path.join(DATASET_ROOT, cwe_id, lang)
        if not os.path.isdir(lang_dir):
            continue
        for filename in os.listdir(lang_dir):
            filepath = os.path.join(lang_dir, filename)
            if filename.endswith('.DS_Store'):
                continue
            label = 1 if "bad" in filename.lower() else 0
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            samples.append({
                "filename": filename,
                "code": code,
                "label": label
            })
    print(len(samples))
    return samples

def tokenize_example(batch, cwe_id, max_length=16384):
    tokens = tokenizer(
        [f"Does this source code contain the following vulnerability {cwe_id}? {code}" for code in batch["code"]],
        return_attention_mask=True,
        truncation=True,
        padding="max_length",
        max_length=max_length,
    )
    return {
        "input_ids": tokens["input_ids"],
        "attention_mask": tokens["attention_mask"],
        "label": batch["label"],
    }

def compute_metrics(preds, labels):
    preds = torch.sigmoid(preds).detach().cpu().numpy()
    preds_bin = (preds > 0.5).astype(int)
    labels = labels.cpu().numpy()
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds_bin, average='binary', zero_division=0)
    acc = accuracy_score(labels, preds_bin)
    return {
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

# INITIALISATION
logfile_path = "./training_log.txt"
tee = Tee(logfile_path)
os.environ["CUDA_LAUNCH_BLOCKING"] = "1"
DATASET_ROOT = "/vol/bitbucket/rg721/CrossVul"
ALLOWED_CWE_IDS = {"CWE-22"} # "CWE-22", "CWE-89", "CWE-787"
LANGUAGES = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
SEED = 42
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

model_path = "/vol/bitbucket/rg721/FinalYearProject/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"
base_model = Qwen2ForCausalLM.from_pretrained(
    model_path,
    torch_dtype=torch.float16,
    device_map="auto",
)
hidden_size = base_model.config.hidden_size
model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2)

tokenizer = AutoTokenizer.from_pretrained(model_path, model_max_length=16384, truncation_side="left")
accelerator = Accelerator()
model = model.to(accelerator.device)

# FINETUNING
batch_sizes = [1]
layers = [4, 8, 16]
epochs_list = [5]
learning_rates = [1e-5]
weight_decays = [0]
GRADIENT_ACCUMULATION_STEPS = [8]
cwe_id = "CWE-22"

def run_training(cwe_id, model_path, batch_size, epochs, lr, layers, weight_decay, grad_accumulation_steps, warmup_ratio=0.1):
    model_dir = f"./models/vulberta_{cwe_id}_bs{batch_size}_ep{epochs}_lr{lr}_wd{weight_decay}_accum{grad_accumulation_steps}"
    samples = collect_files_for_cwe(cwe_id)
    random.seed(SEED)
    random.shuffle(samples)

    raw_dataset = Dataset.from_list(samples)
    tokenized_dataset = raw_dataset.map(
        tokenize_example,
        batched=True,
        remove_columns=["filename", "code"],
        fn_kwargs={"cwe_id": cwe_id}
    )
    tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
    train_test = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)
    train_loader = DataLoader(train_test["train"], batch_size=batch_size, shuffle=True)
    eval_loader = DataLoader(train_test["test"], batch_size=1)

    base_model = Qwen2ForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )
    hidden_size = base_model.config.hidden_size
    model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2).to(accelerator.device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    num_train_steps = len(train_loader) * epochs // grad_accumulation_steps
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(warmup_ratio * num_train_steps),
        num_training_steps=num_train_steps
    )

    for param in model.base_model.parameters():
        param.requires_grad = False
    if hasattr(model.base_model, 'transformer'):
        encoder_layers = model.base_model.transformer.h
        if isinstance(encoder_layers, torch.nn.ModuleList):
            for layer in encoder_layers[-layers:]:
                for param in layer.parameters():
                    param.requires_grad = True
    for param in model.classifier.parameters():
        param.requires_grad = True

    model.train()
    best_f1 = 0.0

    for epoch in range(epochs):
        print(f"\nEpoch {epoch + 1}/{epochs}")
        running_loss = 0.0
        optimizer.zero_grad()
        for step, batch in enumerate(tqdm(accelerator.prepare(train_loader))):
            batch = {k: v.to(accelerator.device) for k, v in batch.items()}
            with autocast():
                if 'label' in batch:
                    batch['labels'] = batch.pop('label')
                outputs = model(**batch)
            
            loss = outputs.loss / grad_accumulation_steps
            accelerator.backward(loss)

            if (step + 1) % grad_accumulation_steps == 0:
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            running_loss += loss.item()

        print(f"Training Loss: {running_loss / len(train_loader):.4f}")

        model.eval()
        all_preds = []
        all_labels = []
        with torch.no_grad():
            for batch in tqdm(accelerator.prepare(eval_loader)):
                batch = {k: v.to(accelerator.device) for k, v in batch.items()}
                if 'label' in batch:
                    batch['labels'] = batch.pop('label')
                outputs = model(**batch)
                all_preds.append(outputs.logits.squeeze(-1))
                all_labels.append(batch["labels"])

        preds = torch.cat(all_preds)
        labels = torch.cat(all_labels)
        metrics = compute_metrics(preds, labels)
        f1_score = metrics["f1"]
        print(metrics)

        if f1_score > best_f1:
            print(f"New best F1 score: {f1_score:.4f}. Saving model...")
            best_f1 = f1_score
            model.base_model.save_pretrained(model_dir)
            torch.save(model.classifier, os.path.join(model_dir, "classifier.pt"))

    print(f"Finished training for {cwe_id} with F1: {best_f1:.4f}")
    return best_f1

grid = product(batch_sizes, layers, epochs_list, learning_rates, weight_decays, GRADIENT_ACCUMULATION_STEPS)

results = []
for batch_size, layers, epochs, lr, weight_decay, grad_accumulation_steps in grid:
    print(f"\n=== Running: BS={batch_size}, Layers={layers}, EP={epochs}, LR={lr}, WD={weight_decay}, Grad Accum Steps={grad_accumulation_steps} ===")
    f1 = run_training(cwe_id, model_path, batch_size, epochs, lr, layers, weight_decay, grad_accumulation_steps)
    results.append((batch_size, epochs, lr, layers, weight_decay, grad_accumulation_steps, f1))

results.sort(key=lambda x: -x[-1])
print("\nTop Configurations:")
for config in results[:5]:
    print(f"BS={config[0]}, EP={config[1]}, LR={config[2]}, layers={config[3]}, WD={config[4]}, Grad Accum Steps={config[5]} -> F1={config[6]:.4f}")


# from sklearn.metrics import confusion_matrix, classification_report
# import matplotlib.pyplot as plt
# import seaborn as sns

# def evaluate_model(model_dir, cwe_id="CWE-22"):
#     print(f"\nEvaluating {model_dir}...")
#     model = CausalLMWithClassifier.from_pretrained(model_dir)
#     model = model.to(accelerator.device)
#     model.eval()
#     samples = collect_files_for_cwe(cwe_id)
#     random.seed(SEED)
#     random.shuffle(samples)
#     raw_dataset = Dataset.from_list(samples)
#     tokenized_dataset = raw_dataset.map(
#         tokenize_example,
#         batched=True,
#         remove_columns=["filename", "code"],
#         fn_kwargs={"cwe_id": cwe_id}
#     )
#     tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
#     test_dataset = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)["test"]
#     test_loader = DataLoader(test_dataset, batch_size=1)

#     all_preds, all_labels = [], []
#     with torch.no_grad():
#         for batch in tqdm(accelerator.prepare(test_loader), desc="Evaluating"):
#             batch = {k: v.to(accelerator.device) for k, v in batch.items()}
#             if 'label' in batch:
#                 batch['labels'] = batch.pop('label')
#             outputs = model(**batch)
#             all_preds.append(outputs.logits.squeeze(-1).cpu())
#             all_labels.append(batch["labels"].cpu())

#     preds = torch.cat(all_preds)
#     labels = torch.cat(all_labels)
#     preds_bin = (torch.sigmoid(preds) > 0.5).int()
#     labels = labels.int()

#     print(classification_report(labels, preds_bin, target_names=["good", "bad"], digits=4))
    
#     cm = confusion_matrix(labels, preds_bin)
#     sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["good", "bad"], yticklabels=["good", "bad"])
#     plt.xlabel("Predicted")
#     plt.ylabel("Actual")
#     plt.title(f"Confusion Matrix for {os.path.basename(model_dir)}")
#     plt.tight_layout()
#     plt.savefig(f"{os.path.basename(model_dir)}_confusion_matrix.png")
#     plt.close()

# model_dirs = [
#     "../runs/models/vulberta_CWE-22_bs1_ep5_lr1e-05_wd0_accum4",
#     "../runs/models/vulberta_CWE-22_bs1_ep9_lr1e-05_wd0_accum4",
#     "../runs/models/vulberta_CWE-22_bs1_ep3_lr1e-05_wd0_accum8",
#     "../runs/models/vulberta_CWE-22_bs1_ep3_lr1e-05_wd0_accum2",
#     "../runs/models/vulberta_CWE-22_bs1_ep5_lr1e-05_wd0_accum8",
#     "../runs/models/vulberta_CWE-22_bs1_ep5_lr1e-05_wd0_accum2",
#     "../runs/models/vulberta_CWE-22_bs1_ep9_lr1e-05_wd0_accum2",
#     "../runs/models/vulberta_CWE-22_bs1_ep9_lr1e-05_wd0_accum8",
#     "../runs/models/vulberta_CWE-22_bs1_ep3_lr1e-05_wd0_accum4",
# ]

# for model_dir in model_dirs:
#     evaluate_model(model_dir, cwe_id="CWE-22")

tee.close()