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
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
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
        base_model_kwargs = kwargs.copy()
        if 'use_cache' not in base_model_kwargs:
            base_model_kwargs['use_cache'] = False

        outputs = self.base_model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_hidden_states=True,
            **base_model_kwargs # Use modified kwargs
        )
        hidden_states = outputs.hidden_states[-1]
        pooled_output = hidden_states[:, 0, :]
        
        input_for_classifier = pooled_output.to(dtype=self.classifier.weight.dtype)
        logits = self.classifier(input_for_classifier).squeeze(-1)

        loss = None
        if labels is not None:
            loss = F.binary_cross_entropy_with_logits(logits, labels.float())

        return SequenceClassifierOutput(
            loss=loss,
            logits=logits.unsqueeze(-1) if logits.ndim == 1 else logits,
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

def collect_files_for_cwe(cwe_id, root):
    samples = []
    for lang in LANGUAGES:
        lang_dir = os.path.join(root, cwe_id, lang)
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
logfile_path = "./test_untrained_log.txt"
tee = Tee(logfile_path)
os.environ["CUDA_LAUNCH_BLOCKING"] = "1"
DATASET_ROOTS = ["/vol/bitbucket/rg721/FinalYearProject/Preprocessed/Rename", 
                 "/vol/bitbucket/rg721/FinalYearProject/Preprocessed/NoRename", 
                 "/vol/bitbucket/rg721/CrossVul"]
TARGET_CWE_IDS = ["CWE-22", "CWE-79", "CWE-89", "CWE-787"]
LANGUAGES = ['c', 'cpp', 'cs', 'java', 'py', 'php']
SEED = 42
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

model_path = "/vol/bitbucket/rg721/FinalYearProject/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"
tokenizer = AutoTokenizer.from_pretrained(model_path, model_max_length=16384, truncation_side="left", trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token


accelerator = Accelerator()
batch_sizes = [1]
epochs_list = [3]
learning_rates = [1e-5]
weight_decays = [0.01]
GRADIENT_ACCUMULATION_STEPS = [8]

def test_untrained(cwe_id, root):
    print(f"\n--- Testing untrained model for CWE-{cwe_id} on dataset: {os.path.basename(root)} ---")

    base_model_instance = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.float16,
        trust_remote_code=True
    )
    
    model_instance = CausalLMWithClassifier(base_model_instance, num_labels=2)
    model_instance = accelerator.prepare(model_instance)

    samples = collect_files_for_cwe(cwe_id, root)
    if not samples:
        print(f"No samples found for CWE-{cwe_id} in {root}. Skipping evaluation.")
        del model_instance
        del base_model_instance
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        return
    random.seed(SEED)
    random.shuffle(samples)

    raw_dataset = Dataset.from_list(samples)
    tokenized_dataset = raw_dataset.map(
        tokenize_example,
        batched=True,
        remove_columns=["filename", "code"],
        fn_kwargs={"cwe_id": cwe_id}
    )

    tokenized_dataset = tokenized_dataset.rename_column("label", "labels")
    tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'labels'])

    test_dataset = tokenized_dataset
    test_loader = DataLoader(test_dataset, batch_size=1)
    test_loader = accelerator.prepare(test_loader)

    all_logits, all_labels = [], []
    model_instance.eval()
    with torch.no_grad():
        for batch in tqdm(test_loader, desc=f"Evaluating {cwe_id} on {os.path.basename(root)}"):
            outputs = model_instance(**batch)
            logits = outputs.logits.view(-1)
            all_logits.append(logits)
            all_labels.append(batch["labels"])

    if not all_logits:
        print("No predictions made, possibly empty test_loader.")
        return

    logits_tensor = torch.cat(all_logits)
    labels_tensor = torch.cat(all_labels)
    logits_tensor_cpu = logits_tensor.cpu()
    labels_tensor_cpu = labels_tensor.cpu()

    preds_probs = torch.sigmoid(logits_tensor_cpu)
    preds_bin = (preds_probs > 0.5).int()
    accuracy = accuracy_score(labels_tensor_cpu, preds_bin)
    precision, recall, f1, _ = precision_recall_fscore_support(labels_tensor_cpu, preds_bin, average='binary', zero_division=0)

    print(f"\nOverall Metrics for CWE-{cwe_id} on {os.path.basename(root)}:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")

    print("\nClassification Report:")
    print(classification_report(labels_tensor_cpu, preds_bin, target_names=["good", "bad"], labels=[0, 1], digits=4, zero_division=0))
    cm = confusion_matrix(labels_tensor_cpu, preds_bin, labels=[0,1])
    print("\nConfusion Matrix (numeric):")
    print(cm)

    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["good", "bad"], yticklabels=["good", "bad"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plot_title = f"Untrained CM: {cwe_id} on {os.path.basename(root)}"
    plt.title(plot_title)
    plt.tight_layout()
    cm_filename = f"untrained_{cwe_id}_{os.path.basename(root)}_confusion_matrix.png"
    plt.savefig(cm_filename)
    print(f"Confusion matrix saved to {cm_filename}")
    plt.close()
    
    del model_instance
    del base_model_instance
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def evaluate_model(model_dir, cwe_id, root):
    print(f"\nEvaluating {model_dir}...")
    global tokenizer
    if tokenizer is None:
        tokenizer = AutoTokenizer.from_pretrained(model_path, model_max_length=16384, truncation_side="left", trust_remote_code=True)
        if tokenizer.pad_token is None: tokenizer.pad_token = tokenizer.eos_token

    model = CausalLMWithClassifier.from_pretrained(model_dir)
    model = accelerator.prepare(model)
    model.eval()
    samples = collect_files_for_cwe(cwe_id, root)
    if not samples:
        print(f"No samples found for {cwe_id} in {root} for evaluation of {model_dir}")
        return
        
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
    test_dataset = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)["test"] 
    test_loader = DataLoader(test_dataset, batch_size=1)
    test_loader = accelerator.prepare(test_loader)

    all_preds_logits, all_labels_list = [], []
    with torch.no_grad():
        for batch in tqdm(test_loader, desc=f"Evaluating {os.path.basename(model_dir)}"):
            if 'label' in batch:
                batch['labels'] = batch.pop('label')
            outputs = model(**batch)
            all_preds_logits.append(outputs.logits.squeeze(-1))
            all_labels_list.append(batch["labels"])

    if not all_preds_logits:
        print(f"No predictions made for {model_dir}.")
        return

    preds_logits_cat = torch.cat(all_preds_logits).cpu()
    labels_cat = torch.cat(all_labels_list).cpu().int()

    preds_bin_cat = (torch.sigmoid(preds_logits_cat) > 0.5).int()

    print(f"\nClassification Report for {os.path.basename(model_dir)} on {cwe_id} ({os.path.basename(root)}):")
    print(classification_report(labels_cat, preds_bin_cat, target_names=["good", "bad"], digits=4, zero_division=0))
    
    cm = confusion_matrix(labels_cat, preds_bin_cat, labels=[0,1])
    print("\nConfusion Matrix (numeric):")
    print(cm)
    
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["good", "bad"], yticklabels=["good", "bad"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(f"CM for {os.path.basename(model_dir)} - {cwe_id} on {os.path.basename(root)}")
    plt.tight_layout()
    cm_eval_filename = f"{os.path.basename(model_dir)}_{cwe_id}_{os.path.basename(root)}_eval_confusion_matrix.png"
    plt.savefig(cm_eval_filename)
    print(f"Evaluation confusion matrix saved to {cm_eval_filename}")
    plt.close()

    del model
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

def set_trainable_layers(model):
    for param in model.parameters():
        param.requires_grad = False
    for param in model.classifier.parameters():
        param.requires_grad = True

def run_training(cwe_id, model_path, batch_size, epochs, lr, layers, weight_decay, grad_accumulation_steps, root, warmup_ratio=0.1):
    model_dir = f"./models/vulberta_{cwe_id}_bs{batch_size}_ep{epochs}_lr{lr}_wd{weight_decay}_accum{grad_accumulation_steps}_layers{layers}_ds{root.split("/")[-1]}"
    best_f1 = 0
    # samples = collect_files_for_cwe(cwe_id, root)
    # random.seed(SEED)
    # random.shuffle(samples)

    # raw_dataset = Dataset.from_list(samples)
    # tokenized_dataset = raw_dataset.map(
    #     tokenize_example,
    #     batched=True,
    #     remove_columns=["filename", "code"],
    #     fn_kwargs={"cwe_id": cwe_id}
    # )
    # tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
    # train_test = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)
    # train_loader = DataLoader(train_test["train"], batch_size=batch_size, shuffle=True)
    # eval_loader = DataLoader(train_test["test"], batch_size=1)

    # base_model = Qwen2ForCausalLM.from_pretrained(
    #     model_path,
    #     torch_dtype=torch.float16,
    #     device_map="auto",
    #     trust_remote_code=True
    # )
    # hidden_size = base_model.config.hidden_size
    # model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2).to(accelerator.device)

    # set_trainable_layers(model)

    # optimizer = AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    # num_train_steps = len(train_loader) * epochs // grad_accumulation_steps
    # scheduler = get_cosine_schedule_with_warmup(
    #     optimizer,
    #     num_warmup_steps=int(warmup_ratio * num_train_steps),
    #     num_training_steps=num_train_steps
    # )

    # model.train()
    # best_f1 = 0.0

    # for epoch in range(epochs):
    #     print(f"\nEpoch {epoch + 1}/{epochs}")
    #     running_loss = 0.0
    #     optimizer.zero_grad()
    #     for step, batch in enumerate(tqdm(accelerator.prepare(train_loader))):
    #         batch = {k: v.to(accelerator.device) for k, v in batch.items()}
    #         with autocast():
    #             if 'label' in batch:
    #                 batch['labels'] = batch.pop('label')
    #             outputs = model(**batch)
            
    #         loss = outputs.loss / grad_accumulation_steps
    #         accelerator.backward(loss)

    #         if (step + 1) % grad_accumulation_steps == 0:
    #             optimizer.step()
    #             scheduler.step()
    #             optimizer.zero_grad()

    #         running_loss += loss.item()

    #     print(f"Training Loss: {running_loss / len(train_loader):.4f}")

    #     model.eval()
    #     all_preds = []
    #     all_labels = []
    #     with torch.no_grad():
    #         for batch in tqdm(accelerator.prepare(eval_loader)):
    #             batch = {k: v.to(accelerator.device) for k, v in batch.items()}
    #             if 'label' in batch:
    #                 batch['labels'] = batch.pop('label')
    #             outputs = model(**batch)
    #             all_preds.append(outputs.logits.squeeze(-1))
    #             all_labels.append(batch["labels"])

    #     preds = torch.cat(all_preds)
    #     labels = torch.cat(all_labels)
    #     metrics = compute_metrics(preds, labels)
    #     f1_score = metrics["f1"]
    #     print(metrics)

    #     if f1_score > best_f1:
    #         print(f"New best F1 score: {f1_score:.4f  }. Saving model...")
    #         best_f1 = f1_score
    #         model.base_model.save_pretrained(model_dir)
    #         torch.save(model.classifier, os.path.join(model_dir, "classifier.pt"))

    # print(f"Finished training for {cwe_id} with F1: {best_f1:.4f}")
    # evaluate_model(model_dir, cwe_id, root)
    test_untrained(cwe_id, root)
    return best_f1

skip_combinations = [
    ("CWE-22", "CrossVul"),
    ("CWE-79", "CrossVul"),
    ("CWE-79", "NoRename"), 
    ("CWE-89", "CrossVul"),
    ("CWE-787", "CrossVul")
]

print("\nStarting batch testing of untrained models...")

for cwe_id_to_test in TARGET_CWE_IDS:
    for dataset_root_path in DATASET_ROOTS:
        current_dataset_basename = os.path.basename(dataset_root_path)
        
        if (cwe_id_to_test, current_dataset_basename) in skip_combinations:
            print(f"\nSKIPPING: CWE {cwe_id_to_test} on dataset {current_dataset_basename} (path: {dataset_root_path}) as per provided list.")
            continue
        test_untrained(cwe_id=cwe_id_to_test, root=dataset_root_path)

print("\nFinished batch testing of untrained models.")

# grid = product(batch_sizes, layers, epochs_list, learning_rates, weight_decays, GRADIENT_ACCUMULATION_STEPS)
# results = []
# for cwe_id_loop_var in TARGET_CWE_IDS: # Example: if you wanted to loop CWEs in grid
#   for root_loop_var in DATASET_ROOTS:
#     for batch_size_p, layers_p, epochs_p, lr_p, weight_decay_p, grad_accumulation_steps_p in grid:
#       # Check skips if necessary for training runs too
#       print(f"\n=== Potentially Running Training: CWE={cwe_id_loop_var}, Root={os.path.basename(root_loop_var)}, BS={batch_size_p}, EP={epochs_p}, LR={lr_p} ===")
#       # f1 = run_training(cwe_id_loop_var, model_path, batch_size_p, epochs_p, lr_p, layers_p, weight_decay_p, grad_accumulation_steps_p, root_loop_var)
#       # results.append((cwe_id_loop_var, os.path.basename(root_loop_var), batch_size_p, epochs_p, lr_p, layers_p, weight_decay_p, grad_accumulation_steps_p, f1))

# results.sort(key=lambda x: -x[-1]) # Sort by F1 score
# print("\nTop Configurations (if training was run):")
# for config in results[:5]:
#   print(f"CWE={config[0]}, Dataset={config[1]}, BS={config[2]}, EP={config[3]}, LR={config[4]}, Layers={config[5]}, WD={config[6]}, GradAccum={config[7]} -> F1={config[8]:.4f}")

tee.close()
print("Log saved to ./test_untrained_log.txt")