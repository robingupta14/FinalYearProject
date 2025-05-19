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
from accelerate import Accelerator
import torch.nn as nn
import sys
from transformers import Qwen2ForCausalLM
from transformers.modeling_outputs import SequenceClassifierOutput
from torch.utils.data import DataLoader
import csv

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
EPOCHS = 3
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
EPOCHS_LIST = [3, 5]
LEARNING_RATES = [1e-5, 2e-5]
WEIGHT_DECAYS = [0.01]
BATCH_SIZES = [4, 8, 16]
LAYERS_TO_UNFREEZE = [0, 1, 2, 4]

for cwe_id in ALLOWED_CWE_IDS:
    print(f"\n--- Grid Search for {cwe_id} ---")
    samples = collect_files_for_cwe(cwe_id)
    random.seed(SEED)
    random.shuffle(samples)
    raw_dataset = Dataset.from_list(samples)
    tokenized_dataset = raw_dataset.map(lambda batch: tokenize_example(batch, cwe_id), batched=True, remove_columns=["filename", "code"])
    tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label'])
    train_test = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)
    train_dataset = train_test["train"]
    eval_dataset = train_test["test"]

    log_path = f"./models/deepseek_{cwe_id}/gridsearch_results.csv"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["epochs", "lr", "weight_decay", "batch_size", "unfrozen_layers", "precision", "recall", "f1", "accuracy"])

    best_f1 = -1
    best_dir = None

    for epochs in EPOCHS_LIST:
        for lr in LEARNING_RATES:
            for wd in WEIGHT_DECAYS:
                for batch_size in BATCH_SIZES:
                    for unfrozen in LAYERS_TO_UNFREEZE:
                        print(f"\nRunning with epochs={epochs}, lr={lr}, wd={wd}, batch_size={batch_size}, unfrozen_layers={unfrozen}")

                        base_model = Qwen2ForCausalLM.from_pretrained(
                            model_path,
                            torch_dtype=torch.float16,
                            device_map="auto",
                        )
                        hidden_size = base_model.config.hidden_size
                        model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2)

                        for param in model.base_model.parameters():
                            param.requires_grad = False

                        if hasattr(model.base_model, 'transformer'):
                            encoder_layers = model.base_model.transformer.h
                            if isinstance(encoder_layers, torch.nn.ModuleList):
                                for layer in encoder_layers[-unfrozen:]:
                                    for param in layer.parameters():
                                        param.requires_grad = True

                        for param in model.classifier.parameters():
                            param.requires_grad = True

                        optimizer = AdamW(model.parameters(), lr=lr, weight_decay=wd)
                        num_train_steps = (len(train_dataset) // batch_size) * epochs
                        warmup_steps = int(0.1 * num_train_steps)
                        scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=warmup_steps, num_training_steps=num_train_steps)

                        accelerator = Accelerator()
                        model, optimizer, train_dataset, eval_dataset = accelerator.prepare(model, optimizer, train_dataset, eval_dataset)

                        output_dir = f"./models/deepseek_{cwe_id}/gridsearch/ep{epochs}_lr{lr}_wd{wd}_bs{batch_size}_uf{unfrozen}"
                        os.makedirs(output_dir, exist_ok=True)

                        for epoch in range(epochs):
                            model.train()
                            train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
                            for batch in tqdm(train_loader, desc=f"Epoch {epoch+1}/{epochs}"):
                                optimizer.zero_grad()
                                with accelerator.autocast():
                                    outputs = model(
                                        input_ids=batch["input_ids"],
                                        attention_mask=batch["attention_mask"],
                                        labels=batch["label"]
                                    )
                                    loss = outputs.loss
                                accelerator.backward(loss)
                                optimizer.step()
                                scheduler.step()

                        model.eval()
                        eval_loader = DataLoader(eval_dataset, batch_size=batch_size)
                        all_preds = []
                        all_labels = []
                        with torch.no_grad():
                            for batch in eval_loader:
                                outputs = model(
                                    input_ids=batch["input_ids"],
                                    attention_mask=batch["attention_mask"]
                                )
                                all_preds.append(outputs.logits.squeeze(-1).detach())
                                all_labels.append(batch["label"])

                        preds = torch.cat(all_preds)
                        labels = torch.cat(all_labels)
                        metrics = compute_metrics(preds, labels)

                        with open(log_path, "a", newline="") as f:
                            writer = csv.writer(f)
                            writer.writerow([epochs, lr, wd, batch_size, unfrozen, metrics['precision'], metrics['recall'], metrics['f1'], metrics['accuracy']])

                        if metrics['f1'] > best_f1:
                            best_f1 = metrics['f1']
                            best_dir = output_dir
                            model_to_save = accelerator.unwrap_model(model)
                            model_to_save.base_model.save_pretrained(best_dir + "/final")
                            torch.save(model_to_save.classifier, best_dir + "/final/classifier.pt")

    if best_dir is not None:
        os.system(f"cp -r {best_dir}/final ./models/deepseek_{cwe_id}/best_model")
        print(f"\nBest model for {cwe_id} saved from: {best_dir} with F1={best_f1:.4f}")

tee.close()