from transformers import AutoTokenizer, AutoModelForCausalLM, AutoModelForSequenceClassification, Trainer, TrainingArguments, get_cosine_schedule_with_warmup
from torch.optim import AdamW
from tqdm import tqdm
import torch
import os
from datasets import Dataset
import random
from sklearn.metrics import precision_recall_fscore_support, accuracy_score, confusion_matrix
import numpy as np
from collections import defaultdict
from tqdm import tqdm
import torch.nn.functional as F
from torch.cuda.amp import autocast
from accelerate import Accelerator, DataLoaderConfiguration
import torch.nn as nn
import sys
import os
from transformers import Qwen2ForCausalLM
from transformers.modeling_outputs import SequenceClassifierOutput

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

logfile_path = "./training_log.txt"
tee = Tee(logfile_path)



os.environ["CUDA_LAUNCH_BLOCKING"] = "1"
DATASET_ROOT = "/vol/bitbucket/rg721/CrossVul"
ALLOWED_CWE_IDS = {"CWE-22"} # "CWE-22", "CWE-89", "CWE-787"
LANGUAGES = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
SEED = 42
EPOCHS = 5

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

model_path = "/vol/bitbucket/rg721/FinalYearProject/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"

base_model = Qwen2ForCausalLM.from_pretrained(
    model_path,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)
hidden_size = base_model.config.hidden_size
model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2)
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True, model_max_length=16384, truncation_side="left")


class FileAwareTrainer(Trainer):
    def __init__(self, *args, eval_dataset_filenames=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.eval_dataset_filenames = eval_dataset_filenames

    def evaluate(self, eval_dataset=None, **kwargs):
        output = super().evaluate(eval_dataset=eval_dataset, **kwargs)
        self._last_eval_preds = kwargs.get('preds', None)
        return output

    def predict(self, test_dataset, **kwargs):
        self.eval_dataset_filenames = test_dataset['filename']
        return super().predict(test_dataset, **kwargs)

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

def compute_file_metrics_builder(filenames):
    def compute_file_metrics(eval_pred):
        preds = eval_pred.predictions
        labels = eval_pred.label_ids

        if isinstance(preds, np.ndarray) and preds.ndim > 1:
            preds = np.argmax(preds, axis=-1)
        preds = np.asarray(preds).flatten()
        labels = np.asarray(labels).flatten()

        global eval_filenames
        if 'eval_filenames' not in globals():
            raise ValueError("Global variable `eval_filenames` not set. Set it to list of filenames before eval.")

        filenames = eval_filenames
        if isinstance(filenames, str) or not hasattr(filenames, '__len__'):
            filenames = [filenames]

        if len(filenames) != len(preds):
            raise ValueError(f"Mismatch: {len(filenames)=}, {len(preds)=}, {len(labels)=}")

        metrics = []
        for pred, label, fname in zip(preds, labels, filenames):
            metrics.append({
                "filename": fname,
                "prediction": int(pred),
                "label": int(label),
                "tp": int(pred == 1 and label == 1),
                "fp": int(pred == 1 and label == 0),
                "tn": int(pred == 0 and label == 0),
                "fn": int(pred == 0 and label == 1),
            })

        tp = sum(m["tp"] for m in metrics)
        fp = sum(m["fp"] for m in metrics)
        tn = sum(m["tn"] for m in metrics)
        fn = sum(m["fn"] for m in metrics)

        precision = tp / (tp + fp + 1e-8)
        recall = tp / (tp + fn + 1e-8)
        f1 = 2 * precision * recall / (precision + recall + 1e-8)
        accuracy = (tp + tn) / (tp + tn + fp + fn + 1e-8)

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }


def tokenize_example(batch, cwe_id, max_length=16384):
    input_ids_list = []
    attention_mask_list = []
    labels_list = []
    filenames_list = []

    for code, label, filename in zip(batch["code"], batch["label"], batch["filename"]):
        prompt = f"Does this source code contain the following vulnerability {cwe_id}? {code}"
        
        tokens = tokenizer(prompt, return_attention_mask=True, truncation=True, padding="max_length", max_length=16384)
        input_ids = tokens["input_ids"]
        attention_mask = tokens["attention_mask"]

        for i in range(0, len(input_ids), max_length):
            chunk_ids = input_ids[i:i + max_length]
            chunk_mask = attention_mask[i:i + max_length]

            pad_len = max_length - len(chunk_ids)
            if pad_len > 0:
                chunk_ids += [tokenizer.pad_token_id] * pad_len
                chunk_mask += [0] * pad_len

            input_ids_list.append(chunk_ids)
            attention_mask_list.append(chunk_mask)
            labels_list.append(label)
            filenames_list.append(filename)

    return {
        "input_ids": input_ids_list,
        "attention_mask": attention_mask_list,
        "label": labels_list,
        "filename": filenames_list
    }

accelerator = Accelerator()
model = model.to(accelerator.device)

for cwe_id in ALLOWED_CWE_IDS:
    print(f"\n--- Processing for {cwe_id} ---")
    model_dir = f"./models/vulberta_{cwe_id}"
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
    tokenized_dataset.set_format(type='torch', columns=['input_ids', 'attention_mask', 'label', 'filename'])
    train_test = tokenized_dataset.train_test_split(test_size=0.2, seed=SEED)
    train_dataset = train_test["train"]
    eval_dataset = train_test["test"]

    base_model = Qwen2ForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )

    model = CausalLMWithClassifier(base_model, hidden_size, num_labels=2)
    model = model.to(accelerator.device)

    optimizer = AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    num_train_steps = len(train_dataset) * EPOCHS
    warmup_steps = int(0.1 * num_train_steps)
    scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=warmup_steps, num_training_steps=num_train_steps)

    training_args = TrainingArguments(
        output_dir=model_dir,
        eval_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=8,
        bf16=True,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        remove_unused_columns=False,
    )

    trainer = FileAwareTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        compute_metrics=compute_file_metrics_builder(eval_dataset["filename"]),
        optimizers=(optimizer, scheduler)
    )
    
    if os.path.exists(model_dir):
        print(f"Found existing model at {model_dir}. Loading...")
        model = CausalLMWithClassifier.from_pretrained(model_dir)
        model = model.to(accelerator.device)
        continue 
    else:
        print(f"No existing model found at {model_dir}. Finetuning...")

        for param in model.base_model.parameters():
            param.requires_grad = False
        for param in model.classifier.parameters():
            param.requires_grad = True

        trainer.train()
        model.base_model.save_pretrained(model_dir)
        torch.save(model.classifier, os.path.join(model_dir, "classifier.pt"))


def predict_with_chunk_voting(trainer, raw_samples, chunk_size=512, stride=256):
    true_labels = []
    pred_labels = []

    for example in tqdm(raw_samples, desc="Evaluating with chunk voting"):
        label = example["label"]
        true_labels.append(label)

        tokens = tokenizer(example["code"], return_attention_mask=True, truncation=False)
        input_ids = tokens["input_ids"]
        attention_mask = tokens["attention_mask"]

        chunks = []
        for i in range(0, len(input_ids), stride):
            chunk_ids = input_ids[i:i + chunk_size]
            chunk_mask = attention_mask[i:i + chunk_size]

            chunks.append({
                "input_ids": chunk_ids,
                "attention_mask": chunk_mask,
            })

        if not chunks:
            pred_labels.append(0)
            continue

        max_len = max(len(c["input_ids"]) for c in chunks)
        for chunk in chunks:
            pad_len = max_len - len(chunk["input_ids"])
            chunk["input_ids"] += [tokenizer.pad_token_id] * pad_len
            chunk["attention_mask"] += [0] * pad_len

        device = next(trainer.model.parameters()).device
        input_ids = torch.tensor([c["input_ids"] for c in chunks]).to(device)
        attention_mask = torch.tensor([c["attention_mask"] for c in chunks]).to(device)

        with torch.no_grad():
            outputs = trainer.model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            preds = torch.argmax(logits, dim=1).cpu().numpy()

        file_pred = 1 if (preds.mean() > 0.2) else 0
        pred_labels.append(file_pred)

    return true_labels, pred_labels

true_labels, pred_labels = predict_with_chunk_voting(trainer, samples) 
precision, recall, f1, _ = precision_recall_fscore_support(true_labels, pred_labels, average='binary', zero_division=0)
acc = accuracy_score(true_labels, pred_labels)

print(f"Metrics for {cwe_id}:")
print({
    'accuracy': acc,
    'precision': precision,
    'recall': recall,
    'f1': f1,
})

print(f"\nConfusion Matrix for {cwe_id}:")
print(confusion_matrix(true_labels, pred_labels))
tee.close()