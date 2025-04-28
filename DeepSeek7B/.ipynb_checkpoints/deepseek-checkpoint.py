from transformers import AdamW, AutoTokenizer, AutoModelForCausalLM, AutoModelForSequenceClassification, Trainer, TrainingArguments, get_cosine_schedule_with_warmup
from tqdm import tqdm
import os
from datasets import Dataset
import random
from sklearn.metrics import precision_recall_fscore_support, accuracy_score, confusion_matrix
import numpy as np
from collections import defaultdict
from tqdm import tqdm
from torch.cuda.amp import autocast


os.environ["CUDA_LAUNCH_BLOCKING"] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = ""
DATASET_ROOT = "../../CrossVul"
ALLOWED_CWE_IDS = {"CWE-22"} # "CWE-22", "CWE-89", "CWE-787"
LANGUAGES = ['c', 'cpp', 'cs', 'html', 'java', 'py', 'php']
SEED = 42
EPOCHS = 5


torch.cuda.empty_cache()  

#model_path = r"C:\Users\robpi\.cache\huggingface\hub\models--deepseek-ai--DeepSeek-R1-Distill-Qwen-7B\snapshots\916b56a44061fd5cd7d6a8fb632557ed4f724f60"
# model_path = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
model_path = "/vol/bitbucket/rg721/models--deepseek-ai--DeepSeek-R1-Distill-Qwen-7B/snapshots/916b56a44061fd5cd7d6a8fb632557ed4f724f60"
tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(model_path, torch_dtype=torch.float16, device_map=None, trust_remote_code=True)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")
model = model.to(device)
print(f"Model is loaded on device: {model.device}")


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
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)

        file_pred_chunks = defaultdict(list)
        file_label = {}

        for pred, label, fname in zip(preds, labels, filenames):
            file_pred_chunks[fname].append(pred)
            file_label[fname] = label

        final_preds, final_labels = [], []
        for fname in file_pred_chunks:
            final_labels.append(file_label[fname])
            vulnerable_chunks = sum(1 for pred in file_pred_chunks[fname] if pred == 1)
            if vulnerable_chunks / len(file_pred_chunks[fname]) >= 0.25:
                final_preds.append(1)
            else:
                final_preds.append(0)

        precision, recall, f1, _ = precision_recall_fscore_support(final_labels, final_preds, average='binary')
        acc = accuracy_score(final_labels, final_preds)
        return {
            'accuracy': acc,
            'precision': precision,
            'recall': recall,
            'f1': f1,
        }

    return compute_file_metrics

def tokenize_example(batch, cwe_id, max_length=16384):
    input_ids_list = []
    attention_mask_list = []
    labels_list = []
    filenames_list = []

    for code, label, filename in zip(batch["code"], batch["label"], batch["filename"]):
        prompt = f"Does this source code contain the following vulnerability {cwe_id}? {code}"
        
        tokens = tokenizer(prompt, return_attention_mask=True, truncation=False)
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


from accelerate import Accelerator
accelerator = Accelerator()
model = model.to(accelerator.device)

for cwe_id in ALLOWED_CWE_IDS:
    print(f"\n--- Training for {cwe_id} ---")
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
    
    print(f"Training new model for {cwe_id}...")
    optimizer = AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    num_train_steps = len(train_dataset) * EPOCHS
    warmup_steps = int(0.1 * num_train_steps)
    scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=warmup_steps, num_training_steps=num_train_steps)
    
    training_args = TrainingArguments(
        output_dir=f"./models/vulberta_{cwe_id}",
        evaluation_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
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
        optimizers=(optimizer, scheduler),
    )

    trainer.train()
    trainer.save_model(f"./models/vulberta_{cwe_id}")


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

        input_ids = torch.tensor([c["input_ids"] for c in chunks]).to(trainer.model.device)
        attention_mask = torch.tensor([c["attention_mask"] for c in chunks]).to(trainer.model.device)

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