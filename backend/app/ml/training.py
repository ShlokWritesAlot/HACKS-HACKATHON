import json
import logging
from pathlib import Path
from typing import Any

# Note: We import these conditionally or expect them to be available in the training env.
# In our local environment, PyTorch/Transformers may fail to install, but this is the production training code.
try:
    import numpy as np
    import torch
    from sklearn.metrics import classification_report, confusion_matrix
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments
except ImportError:
    # Dummy mock for static analysis environment
    np, torch, classification_report, confusion_matrix = None, None, None, None
    AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments = None, None, None, None

from app.ml.dataset import create_leakage_free_splits
from app.ml.schemas import ScamCategory

logger = logging.getLogger(__name__)

# Security: Pin a specific trusted multilingual model rather than a dynamic user-provided one.
BASE_MODEL_NAME = "xlm-roberta-base"


class DatasetWrapper:
    def __init__(self, encodings: dict[str, Any], labels: list[int]):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self) -> int:
        return len(self.labels)


def compute_metrics(eval_pred: tuple[np.ndarray, np.ndarray]) -> dict[str, float]:
    """Computes F1, Precision, Recall, and Confusion Matrix during evaluation."""
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    
    # We use macro average to treat all classes equally regardless of support
    report = classification_report(labels, predictions, output_dict=True, zero_division=0)
    conf_matrix = confusion_matrix(labels, predictions).tolist()
    
    return {
        "accuracy": report["accuracy"],
        "macro_f1": report["macro avg"]["f1-score"],
        "macro_precision": report["macro avg"]["precision"],
        "macro_recall": report["macro avg"]["recall"],
        "confusion_matrix": conf_matrix,
    }


def train_model(data: list[dict], output_dir: str = "./model_artifact") -> None:
    """
    Complete pipeline to train the Scam Classifier.
    """
    logger.info("Initializing training pipeline...")
    
    # 1. Dataset splitting (leakage free)
    train_raw, val_raw, test_raw = create_leakage_free_splits(data)
    
    # Label mapping
    categories = [e.value for e in ScamCategory]
    label2id = {label: i for i, label in enumerate(categories)}
    id2label = {i: label for i, label in enumerate(categories)}
    
    # 2. Tokenization
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
    
    def prepare_dataset(raw_samples: list[dict]) -> DatasetWrapper:
        texts = [s["text"] for s in raw_samples]
        labels = [label2id[s["label"]] for s in raw_samples]
        encodings = tokenizer(texts, truncation=True, padding=True, max_length=128)
        return DatasetWrapper(encodings, labels)

    train_dataset = prepare_dataset(train_raw)
    val_dataset = prepare_dataset(val_raw)
    test_dataset = prepare_dataset(test_raw)
    
    # 3. Model setup
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL_NAME,
        num_labels=len(categories),
        id2label=id2label,
        label2id=label2id,
    )
    
    # 4. Training
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=64,
        warmup_steps=500,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        logging_dir="./logs",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )
    
    trainer.train()
    
    # 5. Final Evaluation on completely held-out Test Set
    logger.info("Running final evaluation on test set...")
    test_results = trainer.evaluate(test_dataset)
    
    # Save test results
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(output_dir) / "test_evaluation.json", "w") as f:
        json.dump(test_results, f, indent=2)
        
    logger.info(f"Test Evaluation Results: {test_results}")
    
    # 6. Save final artifact
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info(f"Model saved securely to {output_dir}")
