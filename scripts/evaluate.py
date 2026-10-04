"""Evaluate trained model checkpoint on test splits."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

import pandas as pd
import torch
from torch.utils.data import DataLoader

from src.data.dataset_loader import DatasetLoader
from src.evaluation.metrics import VulnerabilityMetrics
from src.models.model_factory import ModelFactory
from src.preprocessing.tokenizer_wrapper import CodeDataset
from src.utils.config import load_config
from src.utils.logger import get_logger

logger = get_logger("scripts.evaluate")


def main():
    parser = argparse.ArgumentParser(description="Evaluate model on test dataset.")
    parser.add_argument("--config", type=str, default="configs/codebert_baseline.yaml")
    parser.add_argument("--checkpoint", type=str, default=None, help="Override model directory")
    parser.add_argument("--test_split", type=str, default=None, help="Override test data split")
    parser.add_argument("--output_dir", type=str, default="results/baseline")
    args = parser.parse_args()

    cfg = load_config(args.config)
    device = ModelFactory.get_device()

    checkpoint_dir = args.checkpoint or cfg["model"].get("save_dir", "models/codebert")
    test_path = args.test_split or cfg["data"]["test_split"]
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading model from {checkpoint_dir}...")
    model, tokenizer = ModelFactory.load_codebert(checkpoint_dir, device=device)
    model.eval()

    test_samples = DatasetLoader.load_jsonl(
        test_path, max_samples=cfg["data"].get("max_test_samples", 500)
    )
    logger.info(f"Evaluating {len(test_samples)} samples from {test_path}...")

    test_ds = CodeDataset(test_samples, tokenizer, max_length=cfg["model"].get("max_length", 512))
    test_loader = DataLoader(
        test_ds, batch_size=cfg["training"].get("batch_size", 16), shuffle=False
    )

    y_true = []
    y_pred = []
    y_probs = []
    predictions = []

    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"]

            out = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(out["logits"], dim=-1)
            preds = torch.argmax(probs, dim=-1)

            y_true.extend(labels.tolist())
            y_pred.extend(preds.cpu().tolist())
            y_probs.extend(probs[:, 1].cpu().tolist())

    metrics = VulnerabilityMetrics.compute_all(y_true, y_pred, y_probs)

    for i, s in enumerate(test_samples):
        predictions.append(
            {
                "sample_id": s.sample_id,
                "prediction": y_pred[i],
                "probability": round(y_probs[i], 4),
                "label": "vulnerable" if y_pred[i] == 1 else "safe",
                "ground_truth": y_true[i],
                "project": s.project,
                "cwe": s.cwe,
            }
        )

    with open(out_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    pd.DataFrame(predictions).to_csv(out_dir / "test_predictions.csv", index=False)
    VulnerabilityMetrics.save_confusion_matrix_plot(
        metrics["confusion_matrix"],
        out_dir / "confusion_matrix.png",
        title="Model Evaluation Confusion Matrix",
    )

    logger.info(f"Evaluation Metrics: {metrics}")


if __name__ == "__main__":
    main()
