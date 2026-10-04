"""Train CodeBERT baseline on DiverseVul binary vulnerability classification."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

import pandas as pd

from src.data.dataset_loader import DatasetLoader
from src.evaluation.metrics import VulnerabilityMetrics
from src.models.model_factory import ModelFactory
from src.training.trainer import VulnerabilityTrainer, set_seed
from src.utils.config import load_config
from src.utils.logger import get_logger

logger = get_logger("scripts.train_codebert")


def main():
    parser = argparse.ArgumentParser(description="Train CodeBERT baseline model.")
    parser.add_argument("--config", type=str, default="configs/codebert_baseline.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    seed = cfg["training"].get("seed", 42)
    set_seed(seed)

    device = ModelFactory.get_device()
    logger.info(f"Target execution device: {device}")

    # Load dataset splits
    train_file = Path(cfg["data"]["train_split"])
    val_file = Path(cfg["data"]["val_split"])
    test_file = Path(cfg["data"]["test_split"])

    max_train = cfg["data"].get("max_train_samples", 2000)
    max_val = cfg["data"].get("max_val_samples", 400)
    max_test = cfg["data"].get("max_test_samples", 400)

    train_samples = DatasetLoader.load_jsonl(train_file, max_samples=max_train)
    val_samples = DatasetLoader.load_jsonl(val_file, max_samples=max_val)
    test_samples = DatasetLoader.load_jsonl(test_file, max_samples=max_test)

    logger.info(
        f"Loaded partitions: Train={len(train_samples)}, Val={len(val_samples)}, Test={len(test_samples)}"
    )

    # Load model and tokenizer
    save_dir = Path(cfg["model"].get("save_dir", "models/codebert"))
    pretrained_name = cfg["model"].get("pretrained_model", "microsoft/codebert-base")

    model, tokenizer = ModelFactory.load_codebert(pretrained_name, device=device)

    # Initialize trainer
    trainer = VulnerabilityTrainer(
        model=model, tokenizer=tokenizer, device=device, save_dir=save_dir
    )

    # Train
    trainer.train(
        train_samples=train_samples,
        val_samples=val_samples,
        num_epochs=cfg["training"].get("num_epochs", 2),
        batch_size=cfg["training"].get("batch_size", 16),
        learning_rate=float(cfg["training"].get("learning_rate", 2e-5)),
        weight_decay=float(cfg["training"].get("weight_decay", 0.01)),
        warmup_ratio=float(cfg["training"].get("warmup_ratio", 0.1)),
        max_length=cfg["model"].get("max_length", 512),
        seed=seed,
    )

    # Evaluate on held-out test split
    logger.info(f"Evaluating best checkpoint on held-out test set ({len(test_samples)} samples)...")
    from torch.utils.data import DataLoader

    from src.preprocessing.tokenizer_wrapper import CodeDataset

    test_ds = CodeDataset(test_samples, tokenizer, max_length=cfg["model"].get("max_length", 512))
    test_loader = DataLoader(
        test_ds, batch_size=cfg["training"].get("batch_size", 16), shuffle=False
    )
    test_metrics = trainer.evaluate(test_loader)

    # Save baseline evaluation metrics
    res_dir = Path(cfg["evaluation"].get("results_dir", "results/baseline"))
    res_dir.mkdir(parents=True, exist_ok=True)

    with open(res_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(test_metrics, f, indent=2)

    # Save confusion matrix plot
    VulnerabilityMetrics.save_confusion_matrix_plot(
        test_metrics["confusion_matrix"],
        res_dir / "confusion_matrix.png",
        title="CodeBERT Baseline Confusion Matrix (DiverseVul Test)",
    )

    # Save detailed prediction samples
    predictions = []
    for s in test_samples:
        pred_out = model.predict_sample(s.code, tokenizer, sample_id=s.sample_id, device=device)
        pred_dict = pred_out.to_dict()
        pred_dict["ground_truth"] = s.target
        predictions.append(pred_dict)

    pd.DataFrame(predictions).to_csv(res_dir / "test_predictions.csv", index=False)

    logger.info("Baseline training and evaluation complete.")
    logger.info(
        f"Test Results: Accuracy={test_metrics['accuracy']:.4f} | F1={test_metrics['f1']:.4f} | "
        f"PR-AUC={test_metrics['pr_auc']:.4f} | ROC-AUC={test_metrics['roc_auc']:.4f}"
    )


if __name__ == "__main__":
    main()
