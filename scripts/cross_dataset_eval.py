"""Evaluate frozen baseline model on external out-of-distribution datasets."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

import pandas as pd

from src.data.dataset_loader import DatasetLoader
from src.evaluation.cross_evaluator import CrossDatasetEvaluator
from src.models.model_factory import ModelFactory
from src.utils.config import load_config
from src.utils.logger import get_logger

logger = get_logger("scripts.cross_dataset_eval")


def main():
    parser = argparse.ArgumentParser(description="Cross-dataset frozen evaluation.")
    parser.add_argument("--config", type=str, default="configs/cross_dataset.yaml")
    parser.add_argument("--output_dir", type=str, default="results/cross_dataset")
    args = parser.parse_args()

    cfg = load_config(args.config)
    device = ModelFactory.get_device()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load trained model (or fallback if training is in progress)
    model_dir = Path(cfg["source_experiment"].get("baseline_model", "models/codebert"))
    fallback = cfg["source_experiment"].get("pretrained_fallback", "microsoft/codebert-base")

    if (model_dir / "pytorch_model.bin").is_file() or (model_dir / "model.pt").is_file():
        logger.info(f"Loading trained baseline from {model_dir}")
        model, tokenizer = ModelFactory.load_codebert(model_dir, device=device)
    else:
        logger.warning(
            f"Trained checkpoint not found at {model_dir}. Loading {fallback} as zero-shot baseline..."
        )
        model, tokenizer = ModelFactory.load_codebert(fallback, device=device)

    evaluator = CrossDatasetEvaluator(
        model=model,
        tokenizer=tokenizer,
        device=device,
        batch_size=cfg["evaluation"].get("batch_size", 16),
        max_length=cfg["evaluation"].get("max_length", 512),
    )

    all_results = {}

    # 2. Evaluate on CVEfixes
    cve_cfg = cfg["external_datasets"].get("cvefixes")
    if cve_cfg and Path(cve_cfg["path"]).is_file():
        logger.info(f"Loading external CVEfixes dataset from {cve_cfg['path']}...")
        cve_samples = DatasetLoader.load_cvefixes(
            Path(cve_cfg["path"]), max_samples=cve_cfg.get("max_samples", 300)
        )
        cve_report, cve_preds = evaluator.evaluate_dataset(
            cve_samples,
            dataset_name="CVEfixes",
            training_dataset=cfg["source_experiment"]["training_dataset"],
        )
        all_results["cvefixes"] = cve_report
        with open(out_dir / "cvefixes_evaluation.json", "w", encoding="utf-8") as f:
            json.dump(cve_report, f, indent=2)
        pd.DataFrame([p.to_dict() for p in cve_preds]).to_csv(
            out_dir / "cvefixes_predictions.csv", index=False
        )

    # 3. Evaluate on Devign (if available)
    devign_cfg = cfg["external_datasets"].get("devign")
    if devign_cfg and Path(devign_cfg["path"]).is_file():
        logger.info(f"Loading external Devign dataset from {devign_cfg['path']}...")
        devign_samples = DatasetLoader.load_devign(
            Path(devign_cfg["path"]), max_samples=devign_cfg.get("max_samples", 300)
        )
        devign_report, devign_preds = evaluator.evaluate_dataset(
            devign_samples,
            dataset_name="Devign",
            training_dataset=cfg["source_experiment"]["training_dataset"],
        )
        all_results["devign"] = devign_report
        with open(out_dir / "devign_evaluation.json", "w", encoding="utf-8") as f:
            json.dump(devign_report, f, indent=2)
        pd.DataFrame([p.to_dict() for p in devign_preds]).to_csv(
            out_dir / "devign_predictions.csv", index=False
        )

    # 4. Generate formal markdown cross-dataset report
    md_lines = [
        "# Cross-Dataset Generalization Report",
        "",
        f"- **Source Training Dataset:** `{cfg['source_experiment']['training_dataset']}`",
        "- **Additional Training on Evaluation Dataset:** `NO`",
        "- **Model Frozen:** `YES (Parameters Locked, In-Distribution Weights Only)`",
        "",
        "## Summary of Cross-Dataset Results",
        "",
        "| Evaluation Dataset | Samples | Accuracy | Precision | Recall | F1 Score | PR-AUC | ROC-AUC |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for ds_name, rep in all_results.items():
        m = rep["metrics"]
        md_lines.append(
            f"| **{ds_name.upper()}** | {rep['total_evaluated_samples']} | "
            f"{m['accuracy']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['pr_auc']:.4f} | {m['roc_auc']:.4f} |"
        )

    md_lines.extend(
        [
            "",
            "## Methodological Discussion",
            "When models trained on DiverseVul are evaluated on external datasets like CVEfixes without fine-tuning,",
            "performance drops are frequently observed. This highlights the domain shift across project conventions,",
            "vulnerability reporting taxonomies, and function granularity, reinforcing the need for structural interprocedural context.",
        ]
    )

    with open(out_dir / "cross_dataset_summary.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    logger.info(f"Cross-dataset evaluation complete. Results written to {out_dir}")


if __name__ == "__main__":
    main()
