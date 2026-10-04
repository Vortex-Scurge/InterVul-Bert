"""Train / Evaluate GraphCodeBERT on DiverseVul across context strategies."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

from src.data.dataset_loader import DatasetLoader
from src.models.model_factory import ModelFactory
from src.preprocessing.tokenizer_wrapper import CodeDataset
from src.training.trainer import VulnerabilityTrainer, set_seed
from src.utils.config import load_config
from src.utils.logger import get_logger

logger = get_logger("scripts.train_graphcodebert")


def main():
    parser = argparse.ArgumentParser(description="Train/Evaluate GraphCodeBERT model.")
    parser.add_argument("--config", type=str, default="configs/graphcodebert.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    seed = 42
    set_seed(seed)
    device = ModelFactory.get_device()

    # Load test split
    test_file = Path(cfg["data"]["test_split"])
    max_test = cfg["data"].get("max_test_samples", 400)
    test_samples = DatasetLoader.load_jsonl(test_file, max_samples=max_test)

    # Check for fine-tuned checkpoint or pretrained base
    finetuned_checkpoint = cfg["model"].get("finetuned_checkpoint", "microsoft/graphcodebert-base")
    save_dir = Path(cfg["model"].get("save_dir", "models/graphcodebert"))

    logger.info(f"Loading GraphCodeBERT from {finetuned_checkpoint}...")
    model, tokenizer = ModelFactory.load_graphcodebert(finetuned_checkpoint, device=device)
    model.eval()

    # Evaluate on test set
    test_ds = CodeDataset(test_samples, tokenizer, max_length=cfg["model"].get("max_length", 512))
    from torch.utils.data import DataLoader

    test_loader = DataLoader(test_ds, batch_size=16, shuffle=False)

    trainer = VulnerabilityTrainer(
        model=model, tokenizer=tokenizer, device=device, save_dir=save_dir
    )
    metrics = trainer.evaluate(test_loader)

    res_dir = Path("results/interprocedural")
    res_dir.mkdir(parents=True, exist_ok=True)

    with open(res_dir / "graphcodebert_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"GraphCodeBERT Evaluation complete: {metrics}")


if __name__ == "__main__":
    main()
