"""Dataset preparation and leakage prevention script."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

from src.data.dataset_loader import DatasetLoader
from src.preprocessing.split_manager import SplitManager
from src.utils.logger import get_logger

logger = get_logger("scripts.prepare_dataset")


def main():
    parser = argparse.ArgumentParser(
        description="Prepare dataset with project-aware splitting and leakage prevention."
    )
    parser.add_argument(
        "--raw_path", type=str, default="data/raw/diversevul/diversevul_20230702.json"
    )
    parser.add_argument(
        "--meta_path",
        type=str,
        default="data/raw/diversevul/diversevul_20230702_metadata.json",
    )
    parser.add_argument("--processed_dir", type=str, default="data/processed")
    parser.add_argument(
        "--max_samples",
        type=int,
        default=3500,
        help="Maximum samples to ingest for balanced subset",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    proc_dir = Path(args.processed_dir)
    proc_dir.mkdir(parents=True, exist_ok=True)

    raw_path = Path(args.raw_path)
    meta_path = Path(args.meta_path)

    # Check if processed splits already exist
    train_file = proc_dir / "train_samples.jsonl"
    val_file = proc_dir / "val_samples.jsonl"
    test_file = proc_dir / "test_samples.jsonl"

    if (
        train_file.is_file()
        and test_file.is_file()
        and (proc_dir / "leakage_report.json").is_file()
    ):
        logger.info(f"Existing processed partitions detected in {proc_dir}. Verifying integrity...")
        train_samples = DatasetLoader.load_jsonl(train_file)
        val_samples = DatasetLoader.load_jsonl(val_file)
        test_samples = DatasetLoader.load_jsonl(test_file)
        leakage_report = SplitManager.verify_no_leakage(train_samples, val_samples, test_samples)
        with open(proc_dir / "leakage_report.json", "w", encoding="utf-8") as f:
            json.dump(leakage_report, f, indent=2)
        logger.info(f"Leakage verification complete. Leak-free: {leakage_report['is_leak_free']}")
        return

    logger.info(f"Ingesting raw DiverseVul dataset from {raw_path}...")
    samples = list(
        DatasetLoader.stream_diversevul(raw_path, meta_path, max_samples=args.max_samples)
    )
    logger.info(
        f"Ingested {len(samples)} samples. Running project-aware deduplication and partitioning..."
    )

    train_samples, val_samples, test_samples, leakage_report = SplitManager.project_aware_split(
        samples, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=args.seed
    )

    DatasetLoader.save_jsonl(train_samples, train_file)
    DatasetLoader.save_jsonl(val_samples, val_file)
    DatasetLoader.save_jsonl(test_samples, test_file)

    with open(proc_dir / "leakage_report.json", "w", encoding="utf-8") as f:
        json.dump(leakage_report, f, indent=2)

    logger.info(
        f"Splits saved: Train={len(train_samples)}, Val={len(val_samples)}, Test={len(test_samples)}"
    )
    logger.info(f"Leakage report: {leakage_report['is_leak_free']}")


if __name__ == "__main__":
    main()
