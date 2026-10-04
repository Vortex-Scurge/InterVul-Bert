"""Automated dataset download and verification script."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
import urllib.request
from pathlib import Path

from src.data.dataset_loader import compute_file_checksum
from src.utils.logger import get_logger

logger = get_logger("scripts.download_data")

CVEFIXES_URL = "https://huggingface.co/datasets/MickyMike/cvefixes_bigvul/resolve/main/test.csv"
DIVERSEVUL_ZENODO_RECORD = "https://zenodo.org/records/8089445"


def main():
    parser = argparse.ArgumentParser(description="Download and verify vulnerability datasets.")
    parser.add_argument(
        "--data_dir", type=str, default="data/raw", help="Path to raw data directory"
    )
    args = parser.parse_args()

    base_raw = Path(args.data_dir)
    diversevul_dir = base_raw / "diversevul"
    cvefixes_dir = base_raw / "cvefixes"
    other_dir = base_raw / "other"

    diversevul_dir.mkdir(parents=True, exist_ok=True)
    cvefixes_dir.mkdir(parents=True, exist_ok=True)
    other_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"timestamp": "2026-10-04", "datasets": {}}

    # 1. DiverseVul verification
    dv_json = diversevul_dir / "diversevul_20230702.json"
    if dv_json.is_file():
        logger.info(
            f"DiverseVul raw dataset found at {dv_json} ({dv_json.stat().st_size / (1024*1024):.1f} MB)"
        )
        manifest["datasets"]["diversevul"] = {
            "path": str(dv_json),
            "size_bytes": dv_json.stat().st_size,
            "status": "available",
            "source": DIVERSEVUL_ZENODO_RECORD,
        }
    else:
        logger.warning(
            f"DiverseVul raw file not found at {dv_json}. "
            f"Official source: {DIVERSEVUL_ZENODO_RECORD} (download diversevul_20230702.json to {diversevul_dir})"
        )
        manifest["datasets"]["diversevul"] = {
            "status": "missing_manual_download_required",
            "source": DIVERSEVUL_ZENODO_RECORD,
            "expected_path": str(dv_json),
        }

    # 2. CVEfixes download
    cve_csv = cvefixes_dir / "cvefixes_test.csv"
    if not cve_csv.is_file():
        logger.info(f"Downloading CVEfixes test set from {CVEFIXES_URL}...")
        try:
            urllib.request.urlretrieve(CVEFIXES_URL, cve_csv)
            logger.info(
                f"CVEfixes downloaded successfully ({cve_csv.stat().st_size / (1024*1024):.1f} MB)"
            )
        except Exception as e:
            logger.error(f"Failed to download CVEfixes from HF: {e}")
    else:
        logger.info(f"CVEfixes test set found at {cve_csv}")

    if cve_csv.is_file():
        manifest["datasets"]["cvefixes"] = {
            "path": str(cve_csv),
            "size_bytes": cve_csv.stat().st_size,
            "sha256": compute_file_checksum(cve_csv),
            "status": "available",
            "source": CVEFIXES_URL,
        }

    # Save manifest
    manifest_path = base_raw / "dataset_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Dataset manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
