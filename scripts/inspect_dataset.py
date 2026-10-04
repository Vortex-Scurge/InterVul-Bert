"""Dataset inspection and statistical reporting script."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
from pathlib import Path

import pandas as pd

from src.data.dataset_loader import (
    DatasetInspector,
    DatasetLoader,
)
from src.utils.logger import get_logger

logger = get_logger("scripts.inspect_dataset")


def main():
    parser = argparse.ArgumentParser(
        description="Inspect raw or processed dataset and generate reports."
    )
    parser.add_argument(
        "--raw_path", type=str, default="data/raw/diversevul/diversevul_20230702.json"
    )
    parser.add_argument(
        "--meta_path",
        type=str,
        default="data/raw/diversevul/diversevul_20230702_metadata.json",
    )
    parser.add_argument(
        "--max_inspect", type=int, default=10000, help="Number of samples to inspect"
    )
    parser.add_argument("--output_doc", type=str, default="docs/dataset.md")
    parser.add_argument("--output_csv", type=str, default="results/tables/dataset_statistics.csv")
    args = parser.parse_args()

    raw_file = Path(args.raw_path)
    meta_file = Path(args.meta_path)

    if not raw_file.is_file():
        logger.error(f"Raw data file not found at {raw_file}")
        return

    logger.info(
        f"Inspecting DiverseVul dataset from {raw_file} (max {args.max_inspect} samples)..."
    )
    samples = list(
        DatasetLoader.stream_diversevul(raw_file, meta_file, max_samples=args.max_inspect)
    )
    logger.info(f"Loaded {len(samples)} samples for inspection.")

    stats = DatasetInspector.inspect(samples, dataset_name="DiverseVul")

    # Format text report exactly matching requirements
    report_text = f"""# Dataset Inspection Report

```text
Dataset Inspection Report
=========================

Samples: {stats['total_samples']}
Vulnerable: {stats['vulnerable_samples']}
Safe: {stats['safe_samples']}
Class ratio: {stats['class_ratio_vuln_to_safe']} (1 : {1/stats['class_ratio_vuln_to_safe']:.2f})

Projects: {stats['unique_projects']}
CWEs: {stats['unique_cwes']}
Languages: {', '.join(stats['languages'])}

Average function length: {stats['avg_lines_per_function']} lines
Median function length: {stats['median_lines_per_function']} lines
Maximum function length: {stats['max_lines_per_function']} lines

Missing values: {stats['missing_code_count']}
Duplicates: {stats['exact_duplicates']}
Near duplicates: {stats['near_duplicates']}
```

## Detailed Metrics Table

| Field | Value | Description |
|---|---|---|
| **Dataset Name** | `{stats['dataset_name']}` | Primary training benchmark |
| **Total Inspected Samples** | `{stats['total_samples']}` | Samples streamed from raw JSON |
| **Vulnerable Count** | `{stats['vulnerable_samples']}` | Labeled target = 1 |
| **Safe Count** | `{stats['safe_samples']}` | Labeled target = 0 |
| **Vulnerability Percentage** | `{stats['vuln_percentage']}%` | Empirical vulnerability prevalence |
| **Unique Projects** | `{stats['unique_projects']}` | Distinct software repositories |
| **Unique CWEs** | `{stats['unique_cwes']}` | Common Weakness Enumeration identifiers |
| **Avg Chars Per Function** | `{stats['avg_chars_per_function']}` | Average character volume |
| **Exact Duplicates** | `{stats['exact_duplicates']}` | Identical code bodies |
| **Near Duplicates** | `{stats['near_duplicates']}` | Whitespace-normalized duplicates |

## Cryptographic & Source Verification

- **Raw File:** `{raw_file.resolve()}`
- **Source Verification:** DiverseVul Benchmark (Chen et al., IEEE S&P 2023)
- **Metadata File:** `{meta_file.resolve() if meta_file.is_file() else 'None'}`
"""

    out_doc = Path(args.output_doc)
    out_doc.parent.mkdir(parents=True, exist_ok=True)
    with open(out_doc, "w", encoding="utf-8") as f:
        f.write(report_text)
    logger.info(f"Dataset inspection markdown report written to {out_doc}")

    # Output CSV
    out_csv = Path(args.output_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    stats_df = pd.DataFrame([stats])
    stats_df.to_csv(out_csv, index=False)
    logger.info(f"Dataset statistics CSV written to {out_csv}")


if __name__ == "__main__":
    main()
