"""Aggregates benchmark results and generates experiment tables."""

from pathlib import Path
from typing import Any

import pandas as pd
from tabulate import tabulate


class ExperimentReportGenerator:
    """Generates standardized experiment tables comparing models and context strategies."""

    @staticmethod
    def generate_experiment_table(
        experiment_records: list[dict[str, Any]],
        output_dir: str | Path = "results/tables",
    ) -> str:
        """Create formatted ASCII and Markdown comparison tables.

        Args:
            experiment_records: List of dicts with 'model', 'context', 'f1', 'pr_auc', 'accuracy', etc.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        rows = []
        for rec in experiment_records:
            rows.append(
                {
                    "Model": rec.get("model", "CodeBERT"),
                    "Context": rec.get("context", "Local"),
                    "Accuracy": f"{min(1.0, float(rec.get('accuracy', 0.0))):.4f}",
                    "Precision": f"{min(1.0, float(rec.get('precision', 0.0))):.4f}",
                    "Recall": f"{min(1.0, float(rec.get('recall', 0.0))):.4f}",
                    "F1": f"{min(1.0, float(rec.get('f1', 0.0))):.4f}",
                    "ROC-AUC": f"{min(1.0, float(rec.get('roc_auc', 0.0))):.4f}",
                    "PR-AUC": f"{min(1.0, float(rec.get('pr_auc', 0.0))):.4f}",
                }
            )

        df = pd.DataFrame(rows)
        df.to_csv(out_path / "experiment_comparison.csv", index=False)

        # Tabulate ASCII Table
        headers = [
            "Model",
            "Context",
            "Accuracy",
            "Precision",
            "Recall",
            "F1",
            "ROC-AUC",
            "PR-AUC",
        ]
        table_data = [[r[h] for h in headers] for r in rows]
        ascii_table = tabulate(table_data, headers=headers, tablefmt="grid")
        github_table = tabulate(table_data, headers=headers, tablefmt="github")

        with open(out_path / "experiment_comparison.txt", "w", encoding="utf-8") as f:
            f.write(ascii_table)

        with open(out_path / "experiment_comparison.md", "w", encoding="utf-8") as f:
            f.write(f"# Model and Context Evaluation Comparison\n\n{github_table}\n")

        return ascii_table
