"""Vulnerability detection evaluation metrics."""

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)


class VulnerabilityMetrics:
    """Computes comprehensive classification metrics for vulnerability detection."""

    @staticmethod
    def compute_all(
        y_true: list[int],
        y_pred: list[int],
        y_probs: list[float],
    ) -> dict[str, Any]:
        """Compute Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, and Confusion Matrix."""
        y_true_arr = np.array(y_true)
        y_pred_arr = np.array(y_pred)
        y_probs_arr = np.array(y_probs)

        acc = float(accuracy_score(y_true_arr, y_pred_arr))
        prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
        rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
        f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))

        # ROC-AUC
        try:
            roc_auc = float(roc_auc_score(y_true_arr, y_probs_arr))
        except Exception:
            roc_auc = 0.5

        # PR-AUC
        try:
            precision_pts, recall_pts, _ = precision_recall_curve(y_true_arr, y_probs_arr)
            pr_auc = float(auc(recall_pts, precision_pts))
        except Exception:
            pr_auc = 0.0

        # Confusion Matrix
        cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            },
            "total_samples": len(y_true),
            "actual_vulnerable": int(np.sum(y_true_arr == 1)),
            "actual_safe": int(np.sum(y_true_arr == 0)),
            "predicted_vulnerable": int(np.sum(y_pred_arr == 1)),
            "predicted_safe": int(np.sum(y_pred_arr == 0)),
        }

    @staticmethod
    def save_confusion_matrix_plot(
        cm_dict: dict[str, int],
        output_path: str | Path,
        title: str = "Confusion Matrix",
    ) -> None:
        """Plot and save confusion matrix heatmap."""
        matrix = np.array(
            [
                [cm_dict["tn"], cm_dict["fp"]],
                [cm_dict["fn"], cm_dict["tp"]],
            ]
        )
        labels = [["TN", "FP"], ["FN", "TP"]]
        annot = [
            [f"{val}\n({label})" for val, label in zip(row_val, row_lbl)]
            for row_val, row_lbl in zip(matrix, labels)
        ]

        plt.figure(figsize=(6, 5))
        sns.heatmap(
            matrix,
            annot=annot,
            fmt="",
            cmap="Blues",
            xticklabels=["Predicted Safe (0)", "Predicted Vuln (1)"],
            yticklabels=["Actual Safe (0)", "Actual Vuln (1)"],
        )
        plt.title(title, fontsize=12, pad=12)
        plt.tight_layout()
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, dpi=300)
        plt.close()
