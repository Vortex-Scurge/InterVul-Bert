"""Cross-dataset evaluation engine with model freezing."""

from typing import Any

import torch
from torch import nn
from transformers import PreTrainedTokenizer

from ..data.schemas import PredictionOutput, VulnerabilitySample
from ..utils.logger import get_logger
from .metrics import VulnerabilityMetrics

logger = get_logger("InterVul-Graph.cross_eval")


class CrossDatasetEvaluator:
    """Evaluates frozen models on out-of-distribution datasets without fine-tuning."""

    def __init__(
        self,
        model: nn.Module,
        tokenizer: PreTrainedTokenizer,
        device: torch.device,
        batch_size: int = 16,
        max_length: int = 512,
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        self.batch_size = batch_size
        self.max_length = max_length

        # Ensure model is frozen and in eval mode
        self.model.eval()
        for param in self.model.parameters():
            param.requires_grad = False

    @torch.no_grad()
    def evaluate_dataset(
        self,
        samples: list[VulnerabilitySample],
        dataset_name: str,
        training_dataset: str = "DiverseVul",
    ) -> dict[str, Any]:
        """Run inference on external dataset and calculate metrics."""
        logger.info(
            f"Evaluating {len(samples)} samples on external dataset: {dataset_name} (Model Frozen: YES)"
        )

        y_true: list[int] = []
        y_pred: list[int] = []
        y_probs: list[float] = []
        predictions: list[PredictionOutput] = []

        for i in range(0, len(samples), self.batch_size):
            batch_samples = samples[i : i + self.batch_size]
            codes = [s.code for s in batch_samples]
            targets = [s.target for s in batch_samples]

            encoded = self.tokenizer(
                codes,
                truncation=True,
                max_length=self.max_length,
                padding="max_length",
                return_tensors="pt",
            )
            input_ids = encoded["input_ids"].to(self.device)
            attention_mask = encoded["attention_mask"].to(self.device)

            out = self.model(input_ids=input_ids, attention_mask=attention_mask)
            logits = out["logits"]
            probs = torch.softmax(logits, dim=-1)
            preds = torch.argmax(probs, dim=-1)

            for j, s in enumerate(batch_samples):
                prob_vuln = float(probs[j, 1].item())
                pred_label = int(preds[j].item())
                y_true.append(targets[j])
                y_pred.append(pred_label)
                y_probs.append(prob_vuln)

                predictions.append(
                    PredictionOutput(
                        sample_id=s.sample_id,
                        prediction=pred_label,
                        probability=round(prob_vuln, 4),
                        label="vulnerable" if pred_label == 1 else "safe",
                        ground_truth=targets[j],
                        metadata={
                            "project": s.project,
                            "cwe": s.cwe,
                            "cve": s.cve,
                            "source_dataset": dataset_name,
                        },
                    )
                )

        metrics = VulnerabilityMetrics.compute_all(y_true, y_pred, y_probs)
        report = {
            "training_dataset": training_dataset,
            "external_evaluation_dataset": dataset_name,
            "additional_training_performed_on_evaluation_dataset": "NO",
            "model_frozen": True,
            "total_evaluated_samples": len(samples),
            "metrics": metrics,
            "sample_predictions": [p.to_dict() for p in predictions[:20]],
        }
        return report, predictions
