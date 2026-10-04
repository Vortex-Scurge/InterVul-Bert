"""Training engine for fine-tuning CodeBERT and GraphCodeBERT."""

import json
import random
from pathlib import Path
from typing import Any, Union

import numpy as np
import torch
from torch import nn
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import get_linear_schedule_with_warmup

from ..data.schemas import VulnerabilitySample
from ..evaluation.metrics import VulnerabilityMetrics
from ..preprocessing.tokenizer_wrapper import CodeDataset
from ..utils.logger import get_logger

logger = get_logger("InterVul-Graph.training")


def set_seed(seed: int = 42) -> None:
    """Set random seed for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True


class VulnerabilityTrainer:
    """End-to-end trainer for vulnerability detection transformers."""

    def __init__(
        self,
        model: nn.Module,
        tokenizer: Any,
        device: torch.device,
        save_dir: Union[str, Path] = "models/codebert",
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)

    def train(
        self,
        train_samples: list[VulnerabilitySample],
        val_samples: list[VulnerabilitySample],
        num_epochs: int = 3,
        batch_size: int = 16,
        learning_rate: float = 2.0e-5,
        weight_decay: float = 0.01,
        warmup_ratio: float = 0.1,
        max_length: int = 512,
        seed: int = 42,
    ) -> dict[str, Any]:
        """Fine-tune the model with evaluation on validation set after each epoch."""
        set_seed(seed)
        train_dataset = CodeDataset(train_samples, self.tokenizer, max_length=max_length)
        val_dataset = CodeDataset(val_samples, self.tokenizer, max_length=max_length)

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

        total_steps = len(train_loader) * num_epochs
        warmup_steps = int(total_steps * warmup_ratio)

        no_decay = ["bias", "LayerNorm.weight"]
        optimizer_grouped_parameters = [
            {
                "params": [
                    p
                    for n, p in self.model.named_parameters()
                    if not any(nd in n for nd in no_decay)
                ],
                "weight_decay": weight_decay,
            },
            {
                "params": [
                    p for n, p in self.model.named_parameters() if any(nd in n for nd in no_decay)
                ],
                "weight_decay": 0.0,
            },
        ]
        optimizer = AdamW(optimizer_grouped_parameters, lr=learning_rate)
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps
        )

        logger.info(
            f"Starting training: {len(train_samples)} train samples, {len(val_samples)} val samples, {num_epochs} epochs."
        )
        best_val_f1 = -1.0
        best_metrics: dict[str, Any] = {}
        history: list[dict[str, Any]] = []

        scaler = torch.cuda.amp.GradScaler(enabled=(self.device.type == "cuda"))
        if self.device.type == "cuda":
            torch.cuda.empty_cache()

        for epoch in range(1, num_epochs + 1):
            self.model.train()
            total_train_loss = 0.0
            optimizer.zero_grad()

            for step, batch in enumerate(train_loader):
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["labels"].to(self.device)

                with torch.cuda.amp.autocast(enabled=(self.device.type == "cuda")):
                    outputs = self.model(
                        input_ids=input_ids, attention_mask=attention_mask, labels=labels
                    )
                    loss = outputs["loss"]

                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad()
                scheduler.step()

                total_train_loss += loss.item()

            avg_train_loss = total_train_loss / max(1, len(train_loader))

            # Validation evaluation
            val_metrics = self.evaluate(val_loader)
            val_f1 = val_metrics["f1"]

            epoch_record = {
                "epoch": epoch,
                "train_loss": round(avg_train_loss, 4),
                "val_metrics": val_metrics,
            }
            history.append(epoch_record)
            logger.info(
                f"Epoch {epoch}/{num_epochs} - Train Loss: {avg_train_loss:.4f} | Val F1: {val_f1:.4f} | Val Acc: {val_metrics['accuracy']:.4f}"
            )

            # Save best checkpoint
            if val_f1 > best_val_f1 or epoch == 1:
                best_val_f1 = val_f1
                best_metrics = val_metrics
                torch.save(self.model.state_dict(), self.save_dir / "pytorch_model.bin")
                torch.save(self.model.state_dict(), self.save_dir / "model.pt")
                self.tokenizer.save_pretrained(self.save_dir)
                logger.info(
                    f"Best model updated and saved to {self.save_dir} (Val F1: {val_f1:.4f})"
                )

        # Save training history
        with open(self.save_dir / "training_history.json", "w", encoding="utf-8") as f:
            json.dump(
                {"history": history, "best_val_metrics": best_metrics, "seed": seed},
                f,
                indent=2,
            )

        return {"history": history, "best_val_metrics": best_metrics}

    @torch.no_grad()
    def evaluate(self, data_loader: DataLoader) -> dict[str, Any]:
        """Evaluate model on a DataLoader and compute metrics."""
        self.model.eval()
        y_true: list[int] = []
        y_pred: list[int] = []
        y_probs: list[float] = []

        for batch in data_loader:
            input_ids = batch["input_ids"].to(self.device)
            attention_mask = batch["attention_mask"].to(self.device)
            labels = batch["labels"].to(self.device)

            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs["logits"]
            probs = torch.softmax(logits, dim=-1)
            preds = torch.argmax(probs, dim=-1)

            y_true.extend(labels.cpu().tolist())
            y_pred.extend(preds.cpu().tolist())
            y_probs.extend(probs[:, 1].cpu().tolist())

        return VulnerabilityMetrics.compute_all(y_true, y_pred, y_probs)
