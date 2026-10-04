"""GraphCodeBERT sequence classification model architecture."""

import torch
from torch import nn
from transformers import AutoModel, PreTrainedTokenizer

from ..data.schemas import PredictionOutput


class GraphCodeBERTClassifier(nn.Module):
    """Sequence classification model using GraphCodeBERT encoder and classification head."""

    def __init__(
        self,
        pretrained_model_name: str = "microsoft/graphcodebert-base",
        num_labels: int = 2,
        dropout_prob: float = 0.1,
    ):
        super().__init__()
        self.num_labels = num_labels
        self.encoder = AutoModel.from_pretrained(pretrained_model_name)
        hidden_size = self.encoder.config.hidden_size

        self.dropout = nn.Dropout(dropout_prob)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.Tanh(),
            nn.Dropout(dropout_prob),
            nn.Linear(hidden_size, num_labels),
        )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        labels: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)
        logits = self.classifier(cls_rep)

        res = {"logits": logits}
        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            res["loss"] = loss_fn(logits.view(-1, self.num_labels), labels.view(-1))

        return res

    @torch.no_grad()
    def predict_sample(
        self,
        code: str,
        tokenizer: PreTrainedTokenizer,
        max_length: int = 512,
        sample_id: str = "custom_sample",
        device: torch.device = torch.device("cpu"),
    ) -> PredictionOutput:
        self.eval()
        encoded = tokenizer(
            code,
            truncation=True,
            max_length=max_length,
            padding="max_length",
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"].to(device)
        attention_mask = encoded["attention_mask"].to(device)

        out = self.forward(input_ids=input_ids, attention_mask=attention_mask)
        probs = torch.softmax(out["logits"], dim=-1)[0]
        vuln_prob = float(probs[1].item())
        pred = int(torch.argmax(probs).item())
        label = "vulnerable" if pred == 1 else "safe"

        return PredictionOutput(
            sample_id=sample_id,
            prediction=pred,
            probability=round(vuln_prob, 4),
            label=label,
        )
