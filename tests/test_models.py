"""Tests for CodeBERT and GraphCodeBERT architectures and factories."""

import torch

from src.models.codebert_classifier import CodeBERTClassifier
from src.models.model_factory import ModelFactory


def test_codebert_classifier_forward():
    model = CodeBERTClassifier(num_labels=2)
    model.eval()

    batch_size = 2
    seq_len = 16
    input_ids = torch.randint(0, 1000, (batch_size, seq_len))
    attention_mask = torch.ones((batch_size, seq_len))

    with torch.no_grad():
        out = model(input_ids=input_ids, attention_mask=attention_mask)

    assert "logits" in out
    assert out["logits"].shape == (batch_size, 2)


def test_codebert_predict_sample():
    device = ModelFactory.get_device()
    model, tokenizer = ModelFactory.load_codebert("microsoft/codebert-base", device=device)

    pred = model.predict_sample(
        "void vuln() { strcpy(dest, src); }",
        tokenizer=tokenizer,
        max_length=64,
        device=device,
    )
    assert pred.prediction in [0, 1]
    assert 0.0 <= pred.probability <= 1.0
    assert pred.label in ["safe", "vulnerable"]
