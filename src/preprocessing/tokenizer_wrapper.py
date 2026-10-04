"""Tokenizer wrapper and PyTorch Dataset for CodeBERT and GraphCodeBERT."""

import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer, PreTrainedTokenizer

from ..data.schemas import VulnerabilitySample
from .cleaner import CodeCleaner


class CodeDataset(Dataset):
    """PyTorch Dataset yielding tokenized code and binary vulnerability labels."""

    def __init__(
        self,
        samples: list[VulnerabilitySample],
        tokenizer: PreTrainedTokenizer,
        max_length: int = 512,
        clean_code: bool = True,
    ):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.clean_code = clean_code

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        sample = self.samples[idx]
        code = sample.code
        if self.clean_code:
            code = CodeCleaner.clean(code)

        encoding = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )

        item = {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(sample.target, dtype=torch.long),
        }
        return item


class CodeTokenizerWrapper:
    """Wrapper around HuggingFace AutoTokenizer with custom formatting."""

    def __init__(
        self,
        pretrained_model_name: str = "microsoft/codebert-base",
        max_length: int = 512,
    ):
        self.model_name = pretrained_model_name
        self.max_length = max_length
        self.tokenizer = AutoTokenizer.from_pretrained(pretrained_model_name)

    def tokenize_code(self, code: str, max_length: int | None = None) -> dict[str, torch.Tensor]:
        """Tokenize a single code snippet into model inputs."""
        length = max_length or self.max_length
        cleaned = CodeCleaner.clean(code)
        encoded = self.tokenizer(
            cleaned,
            truncation=True,
            max_length=length,
            padding="max_length",
            return_tensors="pt",
        )
        return encoded

    def tokenize_context(
        self,
        target_code: str,
        caller_code: str | None = None,
        callee_code: str | None = None,
        max_length: int | None = None,
    ) -> dict[str, torch.Tensor]:
        """Format and tokenize interprocedural context."""
        length = max_length or self.max_length
        parts = []

        if caller_code:
            parts.append(f"// --- CALLER CONTEXT ---\n{CodeCleaner.clean(caller_code)}")

        parts.append(f"// --- TARGET FUNCTION ---\n{CodeCleaner.clean(target_code)}")

        if callee_code:
            parts.append(f"// --- CALLEE CONTEXT ---\n{CodeCleaner.clean(callee_code)}")

        combined_text = "\n\n".join(parts)
        return self.tokenize_code(combined_text, max_length=length)
