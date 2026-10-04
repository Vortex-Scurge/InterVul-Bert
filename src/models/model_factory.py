"""Model factory for loading, instantiating, and persisting models and tokenizers."""

from pathlib import Path

import torch
from torch import nn
from transformers import AutoTokenizer, PreTrainedTokenizer

from ..utils.logger import get_logger
from .codebert_classifier import CodeBERTClassifier
from .graphcodebert_classifier import GraphCodeBERTClassifier

logger = get_logger("InterVul-Graph.models")


class ModelFactory:
    """Factory for CodeBERT and GraphCodeBERT models and tokenizers."""

    @staticmethod
    def get_device() -> torch.device:
        """Get best available torch device."""
        if torch.cuda.is_available():
            return torch.device("cuda:0")
        return torch.device("cpu")

    @classmethod
    def load_codebert(
        cls,
        model_path_or_name: str | Path = "microsoft/codebert-base",
        num_labels: int = 2,
        device: torch.device | None = None,
    ) -> tuple[CodeBERTClassifier, PreTrainedTokenizer]:
        """Load CodeBERT model and tokenizer."""
        dev = device or cls.get_device()
        path = Path(model_path_or_name)

        if path.is_dir() and (path / "pytorch_model.bin").is_file():
            logger.info(f"Loading local fine-tuned CodeBERT checkpoint from {path}")
            tokenizer = AutoTokenizer.from_pretrained(path)
            model = CodeBERTClassifier(
                pretrained_model_name="microsoft/codebert-base", num_labels=num_labels
            )
            state_dict = torch.load(path / "pytorch_model.bin", map_location=dev)
            model.load_state_dict(state_dict)
        elif path.is_dir() and (path / "model.pt").is_file():
            logger.info(f"Loading local fine-tuned CodeBERT weights from {path / 'model.pt'}")
            tokenizer = AutoTokenizer.from_pretrained(
                path if (path / "vocab.json").is_file() else "microsoft/codebert-base"
            )
            model = CodeBERTClassifier(
                pretrained_model_name="microsoft/codebert-base", num_labels=num_labels
            )
            state_dict = torch.load(path / "model.pt", map_location=dev)
            model.load_state_dict(state_dict)
        else:
            logger.info(f"Instantiating CodeBERT with pretrained encoder: {model_path_or_name}")
            tokenizer = AutoTokenizer.from_pretrained(str(model_path_or_name))
            model = CodeBERTClassifier(
                pretrained_model_name=str(model_path_or_name), num_labels=num_labels
            )

        model.to(dev)
        return model, tokenizer

    @classmethod
    def load_graphcodebert(
        cls,
        model_path_or_name: str | Path = "microsoft/graphcodebert-base",
        num_labels: int = 2,
        device: torch.device | None = None,
    ) -> tuple[GraphCodeBERTClassifier, PreTrainedTokenizer]:
        """Load GraphCodeBERT model and tokenizer."""
        dev = device or cls.get_device()
        path = Path(model_path_or_name)

        if path.is_dir() and (path / "pytorch_model.bin").is_file():
            logger.info(f"Loading local fine-tuned GraphCodeBERT checkpoint from {path}")
            tokenizer = AutoTokenizer.from_pretrained(path)
            model = GraphCodeBERTClassifier(
                pretrained_model_name="microsoft/graphcodebert-base",
                num_labels=num_labels,
            )
            state_dict = torch.load(path / "pytorch_model.bin", map_location=dev)
            model.load_state_dict(state_dict)
        elif path.is_dir() and (path / "model.pt").is_file():
            logger.info(f"Loading local fine-tuned GraphCodeBERT weights from {path / 'model.pt'}")
            tokenizer = AutoTokenizer.from_pretrained(
                path if (path / "vocab.json").is_file() else "microsoft/graphcodebert-base"
            )
            model = GraphCodeBERTClassifier(
                pretrained_model_name="microsoft/graphcodebert-base",
                num_labels=num_labels,
            )
            state_dict = torch.load(path / "model.pt", map_location=dev)
            model.load_state_dict(state_dict)
        else:
            logger.info(
                f"Instantiating GraphCodeBERT with pretrained encoder: {model_path_or_name}"
            )
            try:
                tokenizer = AutoTokenizer.from_pretrained(str(model_path_or_name))
            except Exception:
                tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
            model = GraphCodeBERTClassifier(
                pretrained_model_name=str(model_path_or_name), num_labels=num_labels
            )

        model.to(dev)
        return model, tokenizer

    @staticmethod
    def save_model(
        model: nn.Module,
        tokenizer: PreTrainedTokenizer,
        output_dir: str | Path,
    ) -> None:
        """Save model weights and tokenizer to directory."""
        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), path / "pytorch_model.bin")
        torch.save(model.state_dict(), path / "model.pt")
        tokenizer.save_pretrained(path)
        logger.info(f"Saved model checkpoint and tokenizer to {path}")
