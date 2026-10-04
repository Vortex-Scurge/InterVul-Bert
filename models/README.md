# Model Checkpoints

This directory houses fine-tuned weights and configuration metadata for neural code vulnerability detection.

## Directory Structure

```
models/
├── codebert/
│   ├── .gitkeep
│   ├── tokenizer.json
│   ├── tokenizer_config.json
│   ├── training_history.json
│   └── [model.pt / pytorch_model.bin] (Generated via training)
└── graphcodebert/
    └── .gitkeep
```

> **Note on Binary Weights**: Heavy binary checkpoint files (`*.pt`, `*.bin`, `*.safetensors` > 100MB) are excluded from Git version control via `.gitignore` to comply with GitHub file size restrictions.

## Training Checkpoints Locally

To train or reproduce the fine-tuned CodeBERT model on the leak-free DiverseVul partition:

```bash
python scripts/train_codebert.py --config configs/codebert_baseline.yaml
```

To train GraphCodeBERT:

```bash
python scripts/train_graphcodebert.py --config configs/graphcodebert.yaml
```

The resulting checkpoints will automatically be saved to `models/codebert/model.pt` and `models/graphcodebert/model.pt`.
