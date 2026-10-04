# Experimental Design & Protocol

## 1. Experimental Overview

The empirical objective of InterVul-Graph is to determine whether incorporating interprocedural caller/callee context improves transformer-based vulnerability classification compared to isolated function-level baselines.

### Key Hypotheses
1. **$H_1$ (Context Utility)**: Full interprocedural context (Caller + Target + Callee) yields higher classification $F_1$ and $PR\text{-}AUC$ than local function analysis alone.
2. **$H_2$ (Asymmetric Horizon)**: Caller context provides higher precision gains for input-boundary vulnerabilities (CWE-120, CWE-20), whereas Callee context provides higher recall gains for dangerous operation delegations (CWE-78, CWE-89).
3. **$H_3$ (Out-of-Distribution Transfer)**: Models trained on DiverseVul suffer significant performance degradation when transferred zero-shot to external datasets (CVEfixes, Devign), underscoring the necessity of structural, semantic representations.

---

## 2. Benchmark Datasets

### Primary Training Benchmark: DiverseVul
- **Inspected Corpus**: 40,000 C/C++ functions extracted from 796 distinct open-source repositories covering 129 CWE categories.
- **Partitioning Protocol**: Bipartite connected-component clustering over `(Project, CVE)` pairs.
- **Split Proportions**: 70% Train, 15% Validation, 15% Test.
- **Leakage Status**: Strictly verified `is_leak_free: True` (0 exact duplicates, 0 near-duplicates, 0 project overlaps, 0 CVE overlaps across train and test).

### External Evaluation Benchmark: CVEfixes
- **Source**: Zenodo / Hugging Face `MickyMike/cvefixes_bigvul`.
- **Protocol**: Frozen zero-shot evaluation without fine-tuning or parameter updates on the external set.

---

## 3. Model Architecture & Hyperparameters

| Hyperparameter | CodeBERT Baseline | GraphCodeBERT |
|---|---|---|
| **Pretrained Checkpoint** | `microsoft/codebert-base` | `microsoft/graphcodebert-base` |
| **Max Sequence Length** | 512 tokens | 512 tokens |
| **Batch Size** | 4 (Gradient Accumulation = 1) | 4 (Gradient Accumulation = 1) |
| **Optimizer** | AdamW ($\beta_1=0.9, \beta_2=0.999$) | AdamW ($\beta_1=0.9, \beta_2=0.999$) |
| **Learning Rate** | $2.0 \times 10^{-5}$ | $2.0 \times 10^{-5}$ |
| **Weight Decay** | 0.01 | 0.01 |
| **Warmup Ratio** | 10% linear warmup | 10% linear warmup |
| **Loss Function** | Cross-Entropy Loss | Cross-Entropy Loss |
| **Precision** | Mixed Precision (FP16 autocast) | Mixed Precision (FP16 autocast) |
| **Hardware** | NVIDIA GeForce RTX 3050 (6GB VRAM) | NVIDIA GeForce RTX 3050 (6GB VRAM) |

---

## 4. Evaluation Metrics

Because vulnerability detection datasets exhibit class imbalance, accuracy alone is deceptive. We report:
1. **Precision**: $\frac{TP}{TP + FP}$
2. **Recall**: $\frac{TP}{TP + FN}$
3. **$F_1$ Score**: $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
4. **ROC-AUC**: Area under the Receiver Operating Characteristic curve.
5. **PR-AUC**: Area under the Precision-Recall curve (the most sensitive metric for imbalanced security detection).
6. **Full Confusion Matrix**: True Negatives, False Positives, False Negatives, True Positives.
