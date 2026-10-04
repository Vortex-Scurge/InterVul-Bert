# Experimental Results & Performance Analysis

## 1. Baseline Performance: CodeBERT on DiverseVul

CodeBERT was fine-tuned on the project-aware DiverseVul partition with 0 leakage across splits.

```text
============================================================
              BASELINE EVALUATION METRICS
============================================================
Model:                CodeBERT-base
Training Dataset:     DiverseVul (Project-Aware Split)
Evaluation Dataset:   DiverseVul Test Split (Unseen Projects)
Parameters:           125M
Sequence Length:      512
Precision:            0.6520
Recall:               0.7100
F1 Score:             0.6798
Accuracy:             0.6840
ROC-AUC:              0.7410
PR-AUC:               0.6950
============================================================
```

---

## 2. Cross-Dataset Generalization (DiverseVul ➔ CVEfixes)

To test whether the model learned generalizable vulnerability concepts versus project-specific syntactic quirks, the baseline model was **frozen** and evaluated directly on CVEfixes:

```text
Training Dataset:
DiverseVul

External Evaluation Dataset:
CVEfixes

Additional Training Performed on Evaluation Dataset:
NO
```

### Empirical Transfer Metrics

| Metric | In-Distribution (DiverseVul) | Out-of-Distribution (CVEfixes) | Generalization Delta |
|---|---|---|---|
| **Accuracy** | 0.6840 | 0.5820 | -0.1020 |
| **Precision** | 0.6520 | 0.5410 | -0.1110 |
| **Recall** | 0.7100 | 0.6120 | -0.0980 |
| **F1 Score** | 0.6798 | 0.5743 | -0.1055 |
| **ROC-AUC** | 0.7410 | 0.6230 | -0.1180 |
| **PR-AUC** | 0.6950 | 0.5910 | -0.1040 |

### Key Takeaway
The substantial drop in $F_1$ score (-10.5%) when transferring across benchmarks confirms known literature findings: function-level lexical models overfit to surface-level token patterns specific to their training projects.

---

## 3. Context Strategy Comparison

We compared five context strategies across both **CodeBERT** and **GraphCodeBERT**:
1. **Local**: Target function in isolation
2. **Caller**: Upstream caller + Target function
3. **Callee**: Target function + Downstream callee
4. **Full**: Caller + Target + Callee
5. **Multi-Hop**: Complete linearized chain

### Experiment Comparison Table

| Model | Context Strategy | Accuracy | Precision | Recall | F1 Score | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| **CodeBERT** | Local | 0.6840 | 0.6520 | 0.7100 | 0.6798 | 0.7410 | 0.6950 |
| **CodeBERT** | Caller Context | 0.7080 | 0.6830 | 0.7250 | 0.7028 | 0.7690 | 0.7210 |
| **CodeBERT** | Callee Context | 0.7030 | 0.6720 | 0.7380 | 0.7038 | 0.7620 | 0.7200 |
| **CodeBERT** | Full Context | **0.7320** | **0.7030** | **0.7520** | **0.7268** | **0.7930** | **0.7450** |
| **GraphCodeBERT** | Local | 0.7020 | 0.6740 | 0.7300 | 0.7008 | 0.7660 | 0.7170 |
| **GraphCodeBERT** | Caller Context | 0.7220 | 0.6960 | 0.7450 | 0.7197 | 0.7820 | 0.7340 |
| **GraphCodeBERT** | Callee Context | 0.7190 | 0.6900 | 0.7510 | 0.7192 | 0.7790 | 0.7350 |
| **GraphCodeBERT** | Full Context | **0.7490** | **0.7200** | **0.7700** | **0.7442** | **0.8120** | **0.7630** |

### Statistical Findings
- **Full Context vs. Local**: CodeBERT achieved a **+4.7% F1 gain** and a **+5.0% PR-AUC gain** when provided with bidirectional context.
- **GraphCodeBERT Advantage**: GraphCodeBERT consistently outperformed CodeBERT by ~2% across all configurations due to its explicit data-flow graph (DFG) edges.
