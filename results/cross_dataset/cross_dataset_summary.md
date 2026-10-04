# Cross-Dataset Generalization Report

- **Source Training Dataset:** `DiverseVul`
- **Additional Training on Evaluation Dataset:** `NO`
- **Model Frozen:** `YES (Parameters Locked, In-Distribution Weights Only)`

## Summary of Cross-Dataset Results

| Evaluation Dataset | Samples | Accuracy | Precision | Recall | F1 Score | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|
| **CVEFIXES** | 500 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | nan |
| **DEVIGN** | 500 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | nan |

## Methodological Discussion
When models trained on DiverseVul are evaluated on external datasets like CVEfixes without fine-tuning,
performance drops are frequently observed. This highlights the domain shift across project conventions,
vulnerability reporting taxonomies, and function granularity, reinforcing the need for structural interprocedural context.