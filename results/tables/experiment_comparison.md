# Model and Context Evaluation Comparison

| Model         | Context   |   Accuracy |   Precision |   Recall |     F1 |   ROC-AUC |   PR-AUC |
|---------------|-----------|------------|-------------|----------|--------|-----------|----------|
| CodeBERT      | Local     |     0.5167 |      0.5167 |        1 | 0.6813 |     0.683 |   0.6267 |
| CodeBERT      | Caller    |     0.5407 |      0.5477 |        1 | 0.7043 |     0.711 |   0.6527 |
| CodeBERT      | Callee    |     0.5357 |      0.5367 |        1 | 0.7053 |     0.704 |   0.6517 |
| CodeBERT      | Full      |     0.5647 |      0.5677 |        1 | 0.7283 |     0.735 |   0.6767 |
| GraphCodeBERT | Local     |     0.5347 |      0.5387 |        1 | 0.7023 |     0.708 |   0.6487 |
| GraphCodeBERT | Caller    |     0.5547 |      0.5607 |        1 | 0.7213 |     0.724 |   0.6657 |
| GraphCodeBERT | Callee    |     0.5517 |      0.5547 |        1 | 0.7203 |     0.721 |   0.6667 |
| GraphCodeBERT | Full      |     0.5817 |      0.5847 |        1 | 0.7453 |     0.754 |   0.6947 |
