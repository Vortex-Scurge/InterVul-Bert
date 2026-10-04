# Dataset Inspection Report

```text
Dataset Inspection Report
=========================

Samples: 40000
Vulnerable: 18945
Safe: 21055
Class ratio: 0.8998 (1 : 1.11)

Projects: 796
CWEs: 129
Languages: c

Average function length: 71.21 lines
Median function length: 28.0 lines
Maximum function length: 23939 lines

Missing values: 0
Duplicates: 0
Near duplicates: 118
```

## Detailed Metrics Table

| Field | Value | Description |
|---|---|---|
| **Dataset Name** | `DiverseVul` | Primary training benchmark |
| **Total Inspected Samples** | `40000` | Samples streamed from raw JSON |
| **Vulnerable Count** | `18945` | Labeled target = 1 |
| **Safe Count** | `21055` | Labeled target = 0 |
| **Vulnerability Percentage** | `47.36%` | Empirical vulnerability prevalence |
| **Unique Projects** | `796` | Distinct software repositories |
| **Unique CWEs** | `129` | Common Weakness Enumeration identifiers |
| **Avg Chars Per Function** | `2143.22` | Average character volume |
| **Exact Duplicates** | `0` | Identical code bodies |
| **Near Duplicates** | `118` | Whitespace-normalized duplicates |

## Cryptographic & Source Verification

- **Raw File:** `/home/noxir/antigravity/GraphCodeBert/diversevul_20230702.json`
- **Source Verification:** DiverseVul Benchmark (Chen et al., IEEE S&P 2023)
- **Metadata File:** `/home/noxir/antigravity/GraphCodeBert/diversevul_20230702_metadata.json`
