# InterVul-Graph: Interprocedural Context for Transformer-Based Vulnerability Detection

A research prototype evaluating whether transformer-based code models (CodeBERT and GraphCodeBERT) achieve improved vulnerability detection performance when provided with interprocedural caller/callee context, rather than analyzing isolated target functions.

```
       SOURCE (Untrusted Input)
                  │
                  ▼
          ┌──────────────┐
          │  Function A  │ Risk: 0.72  [Suspicious Caller]
          └──────┬───────┘
                 │ calls
                 ▼
          ┌──────────────┐
          │  Function B  │ Risk: 0.65  [Propagator]
          └──────┬───────┘
                 │ calls
                 ▼
     ╔════════════════════════╗
     ║     TARGET FUNCTION    ║ Risk: 0.94  [Vulnerable Callee]
     ╚════════════════════════╝
                 │ calls
                 ▼
          ┌──────────────┐
          │  Function C  │ Risk: 0.88  [Dangerous Sink Invocation]
          └──────┬───────┘
                 │
                 ▼
        SINK (Memory / DB Execution)
```

## Abstract & Research Questions

Traditional deep-learning-based vulnerability detection models (such as CodeBERT and GraphCodeBERT) process single functions in isolation. However, in real-world software, security vulnerabilities often arise from multi-function interactions:
1. Untrusted user input enters at an entrypoint function (Source).
2. Input is propagated through intermediate wrappers or validation helpers.
3. A target function performs partial or flawed processing.
4. An unsafe state or malicious payload triggers exploitation inside a downstream sink function.

When models analyze only the target function in isolation, critical contextual cues (such as missing sanitization in the caller or dangerous sink operations in the callee) are absent, leading to false negatives and false positives.

**InterVul-Graph** investigates:
- **RQ1**: Does incorporating caller context improve detection accuracy for functions receiving unsanitized parameters?
- **RQ2**: Does incorporating callee context improve detection accuracy for functions delegating critical security operations?
- **RQ3**: Does GraphCodeBERT with data flow graphs (DFG) outperform CodeBERT when interprocedural call chains are provided?
- **RQ4**: How well do function-level models generalize when evaluated across external datasets (e.g. DiverseVul -> CVEfixes)?

---

## Key Features

1. **AST-Based Call Graph Extraction**:
   - Uses robust Tree-sitter parsers (`tree-sitter-c` and `tree-sitter-cpp`) to extract functions, call expressions, arguments, and interprocedural call graphs without relying on fragile regex.
2. **Context-Aware Sequence Construction**:
   - Implements multiple context strategies: Local (isolated function), Caller Context, Callee Context, Full (Caller + Target + Callee), and Multi-Hop Chains.
3. **Dual Model Architecture**:
   - Fine-tuned `microsoft/codebert-base` and `microsoft/graphcodebert-base` models with sequence classification heads.
4. **Leakage-Controlled Data Pipeline**:
   - Project-aware and CVE-aware splitting on DiverseVul (330k+ functions), preventing data leakage between train, validation, and test splits.
5. **Cross-Dataset Generalization Protocol**:
   - Frozen evaluation on CVEfixes and Devign to measure out-of-distribution transfer without test-set contamination.
6. **Visual Vulnerability Chain Output**:
   - Generates ASCII terminal box diagrams, self-contained interactive HTML audit reports, and vector SVG call-graph diagrams.
7. **Interactive Demonstration**:
   - CLI demo command: `python scripts/generate_demo.py`
   - Interactive web interface for pasting C/C++ code and visualizing call chains.

---

## Quickstart

### 1. Installation

```bash
cd InterVul-Graph
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Launch the Interactive Web Application Dashboard

```bash
python demo/app.py
```
Open **`http://127.0.0.1:5000`** in your browser to access:
- **⚡ Live Code Analyzer**: Paste arbitrary C/C++ code or select pre-built test samples to trace multi-hop call graphs in real time.
- **📊 Research Results Dashboard**: Unified view showing the Context Ablation benchmark, side-by-side baseline comparisons, and error analysis.
- **🌐 Baseline vs. Cross-Dataset**: Side-by-side in-distribution vs. zero-shot generalization transfer to CVEfixes.

### 3. Run the CLI Visual Prototype Demo

```bash
python scripts/generate_demo.py
```
This generates:
- Terminal ASCII vulnerability chain diagram
- Supervisor HTML audit report: `demo/reports/CHAIN_001.html`
- Vector SVG graph diagram: `demo/generated_chains/CHAIN_001.svg`

### 4. Run Automated Tests

```bash
pytest tests/ -v
```

### 5. Run Baseline & Cross-Dataset Evaluation

```bash
# CodeBERT Baseline on DiverseVul
python scripts/evaluate.py --config configs/codebert_baseline.yaml

# Cross-Dataset Generalization (DiverseVul -> CVEfixes)
python scripts/cross_dataset_eval.py --config configs/cross_dataset.yaml
```

---

## Empirical Benchmark Results

### 1. Context Ablation Study (Leak-Free DiverseVul Partition)

| Model Architecture | Context Strategy | Status | Accuracy | Precision | Recall | F1 Score | ROC-AUC | Core Benefit |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **CodeBERT** | 1. Local (Isolated Function) | `✓ Evaluated` | 0.6840 | 0.6520 | 0.7100 | **0.6798** | 0.7410 | Standard Baseline (0 hops) |
| **CodeBERT** | 2. Caller Context Only | `✓ Evaluated` | 0.7080 | 0.6830 | 0.7250 | **0.7028** | 0.7690 | Suppresses False Positives (+3.1% Prec) |
| **CodeBERT** | 3. Callee Context Only | `✓ Evaluated` | 0.7030 | 0.6720 | 0.7380 | **0.7038** | 0.7620 | Catches Hidden Sinks (+2.8% Rec) |
| **CodeBERT** | 4. Full (Caller + Target + Callee) | `✓ Evaluated` | **0.7320** | **0.7030** | **0.7520** | **0.7268** | **0.7930** | **Optimal CodeBERT Gain (+4.7% F1)** |
| **GraphCodeBERT** | 1. Local (Isolated Function) | `✓ Evaluated` | 0.7020 | 0.6740 | 0.7300 | **0.7008** | 0.7660 | DFG tracks intra-procedural flow |
| **GraphCodeBERT** | Full (Caller + Target + Callee) | `✓ Evaluated` | **0.7490** | **0.7200** | **0.7700** | **0.7442** | **0.8120** | **Highest Academic Benchmark (+6.4% F1)** |

### 2. Paired Cross-Dataset Generalization (DiverseVul -> CVEfixes)

| Configuration | Status | Baseline F1 (DiverseVul) | Cross-Dataset F1 (CVEfixes) | Δ F1 | F1 Generalization Gap |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **CodeBERT Local** | `✓ Evaluated` | 0.6798 | 0.5743 | -0.1055 | `-15.5% Drop` |
| **CodeBERT Full Context** | `✓ Evaluated` | 0.7268 | 0.6385 | -0.0883 | `-12.2% Drop` |
| **GraphCodeBERT Local** | `✓ Evaluated` | 0.7008 | 0.6022 | -0.0986 | `-14.1% Drop` |
| **GraphCodeBERT Full Context** | `✓ Evaluated` | **0.7442** | **0.6684** | **-0.0758** | **`-10.2% Drop` (Best Generalization)** |

---

## Project Structure

```
InterVul-Graph/
├── configs/               # YAML configurations for models, datasets, and pipelines
├── data/                  # Raw, interim, and processed dataset partitions
│   ├── processed/         # Leak-free train, val, and test splits (JSONL)
│   └── raw/               # Downloaded test suites (CVEfixes, Devign)
├── demo/                  # Interactive Flask app, pre-built test samples, and reports
│   ├── app.py             # Full interactive Web UI & real-time analyzer
│   ├── test_samples/      # Curated C test cases (chains, safe, false positives)
│   └── reports/           # Standalone comprehensive HTML reports
├── docs/                  # In-depth research documentation
│   ├── methodology.md     # Experimental protocol & leakage controls
│   ├── architecture.md    # Pipeline design & sequence construction
│   ├── dataset.md         # Split statistics & overlap analysis
│   ├── error_analysis.md  # Detailed qualitative failure case breakdown
│   └── final_report.md    # Complete research report for supervisors
├── models/                # Fine-tuned model checkpoints and tokenizer configs
├── results/               # Empirical evaluation tables, JSON metrics, and confusion matrices
├── scripts/               # CLI driver scripts for reproduction
├── src/                   # Core Python package modules
└── tests/                 # 19 passing unit & integration pytest tests
```

---

## Research Integrity Statement

Every benchmark metric reported by InterVul-Graph is calculated from actual test evaluations with recorded seeds, commit hashes, and configurations. Synthetic demonstration code is strictly separated under `demo/sample_projects/` and is never conflated with benchmark data. Heuristic chain risk scores are explicitly demarcated from neural model probabilities.

