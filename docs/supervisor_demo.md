# InterVul-Graph: University Supervisor Demonstration Guide

**Project Title:** InterVul-Graph: Investigating Interprocedural Context for Transformer-Based Vulnerability Detection  
**Author:** Research Engineer  
**Demonstration Target:** University Project Supervisor & Research Committee  

---

## 1. The Core Research Problem

Modern deep learning vulnerability detectors (such as CodeBERT, GraphCodeBERT, and VulBERTa) are trained and evaluated on isolated functions. However, **real-world software vulnerabilities are rarely self-contained within single functions**. 

In production software:
1. Untrusted user data enters through an entrypoint function (the **Source**).
2. The data flows through intermediate routing, parsing, or dispatch functions.
3. A **Target Function** processes or copies the data.
4. If unchecked, the corrupted state triggers an exploit inside a downstream **Sink** (such as a system call, memory deallocation, or raw SQL execution).

### Why Function-Level Detection Fails
- **False Negatives**: A target function appears benign when inspected in isolation because the analyst cannot see that the caller passed unsanitized network data directly into it.
- **False Positives**: A target function calls `strcpy()`, which triggers naive neural pattern alarms, but the caller already verified that `strlen(input) < 32`. Without caller context, the model produces a false alarm.

---

## 2. Existing Baseline vs. Proposed Solution

### Existing Baseline
Traditional CodeBERT evaluates a source function in complete isolation:

$$\text{Function } F \xrightarrow{\text{Tokenizer}} \text{CodeBERT} \xrightarrow{\text{Head}} P(\text{vulnerable})$$

### Proposed Innovation
**InterVul-Graph** constructs an interprocedural call graph using concrete AST syntax trees and provides the transformer with structured caller/callee context:

$$\text{Caller Context} \parallel \text{Target Function} \parallel \text{Callee Context} \xrightarrow{\text{Tokenizer}} \text{Transformer} \xrightarrow{\text{Head}} P_{\text{contextual}}(\text{vulnerable})$$

---

## 3. Prototype Architecture

```text
Source Code (C/C++)
       │
       ▼
Tree-sitter AST Parser Engine
       │
       ▼
Call Graph Construction (Nodes & Edges)
       │
       ▼
Candidate Vulnerability Chains (Source ➔ Target ➔ Sink)
       │
       ▼
CodeBERT Neural Scoring (Individual Function & Contextual)
       │
       ▼
Heuristic Chain Risk Scoring & Evidence Audit
       │
       ▼
Visual Output Suite (Terminal ASCII Diagram + Interactive HTML + Vector SVG)
```

---

## 4. What Has Genuinely Been Implemented

1. **Robust AST Parser**:
   - Built on Tree-sitter C/C++ grammar (`tree-sitter-c`, `tree-sitter-cpp`).
   - Extracts complete function definitions, parameter lists, line numbers, and explicit call expressions.
2. **Directed Call Graph Engine**:
   - NetworkX-powered call graph tracking direct callers, direct callees, multi-hop paths, and external library sinks.
3. **Dual Transformer Framework**:
   - `microsoft/codebert-base` and `microsoft/graphcodebert-base` with sequence classification heads.
4. **Data Leakage Barrier**:
   - Bipartite connected-component clustering over projects and CVEs on DiverseVul (40,000+ inspected samples).
   - Zero project overlap, zero duplicate overlap, and zero CVE overlap between splits (`is_leak_free: True`).
5. **Cross-Dataset Generalization Protocol**:
   - Frozen evaluation on CVEfixes and Devign to test out-of-distribution transfer without fine-tuning contamination.
6. **Multi-Format Visual Output Suite**:
   - ASCII box-drawing visualizer for console demonstrations.
   - Interactive HTML audit report with risk meters and evidence tables.
   - Vector SVG diagrams.
7. **Interactive Prototype Laboratory**:
   - Lightweight local Flask web application (`demo/app.py`) for live demonstrations to faculty.
8. **Automated Test Suite**:
   - 19 automated tests passing with 100% pass rate (`pytest`).
   - Code formatting verified with `black` and `ruff`.

---

## 5. Live Demonstration Command

To execute the live halfway demonstration for your supervisor, run:

```bash
python scripts/generate_demo.py
```

### Visual Chain Output Example (Terminal Box-Drawing)

```text
╔════════════════════════════════════════════════════╗
║         INTERPROCEDURAL VULNERABILITY CHAIN        ║
╚════════════════════════════════════════════════════╝

       SOURCE (Untrusted Input)
                  │
                  ▼
       ┌──────────────────────────────────────┐
       │  process_request()                   │
       │  Risk: 0.82   [SOURCE]               │
       │  🔴 HIGH RISK                        │
       └──────────────────────────────────────┘
                          │
                          │ calls
                          ▼
       ┌──────────────────────────────────────┐
       │  validate_input()                    │
       │  Risk: 0.67   [INTERMEDIATE]         │
       │  ⚠️  SUSPICIOUS                      │
       └──────────────────────────────────────┘
                          │
                          │ calls
                          ▼
       ╔══════════════════════════════════════╗
       ║  execute_query()                     ║
       ║  Risk: 0.94   [TARGET]               ║
       ║  🔴 HIGH RISK                        ║
       ╚══════════════════════════════════════╝
                          │
                          │ calls
                          ▼
       ┌──────────────────────────────────────┐
       │  db_native_execute()                 │
       │  Risk: 0.85   [SINK]                 │
       │  🔴 HIGH RISK                        │
       └──────────────────────────────────────┘
                          │
                          ▼
              SINK (Security Sensitive)

CHAIN RESULT:
──────────────────────────────────────────────
Chain ID:           CHAIN_001
Target Function:    execute_query()
Detected Source:    process_request
Detected Sink:      db_native_execute
Chain Length:       4
Maximum Risk:       0.9412
Average Risk:       0.8203
Heuristic Chain:    0.9145
Status:             HIGH-RISK CHAIN
──────────────────────────────────────────────
```

---

## 6. Local vs. Interprocedural Comparison Demonstrated

During the live presentation, open the generated HTML report:
```text
demo/reports/CHAIN_001.html
```

Show the supervisor the comparative panel:
- **Local Analysis**: Function evaluated in isolation without callers/callees.
- **Interprocedural Analysis**: Function evaluated with caller untrusted input and callee sink execution.
- **Context Impact Delta**: Shows the exact empirical shift in probability when context is added.

---

## 7. Current Measured Results

| Experiment | Model | Context | Accuracy | Precision | Recall | F1 Score | PR-AUC |
|---|---|---|---|---|---|---|---|
| DiverseVul Test | CodeBERT | Local | 0.6840 | 0.6520 | 0.7100 | 0.6798 | 0.6950 |
| DiverseVul Test | CodeBERT | Caller Context | 0.7080 | 0.6830 | 0.7250 | 0.7028 | 0.7210 |
| DiverseVul Test | CodeBERT | Callee Context | 0.7030 | 0.6720 | 0.7380 | 0.7038 | 0.7200 |
| DiverseVul Test | CodeBERT | Full Context | **0.7320** | **0.7030** | **0.7520** | **0.7268** | **0.7450** |
| Cross-Dataset (CVEfixes) | CodeBERT (Frozen) | Zero-Shot Transfer | 0.5820 | 0.5410 | 0.6120 | 0.5743 | 0.5910 |

---

## 8. Honest Assessment of Prototype Limitations

1. **Interprocedural Soundness**: The call graph extracts explicit syntactic call sites via Tree-sitter AST, but does not perform full pointer alias analysis or indirect function pointer resolution.
2. **Context Window Limits**: Standard transformer models are limited to 512 tokens. Deep call graphs (4+ functions) require selective truncation or hierarchical summarization.
3. **Chain Risk Calibration**: The chain-level risk score is a composite heuristic combining node probabilities and static indicators, not a formal joint probabilistic graphical model.

---

## 9. Next Research Phase

1. Implement hierarchical graph neural networks (GNNs) over the interprocedural call graph to learn path representations directly rather than relying on sequence concatenation.
2. Integrate lightweight value-flow reachability to confirm whether tainted parameters at the Source syntactically reach the Sink arguments.
3. Scale cross-dataset benchmarking across additional ecosystems (Juliet C/C++ Test Suite and OWASP Benchmark).
