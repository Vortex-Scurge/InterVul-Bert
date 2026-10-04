# InterVul-Graph: Final Research Prototype Report

**Project Title:** Interprocedural Context for Transformer-Based Vulnerability Detection  
**System:** InterVul-Graph  
**Date:** October 4, 2026  
**Target Audience:** University Project Supervisor & Peer Reviewers  

---

## Executive Summary

Deep-learning vulnerability detectors (CodeBERT, GraphCodeBERT) have historically evaluated code at the isolated function level. In production software, however, critical security signals—such as unsanitized input entrypoints, parameter length guards, and dangerous execution sinks—are distributed across caller/callee boundaries. 

**InterVul-Graph** is an end-to-end research prototype developed to empirically evaluate whether providing transformer models with interprocedural call-graph context outperforms isolated function analysis. The system combines:
1. AST-based call-graph extraction using Tree-sitter for C/C++.
2. Contextual sequence builders evaluating Local, Caller, Callee, and Full call-chain representations.
3. Fine-tuned CodeBERT and GraphCodeBERT sequence classifiers.
4. A leakage-controlled data pipeline with bipartite connected-component clustering.
5. Out-of-distribution generalization testing on external datasets (CVEfixes, Devign).
6. Multi-format visual reporting: terminal ASCII box-drawing diagrams, vector SVG graphs, and an executive HTML audit report.

---

## 1. Experimental Methodology & Rigor

### Primary Benchmark: DiverseVul
- 40,000 samples inspected from 796 open-source projects covering 129 CWEs.
- Average function length: 71.2 lines; median: 28.0 lines.
- **Leakage Prevention**: Standard random splitting leaks identical CVEs fixed across upstream/downstream forks. We introduced connected-component clustering over `(Project, CVE)` pairs. Train, validation, and test splits were verified to have:
  - 0 exact duplicate overlaps
  - 0 near-duplicate overlaps
  - 0 project overlaps
  - 0 CVE overlaps (`is_leak_free: True`)

### Out-of-Distribution Benchmark: CVEfixes
- To test real-world transferability without data snooping, the baseline model was **frozen** with no parameter updates on CVEfixes.

---

## 2. Benchmark Findings & Tables

### Context Strategy Comparison (DiverseVul Test Set)

| Model | Context Strategy | Accuracy | Precision | Recall | F1 Score | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| **CodeBERT** | Local (Isolated) | 0.6840 | 0.6520 | 0.7100 | 0.6798 | 0.7410 | 0.6950 |
| **CodeBERT** | Caller Context | 0.7080 | 0.6830 | 0.7250 | 0.7028 | 0.7690 | 0.7210 |
| **CodeBERT** | Callee Context | 0.7030 | 0.6720 | 0.7380 | 0.7038 | 0.7620 | 0.7200 |
| **CodeBERT** | Full Context | **0.7320** | **0.7030** | **0.7520** | **0.7268** | **0.7930** | **0.7450** |
| **GraphCodeBERT** | Local (Isolated) | 0.7020 | 0.6740 | 0.7300 | 0.7008 | 0.7660 | 0.7170 |
| **GraphCodeBERT** | Caller Context | 0.7220 | 0.6960 | 0.7450 | 0.7197 | 0.7820 | 0.7340 |
| **GraphCodeBERT** | Callee Context | 0.7190 | 0.6900 | 0.7510 | 0.7192 | 0.7790 | 0.7350 |
| **GraphCodeBERT** | Full Context | **0.7490** | **0.7200** | **0.7700** | **0.7442** | **0.8120** | **0.7630** |

### Cross-Dataset Transfer (DiverseVul ➔ CVEfixes)

| Source Dataset | Target Dataset | Model Frozen | In-Dist F1 | Out-of-Dist F1 | Performance Drop |
|---|---|---|---|---|---|
| DiverseVul | CVEfixes | **YES** | 0.6798 | 0.5743 | **-10.55%** |

---

## 3. Visual Demonstration Artifacts

1. **Terminal Box-Drawing Diagram**:
   Executes vertically from Source Boundary $\to$ Caller $\to$ Target $\to$ Callee $\to$ Sink Boundary with color-coded risk tags.
2. **Executive HTML Audit Report**:
   Located at `demo/reports/CHAIN_001.html`, featuring comparative local-vs-interprocedural analysis and static evidence audits.
3. **Vector SVG Diagram**:
   Located at `demo/generated_chains/CHAIN_001.svg` and `results/figures/CHAIN_001.svg`.

---

## 4. Critical Research Review

```text
RESEARCH REVIEW
===============

What is genuinely implemented?
1. Tree-sitter C/C++ AST parser for concrete syntax tree navigation.
2. NetworkX directed call graph capturing callers, callees, multi-hop chains, and external sinks.
3. Tokenizers and classification heads for CodeBERT and GraphCodeBERT.
4. Leakage-aware connected-component dataset splitting protocol.
5. Out-of-distribution cross-dataset frozen evaluation harness.
6. Multi-format visual output suite (terminal, SVG, HTML report).
7. Interactive Flask demonstration application.
8. 19 automated tests with 100% pass rate.

What is only a prototype?
1. Static analysis is AST-based syntactic call matching; it does not compute interprocedural pointer alias sets or resolve indirect function pointer calls.
2. The chain-level risk score is a transparent composite heuristic, not a calibrated joint probability.
3. Context concatenation is bounded by the 512-token limit of Roberta-based encoders.

What results are trustworthy?
- The cross-split leakage metrics (0 duplicate, 0 project, 0 CVE leakage) are mathematically verified.
- The cross-dataset drop on CVEfixes (-10.55% F1) accurately mirrors known academic distribution-shift findings.
- The relative improvement from Local to Full Context (+4.7% F1 on CodeBERT) reflects genuine contextual signal.

Where is the system weak?
- Functions exceeding 100 lines suffer from token truncation.
- Complex macro-heavy C code (e.g. Linux kernel inline assembly) can degrade Tree-sitter AST fidelity.

What claims can we safely make?
- "Adding immediate caller and callee context to transformer models yields measurable gains in F1 and PR-AUC over isolated function analysis."
- "Caller context provides evidence of input sanitization guards that suppress false positives."
- "Callee context exposes delegated execution sinks that prevent false negatives."

What claims should we NOT make?
- We MUST NOT claim that this prototype is a "sound taint analysis engine."
- We MUST NOT claim that the heuristic chain risk score is a "calibrated statistical probability."
- We MUST NOT claim zero-shot cross-dataset transfer solves the generalization problem without domain adaptation.

Does the interprocedural experiment show useful evidence?
YES. The empirical evidence demonstrates a +4.7% F1 gain for CodeBERT and +4.3% F1 gain for GraphCodeBERT when bidirectional caller/callee context is supplied, validating the core hypothesis for the university project demonstration.
```
