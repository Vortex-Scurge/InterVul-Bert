# Interprocedural Vulnerability-Chain Detection

## 1. Concept: Vulnerability Propagation Chains

Real-world vulnerabilities frequently manifest as data and control flow paths connecting:

$$\text{Source} \xrightarrow{\text{calls}} \text{Function } A \xrightarrow{\text{calls}} \dots \xrightarrow{\text{calls}} \text{Target Function} \xrightarrow{\text{calls}} \dots \xrightarrow{\text{calls}} \text{Sink}$$

Where:
- **Source**: Untrusted input ingestion points (e.g., standard input, sockets, HTTP headers, environment variables).
- **Intermediate Nodes**: Propagator, parser, or transformer functions that manipulate or pass parameters.
- **Target Function**: The specific function under audit.
- **Sink**: Security-sensitive operations where tainted or unbounded execution leads to exploitation (e.g., `strcpy`, `system`, SQL execution, memory deallocation).

---

## 2. Detection Pipeline

```text
C/C++ Source File
       │
       ▼
Tree-sitter AST Parser
       │
       ▼
CallGraph Construction
  ├── Node Index: Functions, start/end lines, source/sink flags
  └── Edge Index: Call sites, call arguments, line numbers
       │
       ▼
Candidate Path Extraction (NetworkX DiGraph traversal)
       │
       ▼
Function Risk Scoring (Neural Inference per Node)
       │
       ▼
Composite Chain Risk Calculation
  ├── Target Risk Weighting
  ├── Source Presence Bonus
  ├── Sink Presence Bonus
  └── Max & Average Path Risk
       │
       ▼
Visual Outputs (ASCII Terminal, Vector SVG, Interactive HTML)
```

---

## 3. Risk Assessment Taxonomy

To maintain research integrity and avoid claiming sound static taint analysis, the prototype utilizes a clearly labeled composite risk heuristic:

| Classification | Criteria | Meaning |
|---|---|---|
| **HIGH-RISK CHAIN** | Verified Source + Verified Sink + Target Risk $\ge 0.70$ (or Chain Risk $\ge 0.75$) | Untrusted input flows to a dangerous sink with high neural model concern. |
| **LIKELY VULNERABLE** | Chain Risk $\ge 0.60$ or Max Risk $\ge 0.80$ | Strong neural indicators or dangerous sink invocation present. |
| **UNCERTAIN** | $0.40 \le \text{Chain Risk} < 0.60$ | Ambiguous signals; manual code audit recommended. |
| **SAFE CHAIN** | Chain Risk $< 0.40$ or confirmed caller-side validation | Low model risk scores and safe boundary checks. |

> **Disclaimer**: This prototype combines AST call-graph extraction with transformer embeddings. It is an *interprocedural vulnerability-chain prototype*, not a sound or complete static taint analysis engine.
