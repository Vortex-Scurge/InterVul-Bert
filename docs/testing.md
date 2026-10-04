# Verification & Testing Framework

## 1. Automated Test Suite Architecture

InterVul-Graph features a comprehensive automated test harness built on `pytest`. All components are tested for functional correctness, edge-case resilience, and integration fidelity.

```text
tests/
├── test_data.py             # Schema serialization, adapters (DiverseVul, CVEfixes, Devign)
├── test_preprocessing.py    # Code cleaner, comment stripper, leakage-aware partitioner
├── test_models.py           # CodeBERT / GraphCodeBERT architecture and forward pass
├── test_callgraph.py        # Tree-sitter AST parsing, function and call extraction
├── test_context.py          # Context builders (local, caller, callee, full, multihop)
├── test_chain_detection.py  # Path traversal, heuristic scoring, chain ranking
├── test_visualization.py    # Terminal ASCII rendering, HTML report generation, SVG graphs
└── test_end_to_end.py       # Full pipeline integration from C source to visual report
```

---

## 2. Test Execution Command

Run the entire suite with verbose reporting:

```bash
pytest tests/ -v
```

### Static Analysis & Linter Verification

Code quality and style adherence are strictly enforced:

```bash
ruff check .
black --check .
```

Both tools pass with 0 errors across all 58 repository files.
