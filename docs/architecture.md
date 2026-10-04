# InterVul-Graph: System Architecture

## Overview

InterVul-Graph is an interprocedural vulnerability detection and propagation analysis prototype. It investigates whether transformer-based language models (specifically CodeBERT and GraphCodeBERT) exhibit superior detection performance and lower false-alarm rates when augmented with interprocedural caller and callee context, compared to isolated single-function analysis.

```text
                               ┌─────────────────────────┐
                               │ Raw Source Code (C/C++) │
                               └────────────┬────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │   Tree-sitter AST Parser Engine   │
                           │     (C and C++ Grammar Units)    │
                           └────────────────┬─────────────────┘
                                            │
                       ┌────────────────────┴────────────────────┐
                       │                                         │
                       ▼                                         ▼
         ┌───────────────────────────┐             ┌───────────────────────────┐
         │ Function Definition Index │             │   Call Expression Visitor │
         │   (AST Visitor Extract)   │             │   (Caller / Callee Sites) │
         └─────────────┬─────────────┘             └─────────────┬─────────────┘
                       │                                         │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │      CallGraph Representation    │
                           │   (NetworkX Directed Multigraph) │
                           └────────────────┬─────────────────┘
                                            │
                       ┌────────────────────┴────────────────────┐
                       │                                         │
                       ▼                                         ▼
         ┌───────────────────────────┐             ┌───────────────────────────┐
         │ Neural Scoring Engine     │             │ Security Chain Detector   │
         │ - CodeBERT Classifier     │             │ - Source/Sink Identifier  │
         │ - GraphCodeBERT Classifier│             │ - Path Enumeration        │
         └─────────────┬─────────────┘             └─────────────┬─────────────┘
                       │                                         │
                       └────────────────────┬────────────────────┘
                                            │
                                            ▼
                           ┌──────────────────────────────────┐
                           │    Interprocedural Chain Scorer  │
                           │    - Node-Level Risk Table       │
                           │    - Heuristic Path Metric       │
                           │    - Local vs Context Delta      │
                           └────────────────┬─────────────────┘
                                            │
                       ┌────────────────────┴────────────────────┐
                       │                                         │
                       ▼                                         ▼
         ┌───────────────────────────┐             ┌───────────────────────────┐
         │ Visual Output Suite       │             │ Demonstration Interfaces  │
         │ - ASCII Terminal Diagram  │             │ - Interactive Web UI      │
         │ - Supervisor HTML Report  │             │ - CLI Batch Runner        │
         │ - Vector SVG Call Graph   │             │ - Regression Test Harness │
         └───────────────────────────┘             └───────────────────────────┘
```

---

## Architectural Components

### 1. Abstract Syntax Tree (AST) Parser Layer (`src/callgraph/`)
- **Technology**: Native Tree-sitter bindings (`tree-sitter-c` and `tree-sitter-cpp`).
- **Core Abstractions**:
  - `CodeParser`: Encapsulates multi-language grammars and manages parse trees.
  - `ASTVisitor`: Traverses the concrete syntax tree, extracting function signatures, statement bounds, and call sites.
  - `CallGraph`: Implements a directed graph using `networkx.DiGraph`. Nodes correspond to individual function definitions (or unresolved external library calls); edges model call sites annotated with line numbers and arguments.

### 2. Neural Feature Extraction & Classification Head (`src/models/`)
- **Base Encoders**:
  - `microsoft/codebert-base`: Pretrained on CodeSearchNet with masked language modeling (MLM) and bimodal contrastive objectives.
  - `microsoft/graphcodebert-base`: Pretrained with data-flow graph (DFG) edges and variable alignment.
- **Classification Head**:
  - Token representation extracted from the `<s>` / `[CLS]` sequence token.
  - Non-linear projection: `Dense(768, 768) -> Tanh() -> Dropout(0.1) -> Dense(768, 2)`.
  - Output softmax yields calibrated single-function vulnerability probability $P(\text{vulnerable} \mid c)$.

### 3. Interprocedural Context Aggregator (`src/interprocedural/`)
- **Context Construction Strategies**:
  - **Local Context**: Target function $f_{\text{target}}$ in complete isolation.
  - **Caller Context**: $\bigcup_{c \in \text{Callers}(f)} c \parallel f_{\text{target}}$.
  - **Callee Context**: $f_{\text{target}} \parallel \bigcup_{e \in \text{Callees}(f)} e$.
  - **Full Context**: $\text{Callers}(f) \parallel f_{\text{target}} \parallel \text{Callees}(f)$.
  - **Multi-Hop Chains**: End-to-end paths linearized from source to sink.
- **Security Chain Detector**:
  - Identifies untrusted input sources (e.g., `recv`, `fgets`, `read`, network dispatchers).
  - Traces intermediate transformations and propagators.
  - Detects security-sensitive execution sinks (e.g., `strcpy`, `system`, `execute_query`, `memcpy`).
  - Computes transparent heuristic risk scores across candidate chains.

### 4. Leakage-Controlled Data Pipeline (`src/preprocessing/`)
- **Connected-Component Deduplication & Splitting**:
  - Functions sharing identical normalized bodies are deduplicated.
  - Projects and CVEs form bipartite graph components; each connected component is assigned atomically to either train, validation, or test.
  - Zero leakage of projects, CVEs, or duplicate code across splits.

### 5. Multi-Format Visual Reporting Suite (`src/visualization/`)
- **Terminal Visualizer**: Box-drawing ASCII art showing vertical flow from Source $\to$ Function A $\to$ Target $\to$ Sink.
- **HTML Report Generator**: Self-contained, responsive HTML audits with risk meters, local-vs-interprocedural comparative analysis, and static analysis checklists.
- **Vector SVG Generator**: Scalable vector diagrams with color-coded risk nodes and directed call arrows.
