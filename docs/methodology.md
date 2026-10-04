# Methodology: Interprocedural Vulnerability Detection

## 1. Problem Formulation

In software security, vulnerabilities rarely reside entirely within an isolated function boundary. Standard deep-learning benchmarks (such as Devign, Big-Vul, and DiverseVul) conventionally format vulnerability detection as a binary classification problem over isolated function tokens:

$$f: \mathcal{T}_{\text{func}} \to \{0, 1\}$$

where $\mathcal{T}_{\text{func}} = (t_1, t_2, \dots, t_N)$ represents the sequence of tokens belonging strictly to function $F$.

### The Missing Context Dilemma
1. **Unchecked Caller Inputs (Missing Preconditions)**:
   A target function $F_{\text{target}}$ performs a sensitive memory operation (e.g. `memcpy(dest, src, len)`) under the implicit contract that caller $F_{\text{caller}}$ sanitized $len$. If $F_{\text{caller}}$ omitted sanitization, $F_{\text{target}}$ is exploitable. An isolated model assessing $F_{\text{target}}$ cannot know whether $F_{\text{caller}}$ performed bounds checks.
2. **Delegated Sink Invocations (Missing Postconditions)**:
   A dispatcher function $F_{\text{dispatcher}}$ receives a command string and passes it to helper $F_{\text{exec}}$. If $F_{\text{exec}}$ executes `system()`, the vulnerability exists in the combined chain.
3. **False Positive Suppression**:
   A function uses `strcpy`, which triggers naive neural pattern detectors. However, the caller enforces a strict guard `if (strlen(msg) < 32)`. Isolated models trigger false positives because the guard is outside the function window.

---

## 2. Research Hypothesis

We formulate the core experimental hypothesis:

> **Hypothesis $H_1$**: Providing transformer-based models with structural interprocedural caller/callee context reduces both false negatives (by exposing unsanitized sources and dangerous sinks) and false positives (by revealing upstream validation guards), yielding higher $F_1$ and $PR\text{-}AUC$ scores than isolated function modeling.

---

## 3. Experimental Setup & Context Formulation

We evaluate four hierarchical context regimes for any target function $F$:

| Strategy | Sequence Composition | Contextual Horizon |
|---|---|---|
| **Local** | $F_{\text{target}}$ | 0 hops (Isolated Function) |
| **Caller** | $\bigcup_{C \in \text{Callers}(F)} C \parallel F_{\text{target}}$ | Upstream 1 hop |
| **Callee** | $F_{\text{target}} \parallel \bigcup_{E \in \text{Callees}(F)} E$ | Downstream 1 hop |
| **Full** | $\text{Callers}(F) \parallel F_{\text{target}} \parallel \text{Callees}(F)$ | Bidirectional 1 hop |
| **Multi-Hop** | $\text{Source} \parallel F_1 \parallel \dots \parallel F_{\text{target}} \parallel \dots \parallel \text{Sink}$ | End-to-End Taint Path |

---

## 4. Leakage Prevention Protocol

Data leakage is a severe threat to validity in software vulnerability research. We enforce a four-tiered leakage barrier:

1. **Exact Duplicate Elimination**: MD5 hashing over exact stripped function code.
2. **Near-Duplicate Auditing**: Whitespace and comment normalized hashing eliminates trivial syntactic variations.
3. **Bipartite Project-CVE Component Partitioning**:
   If Project A and Project B share a reported CVE (e.g., in upstream/downstream forks), they are clustered into the same partition, preventing identical vulnerabilities from appearing in both training and test sets.
4. **Out-of-Distribution Cross-Dataset Evaluation**:
   Frozen evaluation on CVEfixes and Devign verifies whether learned representations generalize across completely distinct project ecosystems.

---

## 5. Scoring Methodology

The InterVul-Graph scoring architecture explicitly decouples **function-level model confidence**, **static analysis signals**, and **heuristic chain risk scores**. Risk is never propagated backward from sinks to callers, preserving semantic integrity.

### 1. Function-Level Model Probability
For each internal function $F$, the vulnerability probability is computed directly from CodeBERT's classification head:

$$P(\text{vulnerable}) = \text{Softmax}(\mathbf{z})_1$$

Where $\mathbf{z}$ represents the raw logits. This value represents how strongly the neural model predicts that this individual function is vulnerable in isolation. If the model is not loaded, it is explicitly reported as `unavailable` rather than fabricating neural scores.

Function probabilities are mapped to risk tiers:
- **LOW**: $0.00 \le P < 0.40$
- **MEDIUM**: $0.40 \le P < 0.70$
- **HIGH**: $0.70 \le P \le 1.00$

### 2. Separate Chain Risk Score
Chain risk is evaluated as a composite security score taking into account multiple signals along the call path:
1. Highest function-level vulnerability probability ($P_{\max}$)
2. Verified untrusted input source ($E_{\text{source}} \in \{0, 1\}$)
3. Verified security-sensitive sink ($E_{\text{sink}} \in \{0, 1\}$)
4. Valid source-to-sink reachability path ($E_{\text{path}} \in \{0, 1\}$)

$$\text{Chain Risk Score} = \text{clamp}_{[0, 1]}\left(0.50 \cdot P_{\max} + 0.20 \cdot E_{\text{source}} + 0.20 \cdot E_{\text{sink}} + 0.10 \cdot E_{\text{path}}\right)$$

> **Academic Rigor Note**: This score is explicitly labeled as a **Heuristic Chain Risk Score**, avoiding claims of a calibrated joint probability distribution.

### 3. Chain Evidence Strength
To reflect the unweighted aggregation of supporting evidence across model and structural signals:

$$\text{Chain Evidence Strength} = \frac{P_{\max} + E_{\text{source}} + E_{\text{sink}} + E_{\text{path}}}{4}$$

> **Academic Rigor Note**: This metric is strictly designated as a **prototype evidence aggregation score** (the unweighted mean of available evidence channels). It is never presented as calibrated statistical confidence.

### 4. Interprocedural Comparative Analysis
When comparing function performance in isolation versus whole-program context:
- **Local Analysis**: Reports isolated neural model probability $P(\text{vulnerable})$ ($0 \text{ hops}$).
- **Interprocedural Analysis**: Reports the **Context-Aware Chain Score**, which combines function-level model evidence with interprocedural caller/callee context (prototype/heuristic score).

### 5. Scientifically Honest Separation of Signals
The presentation layer strictly decouples:
- **Model Probability**: Independent CodeBERT probability per function.
- **Static Evidence**: AST and symbol-based source (`fgets`, `recv`) and sink (`strcpy`, `system`) indicators.
- **Interprocedural Evidence**: Call-graph reachability traversal (`Path traversal: CONFIRMED`).
- **Chain Risk Score**: Weighted heuristic composite score ($0.50 \cdot P_{\max} + 0.20 \cdot E_{\text{src}} + 0.20 \cdot E_{\text{snk}} + 0.10 \cdot E_{\text{path}}$).
- **Chain Evidence Strength**: Unweighted mean of evidence components.
- **Function Roles**: `SOURCE`, `INTERMEDIATE`, `HIGH-RISK INTERMEDIATE` (sensitive caller of sink), `SINK`, and `TARGET` (reserved strictly for user-selected targets).
