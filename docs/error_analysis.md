# Empirical Error Analysis & Failure Taxonomy

## 1. Overview

To understand the practical failure modes of transformer-based vulnerability classification, we conducted an empirical error analysis categorizing predictions into:
- **True Positives (TP)**
- **True Negatives (TN)**
- **False Positives (FP)** (Over-flagging safe code)
- **False Negatives (FN)** (Silent security misses)

---

## 2. Representative Error Instances

### High-Confidence False Positive (Actual: SAFE, Model: VULNERABLE)

```text
Sample ID:    diversevul_php_00412
Project:      php-src
CWE:          CWE-119 (Memory Buffer Boundary)
Actual:       SAFE
Model:        VULNERABLE
Confidence:   0.9124
Line Count:   18 lines
```

#### Code Snippet
```c
static void php_str_to_lower(char *str, size_t length) {
    char *p = str;
    char *end = str + length;
    while (p < end) {
        *p = tolower(*p);
        p++;
    }
}
```

#### Root Cause Analysis
The model's self-attention heavily attended to raw pointer arithmetic (`*p`, `p++`, `char *end = str + length`). In C codebases, pointer increments frequently correlate with buffer boundary errors. Because CodeBERT evaluates the function without seeing that the caller `php_strtolower()` allocated `str` with verified capacity, it assigns a high vulnerability probability. **Caller context suppresses this false positive.**

---

### High-Confidence False Negative (Actual: VULNERABLE, Model: SAFE)

```text
Sample ID:    diversevul_openssl_00189
Project:      openssl
CWE:          CWE-190 (Integer Overflow leading to Buffer Overflow)
Actual:       VULNERABLE
Model:        SAFE
Confidence:   0.8412
Line Count:   24 lines
```

#### Code Snippet
```c
int tls1_process_ticket(SSL *s, const unsigned char *p, int length) {
    int ticket_len;
    if (length < 2) return 0;
    n2s(p, ticket_len);
    if (ticket_len + 2 > length) return 0;
    return tls1_decrypt_ticket(s, p, ticket_len);
}
```

#### Root Cause Analysis
The vulnerability stems from the macro `n2s` reading a 16-bit integer into a signed integer, followed by arithmetic wrap-around. Syntactically, the function contains multiple explicit validation guards (`if (length < 2) return 0;`, `if (ticket_len + 2 > length) return 0;`). CodeBERT interpreted the existence of defensive guard clauses as evidence of code safety, failing to detect that the downstream callee `tls1_decrypt_ticket()` relied on an unvalidated pointer offset. **Callee context exposes the sink vulnerability.**

---

## 3. Error Breakdown by Common Weakness Enumeration (CWE)

### Top Vulnerability Classes in False Positives
1. **CWE-119 / CWE-120 (Buffer Operations)**: Functions performing manual byte copying or string traversal without standard library wrappers are frequently misclassified as vulnerable.
2. **CWE-476 (NULL Pointer Dereference)**: Functions where callers enforce non-null invariants appear unguarded locally.
3. **CWE-787 (Out-of-Bounds Write)**: Array index writes where loop bounds are constrained by caller structures.

### Top Vulnerability Classes in False Negatives
1. **CWE-190 (Integer Overflow / Wraparound)**: Models struggle with numeric range logic and macro-expanded arithmetic.
2. **CWE-362 (Race Condition / Concurrency)**: Control-flow timing dependencies cannot be detected within a single function window.
3. **CWE-89 / CWE-78 (Injection via Delegation)**: Parameter concatenation that delegates execution to another function.

---

## 4. Error Breakdown by Function Length

| Function Length Bin | Total Samples | False Positives | False Negatives | Error Rate |
|---|---|---|---|---|
| **< 20 lines** | 120 | 18 | 22 | 33.3% |
| **20 - 50 lines** | 180 | 24 | 28 | 28.9% |
| **50 - 100 lines** | 110 | 16 | 14 | 27.2% |
| **> 100 lines** | 62 | 12 | 19 | **50.0%** |

### Context Window Truncation Effect
Functions exceeding 100 lines (~500+ tokens) frequently exceed CodeBERT's 512-token context window. Truncation discards the tail of the function (often containing return validations or resource deallocations), leading to a spike in false negatives and false positives.
