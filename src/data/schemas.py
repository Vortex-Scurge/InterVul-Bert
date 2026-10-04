"""Canonical data models and schemas for InterVul-Graph."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class VulnerabilitySample:
    """Canonical representation of a code sample."""

    sample_id: str
    code: str
    target: int  # 0: safe, 1: vulnerable
    project: str = "unknown"
    commit_id: str | None = None
    cwe: str | None = None
    cve: str | None = None
    language: str = "c"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert sample to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilitySample":
        """Instantiate sample from dictionary."""
        return cls(
            sample_id=str(data.get("sample_id", "")),
            code=str(data.get("code", "")),
            target=int(data.get("target", data.get("label", 0))),
            project=str(data.get("project", "unknown")),
            commit_id=data.get("commit_id"),
            cwe=data.get("cwe"),
            cve=data.get("cve"),
            language=str(data.get("language", "c")),
            metadata=data.get("metadata", {}),
        )


@dataclass
class CallGraphNode:
    """Node in an interprocedural call graph representing a function."""

    name: str
    code: str
    start_line: int = 1
    end_line: int = 1
    file_path: str = ""
    is_source: bool = False
    is_sink: bool = False
    is_target: bool = False
    source_type: str | None = None
    sink_type: str | None = None
    risk_score: float = 0.0
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CallGraphEdge:
    """Directed edge in an interprocedural call graph representing a call site."""

    caller: str
    callee: str
    call_site_line: int = 1
    arguments: list[str] = field(default_factory=list)
    call_type: str = "direct"  # direct, virtual, recursive, external

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityChain:
    """Security-relevant caller-target-callee chain."""

    chain_id: str
    nodes: list[dict[str, Any]]  # [{"function": "name", "score": float, "role": str}]
    edges: list[list[str]]  # [["A", "B"], ["B", "C"]]
    source_func: str | None = None
    sink_func: str | None = None
    target_func: str = ""
    max_risk_score: float = 0.0
    avg_risk_score: float = 0.0
    heuristic_chain_score: float = 0.0
    chain_risk_score: float = 0.0
    chain_confidence: float = 0.0
    chain_evidence_strength: float = 0.0
    is_targeted: bool = False
    path_traversal: str = "CONFIRMED"
    assessment: str = "UNCERTAIN"
    max_model_probability: float | None = None
    status: str = "UNCERTAIN"  # HIGH RISK, MEDIUM RISK, LOW RISK
    detection_method: str = "AST Call-Graph + CodeBERT Scoring"
    static_evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.chain_evidence_strength == 0.0 and self.chain_confidence > 0.0:
            self.chain_evidence_strength = self.chain_confidence
        elif self.chain_confidence == 0.0 and self.chain_evidence_strength > 0.0:
            self.chain_confidence = self.chain_evidence_strength

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PredictionOutput:
    """Standard model inference result."""

    sample_id: str
    prediction: int  # 0 or 1
    probability: float  # P(vulnerable)
    label: str  # "safe" or "vulnerable"
    ground_truth: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
