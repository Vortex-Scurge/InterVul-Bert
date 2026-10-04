"""Function-level neural scoring and transparent heuristic chain risk computation."""

import numpy as np
import torch
from torch import nn
from transformers import PreTrainedTokenizer

from ..callgraph.graph_builder import CallGraph
from ..data.schemas import CallGraphNode
from ..utils.logger import get_logger

logger = get_logger("InterVul-Graph.interprocedural.scoring")


class FunctionScorer:
    """Runs CodeBERT on individual functions to produce genuine vulnerability probabilities."""

    def __init__(
        self,
        model: nn.Module | None = None,
        tokenizer: PreTrainedTokenizer | None = None,
        device: torch.device | None = None,
        max_length: int = 512,
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device or (torch.device("cuda" if torch.cuda.is_available() else "cpu"))
        self.max_length = max_length
        if self.model is not None:
            self.model.eval()

    @staticmethod
    def get_risk_level(probability: float | None) -> str:
        """Convert function vulnerability probability into simple 3-tier risk level:
        0.00 – 0.39 → LOW
        0.40 – 0.69 → MEDIUM
        0.70 – 1.00 → HIGH
        """
        if probability is None:
            return "UNAVAILABLE"
        if probability < 0.40:
            return "LOW"
        elif probability < 0.70:
            return "MEDIUM"
        else:
            return "HIGH"

    @torch.no_grad()
    def score_code(self, code: str) -> float | None:
        """Run model inference on a single code snippet and return P(vulnerable).

        Returns None if CodeBERT model is unavailable.
        """
        if self.model is None or self.tokenizer is None:
            return None
        if not code or not code.strip():
            return 0.0

        encoded = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"].to(self.device)
        attention_mask = encoded["attention_mask"].to(self.device)

        out = self.model(input_ids=input_ids, attention_mask=attention_mask)
        probs = torch.softmax(out["logits"], dim=-1)[0]
        return round(float(probs[1].item()), 4)

    def score_call_graph(self, callgraph: CallGraph) -> dict[str, float | None]:
        """Score each function individually without backward propagation of sink risk."""
        scores: dict[str, float | None] = {}
        for node_name in callgraph.graph.nodes:
            node_data: CallGraphNode | None = callgraph.get_node(node_name)
            if node_data and not node_data.features.get("external", False):
                # Score genuine code using model
                prob = self.score_code(node_data.code)
                risk_lvl = self.get_risk_level(prob)
                node_data.features["model_probability"] = prob
                node_data.features["risk_level"] = risk_lvl
                node_data.risk_score = prob if prob is not None else 0.0
                scores[node_name] = prob
            else:
                # External nodes (known sinks / sources)
                scores[node_name] = None
                if node_data:
                    node_data.features["model_probability"] = None
                    if node_data.is_sink:
                        node_data.features["static_evidence"] = f"KNOWN SINK ({node_name})"
                        node_data.features["risk_level"] = "HIGH"
                        node_data.risk_score = 0.85
                    elif node_data.is_source:
                        node_data.features["static_evidence"] = f"UNTRUSTED SOURCE ({node_name})"
                        node_data.features["risk_level"] = "MEDIUM"
                        node_data.risk_score = 0.60
                    else:
                        node_data.features["static_evidence"] = "EXTERNAL FUNCTION"
                        node_data.features["risk_level"] = "LOW"
                        node_data.risk_score = 0.10
        return scores


class HeuristicChainScorer:
    """Computes transparent heuristic risk scores for multi-function chains.

    IMPORTANT:
    This is explicitly designated as a heuristic chain-risk score,
    not a calibrated statistical probability.
    """

    @staticmethod
    def calculate_chain_risk(
        node_scores_or_max: list[float] | float | None = None,
        source_detected: bool = False,
        sink_detected: bool = False,
        has_path: bool = True,
        max_function_probability: float | None = None,
        has_source: bool | None = None,
        has_sink: bool | None = None,
        target_score: float | None = None,
    ) -> float:
        """Calculate separate Chain Risk Score.

        Formula:
            chain_score =
                0.50 * max_function_probability
              + 0.20 * source_evidence
              + 0.20 * sink_evidence
              + 0.10 * path_evidence

        where:
            source_evidence = 1.0 if source detected else 0.0
            sink_evidence   = 1.0 if sink detected else 0.0
            path_evidence   = 1.0 if source-to-sink path exists else 0.0
        """
        # Support both new signature and legacy kwarg aliases
        if has_source is not None:
            source_detected = has_source
        if has_sink is not None:
            sink_detected = has_sink

        if max_function_probability is not None:
            max_p = float(max_function_probability)
        elif isinstance(node_scores_or_max, list):
            valid_scores = [s for s in node_scores_or_max if s is not None]
            max_p = max(valid_scores) if valid_scores else 0.0
        elif isinstance(node_scores_or_max, (float, int)):
            max_p = float(node_scores_or_max)
        else:
            max_p = 0.0

        source_evidence = 1.0 if source_detected else 0.0
        sink_evidence = 1.0 if sink_detected else 0.0
        path_evidence = 1.0 if has_path else 0.0

        chain_score = (
            0.50 * max_p + 0.20 * source_evidence + 0.20 * sink_evidence + 0.10 * path_evidence
        )
        return round(float(np.clip(chain_score, 0.0, 1.0)), 4)

    @staticmethod
    def calculate_chain_evidence_strength(
        model_evidence: float | None = None,
        source_detected: bool = False,
        sink_detected: bool = False,
        has_path: bool = True,
    ) -> float:
        """Calculate prototype Chain Evidence Strength (unweighted evidence aggregation mean).

        NOTE: This is explicitly a prototype evidence aggregation score, NOT calibrated statistical confidence.

        Formula:
            average of:
            - model evidence (max function probability)
            - source evidence (1.0 if source detected else 0.0)
            - sink evidence (1.0 if sink detected else 0.0)
            - path evidence (1.0 if path confirmed else 0.0)
        """
        m_ev = model_evidence if model_evidence is not None else 0.0
        src_ev = 1.0 if source_detected else 0.0
        sink_ev = 1.0 if sink_detected else 0.0
        path_ev = 1.0 if has_path else 0.0

        strength = (m_ev + src_ev + sink_ev + path_ev) / 4.0
        return round(float(np.clip(strength, 0.0, 1.0)), 4)

    # Backward-compatible alias
    calculate_chain_confidence = calculate_chain_evidence_strength

    @staticmethod
    def get_assessment(chain_risk_score: float) -> str:
        """Convert Chain Risk Score to qualitative assessment:
        0.70 – 1.00 → HIGH
        0.40 – 0.69 → MEDIUM
        0.00 – 0.39 → LOW
        """
        if chain_risk_score >= 0.70:
            return "HIGH"
        elif chain_risk_score >= 0.40:
            return "MEDIUM"
        else:
            return "LOW"
