"""Interprocedural vulnerability-chain detection engine."""

from typing import Any

from ..callgraph.graph_builder import CallGraph
from ..data.schemas import VulnerabilityChain
from ..utils.logger import get_logger
from .context_builder import ContextBuilder
from .scoring import FunctionScorer, HeuristicChainScorer

logger = get_logger("InterVul-Graph.interprocedural.detector")


class ChainDetector:
    """Detects security-relevant caller-target-callee vulnerability chains."""

    def __init__(self, scorer: FunctionScorer):
        self.scorer = scorer

    def detect_chains(
        self,
        callgraph: CallGraph,
        target_function_name: str | None = None,
        max_chain_length: int = 6,
    ) -> list[VulnerabilityChain]:
        """Extract and score security-relevant chains from a CallGraph."""
        # 1. Run neural scoring on each individual function without propagating risk
        node_scores = self.scorer.score_call_graph(callgraph)

        # 2. Extract linear call paths
        raw_paths = callgraph.find_all_chains(max_depth=max_chain_length)
        if not raw_paths:
            # Fallback if no deep paths: create 1-node or 2-node paths
            raw_paths = [[n] for n in callgraph.graph.nodes]

        is_targeted = bool(target_function_name and target_function_name.strip())
        target_fn_explicit = target_function_name.strip() if is_targeted else ""

        detected_chains: list[VulnerabilityChain] = []

        for idx, path in enumerate(raw_paths):
            if len(path) < 1:
                continue

            # Determine target function in path (only if user explicitly selected target)
            if is_targeted and target_fn_explicit in path:
                target_fn = target_fn_explicit
            else:
                target_fn = ""

            # Identify source and sink strictly based on security properties
            first_node_data = callgraph.get_node(path[0])
            last_node_data = callgraph.get_node(path[-1])
            source_fn = path[0] if (first_node_data and first_node_data.is_source) else None
            sink_fn = path[-1] if (last_node_data and last_node_data.is_sink) else None

            # Node representations (NO risk propagation; each node has its own model prob & risk)
            nodes_info = []
            valid_model_probs = []

            for node_idx, n in enumerate(path):
                node_data = callgraph.get_node(n)
                prob = node_scores.get(n)

                # Assign roles based on explicit target vs automatic chain discovery
                if n == source_fn:
                    role = "SOURCE"
                elif n == sink_fn:
                    role = "SINK"
                elif is_targeted and n == target_fn:
                    role = "TARGET"
                else:
                    # In automatic discovery or intermediate chain nodes:
                    # If this node directly calls the sink in a sink-reaching path, label it HIGH-RISK INTERMEDIATE
                    is_sink_caller = (
                        sink_fn is not None and len(path) >= 2 and node_idx == len(path) - 2
                    )
                    if is_sink_caller or (
                        not is_targeted and sink_fn is None and prob is not None and prob >= 0.70
                    ):
                        role = "HIGH-RISK INTERMEDIATE"
                    else:
                        role = "INTERMEDIATE"

                if prob is not None:
                    valid_model_probs.append(prob)
                    risk_level = FunctionScorer.get_risk_level(prob)
                    score_val = prob
                    static_ev = "NONE"
                else:
                    if node_data and node_data.is_sink:
                        risk_level = "HIGH"
                        score_val = 0.85
                        static_ev = f"KNOWN SINK: {n}()"
                    elif node_data and node_data.is_source:
                        risk_level = "MEDIUM"
                        score_val = 0.60
                        static_ev = f"UNTRUSTED SOURCE: {n}()"
                    else:
                        risk_level = "LOW"
                        score_val = 0.10
                        static_ev = "EXTERNAL"

                nodes_info.append(
                    {
                        "function": n,
                        "model_probability": prob,
                        "risk_level": risk_level,
                        "role": role,
                        "static_evidence": static_ev,
                        "score": score_val,
                    }
                )

            # Edges
            edges = [[path[i], path[i + 1]] for i in range(len(path) - 1)]

            max_model_prob = max(valid_model_probs) if valid_model_probs else None
            avg_score = (
                sum(valid_model_probs) / len(valid_model_probs) if valid_model_probs else 0.0
            )

            has_source = source_fn is not None
            has_sink = sink_fn is not None
            has_path = has_source and has_sink and len(path) >= 2
            path_traversal = "CONFIRMED" if has_path else "NONE"

            chain_risk_score = HeuristicChainScorer.calculate_chain_risk(
                max_function_probability=max_model_prob,
                source_detected=has_source,
                sink_detected=has_sink,
                has_path=has_path,
            )

            chain_evidence_strength = HeuristicChainScorer.calculate_chain_evidence_strength(
                model_evidence=max_model_prob,
                source_detected=has_source,
                sink_detected=has_sink,
                has_path=has_path,
            )

            assessment = HeuristicChainScorer.get_assessment(chain_risk_score)
            status = f"{assessment} RISK"

            static_evidence_dict = {
                "source_identified": has_source,
                "sink_identified": has_sink,
                "source_to_sink_path": has_path,
                "path_traversal": path_traversal,
                "source_function": source_fn,
                "sink_function": sink_fn,
                "unsafe_operation": sink_fn if has_sink else "None",
                "has_external_sink": (
                    last_node_data.features.get("external", False) if last_node_data else False
                ),
            }

            chain_id = f"CHAIN_{idx+1:03d}"
            detected_chains.append(
                VulnerabilityChain(
                    chain_id=chain_id,
                    nodes=nodes_info,
                    edges=edges,
                    source_func=source_fn,
                    sink_func=sink_fn,
                    target_func=target_fn,
                    max_risk_score=max_model_prob if max_model_prob is not None else 0.0,
                    avg_risk_score=round(avg_score, 4),
                    heuristic_chain_score=chain_risk_score,
                    chain_risk_score=chain_risk_score,
                    chain_confidence=chain_evidence_strength,
                    chain_evidence_strength=chain_evidence_strength,
                    is_targeted=is_targeted,
                    path_traversal=path_traversal,
                    assessment=assessment,
                    max_model_probability=max_model_prob,
                    status=status,
                    detection_method="Tree-sitter AST Call-Graph + CodeBERT Scoring",
                    static_evidence=static_evidence_dict,
                )
            )

        # Sort chains by chain_risk_score descending and renumber chain_ids
        sorted_chains = sorted(detected_chains, key=lambda c: c.chain_risk_score, reverse=True)
        for i, c in enumerate(sorted_chains):
            c.chain_id = f"CHAIN_{i+1:03d}"
        return sorted_chains

    def compare_local_vs_interprocedural(
        self,
        callgraph: CallGraph,
        target_name: str,
    ) -> dict[str, Any]:
        """Compute strict comparison between isolated local analysis and interprocedural chain analysis."""
        target_node = callgraph.get_node(target_name)
        if not target_node:
            return {"error": f"Target function '{target_name}' not found in call graph"}

        # 1. Local score on isolated function
        local_score = self.scorer.score_code(target_node.code)
        if local_score is not None:
            local_pred = "VULNERABLE" if local_score >= 0.50 else "SAFE"
            local_conf = round(
                local_score if local_pred == "VULNERABLE" else (1.0 - local_score), 4
            )
        else:
            local_pred = "UNAVAILABLE"
            local_conf = 0.0

        # 2. Extract callers and callees
        callers = callgraph.get_direct_callers(target_name)
        callees = callgraph.get_direct_callees(target_name)

        caller_codes = [callgraph.get_node(c).code for c in callers if callgraph.get_node(c)]
        callee_codes = [callgraph.get_node(c).code for c in callees if callgraph.get_node(c)]

        # 3. Contextual sequences
        full_context = ContextBuilder.build_full_context(
            target_node.code, caller_codes, callee_codes
        )
        interproc_score = self.scorer.score_code(full_context)
        if interproc_score is not None:
            interproc_pred = "VULNERABLE" if interproc_score >= 0.50 else "SAFE"
            interproc_conf = round(
                interproc_score if interproc_pred == "VULNERABLE" else (1.0 - interproc_score),
                4,
            )
        else:
            interproc_pred = "UNAVAILABLE"
            interproc_conf = 0.0

        delta = (
            round(interproc_score - local_score, 4)
            if (interproc_score is not None and local_score is not None)
            else 0.0
        )

        return {
            "target_function": target_name,
            "local_analysis": {
                "prediction": local_pred,
                "confidence": local_conf,
                "model_probability": local_score,
                "vulnerability_probability": local_score,
            },
            "interprocedural_analysis": {
                "prediction": interproc_pred,
                "confidence": interproc_conf,
                "context_aware_chain_score": interproc_score,
                "vulnerability_probability": interproc_score,
                "caller_functions": callers,
                "callee_functions": callees,
                "explanation": (
                    "Combines function-level model evidence with interprocedural source/sink context (prototype/heuristic score)."
                ),
            },
            "delta_probability": delta,
            "context_impact": (
                "ELEVATED_RISK"
                if delta > 0.15
                else ("SUPPRESSED_FP" if delta < -0.15 else "NEGLIGIBLE")
            ),
        }
