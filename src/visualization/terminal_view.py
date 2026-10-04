"""ASCII Box-drawing terminal visualizer for vulnerability chains."""

from ..data.schemas import VulnerabilityChain


class TerminalVisualizer:
    """Renders formatted ASCII box-drawing vulnerability chains for terminal display."""

    @staticmethod
    def render_chain(
        chain: VulnerabilityChain, title: str = "INTERPROCEDURAL VULNERABILITY CHAIN"
    ) -> str:
        """Render complete ASCII diagram of a vulnerability chain with separate model and chain scores."""
        lines = []

        # Top banner
        banner_len = 46
        lines.append("╔" + "═" * (banner_len - 2) + "╗")
        lines.append(f"║{title:^{banner_len - 2}}║")
        lines.append("╚" + "═" * (banner_len - 2) + "╝\n")

        # Source indicator
        if chain.source_func:
            lines.append(f"       SOURCE (Untrusted Input: {chain.source_func})")
        else:
            lines.append("       [ENTRY POINT] (No Untrusted Source Detected)")
        lines.append("                  │")
        lines.append("                  ▼")

        # Function nodes
        num_nodes = len(chain.nodes)
        for i, node in enumerate(chain.nodes):
            fn_name = f"{node['function']}()"
            role = node.get("role", "INTERMEDIATE")
            risk = node.get("risk_level", "LOW")
            prob = node.get("model_probability")
            static_ev = node.get("static_evidence", "NONE")

            if prob is not None:
                prob_str = f"{prob:.2f}"
                prob_line = f"Model probability: {prob_str}"
            elif "KNOWN SINK" in static_ev:
                prob_line = "Static Evidence: KNOWN SINK"
            elif "UNTRUSTED" in static_ev:
                prob_line = "Static Evidence: UNTRUSTED SOURCE"
            else:
                prob_line = "Model probability: unavailable"

            risk_line = f"Risk: {risk}"
            role_line = f"Role: {role}"

            if role == "TARGET":
                box_top = "       ╔══════════════════════════════════════╗"
                box_mid1 = f"       ║  {fn_name:<36}║"
                box_mid2 = f"       ║  {prob_line:<36}║"
                box_mid3 = f"       ║  {risk_line:<36}║"
                box_mid4 = f"       ║  {role_line:<36}║"
                box_bot = "       ╚══════════════════════════════════════╝"
            else:
                box_top = "       ┌──────────────────────────────────────┐"
                box_mid1 = f"       │  {fn_name:<36}│"
                box_mid2 = f"       │  {prob_line:<36}│"
                box_mid3 = f"       │  {risk_line:<36}│"
                box_mid4 = f"       │  {role_line:<36}│"
                box_bot = "       └──────────────────────────────────────┘"

            lines.append(box_top)
            lines.append(box_mid1)
            lines.append(box_mid2)
            lines.append(box_mid3)
            lines.append(box_mid4)
            lines.append(box_bot)

            # Arrow to next node
            if i < num_nodes - 1:
                lines.append("                          │")
                lines.append("                          │ calls")
                lines.append("                          ▼")

        # Sink indicator
        lines.append("                          │")
        lines.append("                          ▼")
        if chain.sink_func:
            lines.append(f"              SINK (Security Sensitive: {chain.sink_func})\n")
        else:
            lines.append("              [EXIT POINT] (No Dangerous Sink Reached)\n")

        # Assessment variables
        has_source = "YES" if chain.source_func else "NO"
        has_sink = "YES" if chain.sink_func else "NO"
        has_path = (
            "YES" if (chain.source_func and chain.sink_func and len(chain.nodes) >= 2) else "NO"
        )

        max_prob_str = (
            f"{chain.max_model_probability:.2f}"
            if chain.max_model_probability is not None
            else "unavailable"
        )
        chain_score_val = (
            chain.chain_risk_score if chain.chain_risk_score > 0 else chain.heuristic_chain_score
        )
        path_traversal = "CONFIRMED" if (has_path == "YES") else "NONE"
        chain_strength_val = (
            chain.chain_evidence_strength
            if chain.chain_evidence_strength > 0
            else chain.chain_confidence
        )

        overall_assessment = (
            f"{chain.assessment} RISK"
            if chain.assessment in ["HIGH", "MEDIUM", "LOW"]
            else chain.status
        )

        # Separate Evidence Sections Matching Exact Specification
        lines.append("========================================")
        lines.append("CHAIN ASSESSMENT")
        lines.append("========================================")
        lines.append(f"Source:                    {has_source}")
        lines.append(f"Sink:                      {has_sink}")
        lines.append(f"Source-to-sink path:       {has_path}")
        lines.append(f"Path traversal:            {path_traversal}")
        lines.append("")
        lines.append(f"Maximum Model Probability: {max_prob_str}")
        lines.append("")
        lines.append(f"Chain Risk Score:          {chain_score_val:.2f}")
        lines.append(f"Chain Evidence Strength:   {chain_strength_val:.2f}")
        lines.append("")
        lines.append(f"Overall Assessment:        {overall_assessment}")
        lines.append("========================================")

        return "\n".join(lines)
