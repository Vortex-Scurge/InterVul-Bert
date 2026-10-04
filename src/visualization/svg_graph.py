"""SVG vector graphic generator for call graphs and vulnerability chains."""

from pathlib import Path

from ..data.schemas import VulnerabilityChain


class SVGGraphGenerator:
    """Generates clean vector SVG call-graph diagrams with highlighted vulnerability chains."""

    @staticmethod
    def generate_chain_svg(
        chain: VulnerabilityChain,
        output_path: str | Path = "demo/generated_chains/CHAIN_001.svg",
    ) -> str:
        """Render a vertical vulnerability chain as an SVG diagram."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        width = 500
        node_width = 380
        node_height = 80
        gap = 45
        margin_top = 80
        total_nodes = len(chain.nodes)
        summary_height = 110
        height = margin_top + total_nodes * (node_height + gap) + summary_height

        chain_score = (
            chain.chain_risk_score if chain.chain_risk_score > 0 else chain.heuristic_chain_score
        )
        chain_strength = (
            chain.chain_evidence_strength
            if chain.chain_evidence_strength > 0
            else chain.chain_confidence
        )
        assessment = chain.assessment if chain.assessment in ["HIGH", "MEDIUM", "LOW"] else "HIGH"

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">',
            "<defs>",
            '  <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%">',
            '    <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.4"/>',
            "  </filter>",
            '  <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>',
            "  </marker>",
            "</defs>",
            f'<rect width="{width}" height="{height}" fill="#0f172a" rx="12"/>',
            f'<text x="{width//2}" y="38" font-family="-apple-system, sans-serif" font-size="18" font-weight="bold" fill="#38bdf8" text-anchor="middle">InterVul-Graph: {chain.chain_id}</text>',
            f'<text x="{width//2}" y="58" font-family="-apple-system, sans-serif" font-size="12" fill="#94a3b8" text-anchor="middle">Chain Risk Score: {chain_score:.2f} | Chain Evidence Strength: {chain_strength:.2f} | {assessment} RISK</text>',
        ]

        x = (width - node_width) // 2

        for i, node in enumerate(chain.nodes):
            y = margin_top + i * (node_height + gap)
            fn_name = f"{node['function']}()"
            role = node.get("role", "INTERMEDIATE")
            risk = node.get("risk_level", "LOW")
            prob = node.get("model_probability")
            static_ev = node.get("static_evidence", "NONE")

            if risk == "HIGH":
                border_color = "#ef4444"
                badge_bg = "#ef444433"
                badge_text = "HIGH"
            elif risk == "MEDIUM":
                border_color = "#f59e0b"
                badge_bg = "#f59e0b33"
                badge_text = "MEDIUM"
            else:
                border_color = "#10b981"
                badge_bg = "#10b98133"
                badge_text = "LOW"

            if prob is not None:
                prob_label = f"Model prob: {prob:.2f}"
                bar_ratio = prob
            elif "KNOWN SINK" in static_ev:
                prob_label = "Static Sink"
                bar_ratio = 0.85
            elif "UNTRUSTED" in static_ev:
                prob_label = "Static Source"
                bar_ratio = 0.60
            else:
                prob_label = "Model: N/A"
                bar_ratio = 0.10

            is_target = role == "TARGET"
            is_high_risk_intermediate = role == "HIGH-RISK INTERMEDIATE"
            card_border = (
                "#38bdf8"
                if is_target
                else ("#ef4444" if is_high_risk_intermediate else border_color)
            )
            border_w = 3 if is_target else 2

            role_w = 150 if "HIGH-RISK" in role else 90
            role_cx = x + 14 + role_w // 2

            # Node card background
            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{node_width}" height="{node_height}" rx="8" fill="#1e293b" stroke="{card_border}" stroke-width="{border_w}" filter="url(#shadow)"/>'
            )
            # Role tag
            svg_parts.append(
                f'<rect x="{x+14}" y="{y+12}" width="{role_w}" height="{20}" rx="4" fill="#334155"/>'
            )
            svg_parts.append(
                f'<text x="{role_cx}" y="{y+26}" font-family="-apple-system, sans-serif" font-size="10" font-weight="bold" fill="#cbd5e1" text-anchor="middle">{role}</text>'
            )
            # Risk badge
            svg_parts.append(
                f'<rect x="{x+node_width-84}" y="{y+12}" width="70" height="20" rx="4" fill="{badge_bg}"/>'
            )
            svg_parts.append(
                f'<text x="{x+node_width-49}" y="{y+26}" font-family="-apple-system, sans-serif" font-size="10" font-weight="bold" fill="{border_color}" text-anchor="middle">{badge_text}</text>'
            )
            # Function name
            svg_parts.append(
                f'<text x="{x+16}" y="{y+52}" font-family="Courier, monospace" font-size="14" font-weight="bold" fill="#f8fafc">{fn_name}</text>'
            )
            # Probability label
            svg_parts.append(
                f'<text x="{x+node_width-16}" y="{y+52}" font-family="-apple-system, sans-serif" font-size="12" font-weight="bold" fill="{border_color}" text-anchor="end">{prob_label}</text>'
            )
            # Progress bar
            bar_width = int((node_width - 32) * min(1.0, max(0.0, bar_ratio)))
            svg_parts.append(
                f'<rect x="{x+16}" y="{y+64}" width="{node_width-32}" height="4" rx="2" fill="#334155"/>'
            )
            svg_parts.append(
                f'<rect x="{x+16}" y="{y+64}" width="{bar_width}" height="4" rx="2" fill="{border_color}"/>'
            )

            # Arrow to next node
            if i < total_nodes - 1:
                arrow_start_y = y + node_height
                arrow_end_y = arrow_start_y + gap
                svg_parts.append(
                    f'<line x1="{width//2}" y1="{arrow_start_y}" x2="{width//2}" y2="{arrow_end_y-6}" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)"/>'
                )
                svg_parts.append(
                    f'<text x="{width//2+10}" y="{arrow_start_y + gap//2 + 4}" font-family="-apple-system, sans-serif" font-size="11" fill="#94a3b8">calls</text>'
                )

        # Assessment Summary Box at bottom
        box_y = margin_top + total_nodes * (node_height + gap)
        has_src = "YES" if chain.source_func else "NO"
        has_snk = "YES" if chain.sink_func else "NO"
        has_pth = "YES" if (chain.source_func and chain.sink_func and total_nodes >= 2) else "NO"
        path_traversal = getattr(chain, "path_traversal", None) or (
            "CONFIRMED" if has_pth == "YES" else "NONE"
        )

        summary_border = (
            "#ef4444"
            if assessment == "HIGH"
            else ("#f59e0b" if assessment == "MEDIUM" else "#10b981")
        )

        svg_parts.append(
            f'<rect x="{x}" y="{box_y}" width="{node_width}" height="85" rx="8" fill="#131d31" stroke="{summary_border}" stroke-width="2"/>'
        )
        svg_parts.append(
            f'<text x="{x+14}" y="{box_y+24}" font-family="-apple-system, sans-serif" font-size="12" font-weight="bold" fill="#38bdf8">CHAIN ASSESSMENT</text>'
        )
        svg_parts.append(
            f'<text x="{x+node_width-14}" y="{box_y+24}" font-family="-apple-system, sans-serif" font-size="11" font-weight="bold" fill="{summary_border}" text-anchor="end">Overall: {assessment} RISK</text>'
        )
        svg_parts.append(
            f'<text x="{x+14}" y="{box_y+46}" font-family="-apple-system, sans-serif" font-size="11" fill="#cbd5e1">Source: {has_src}  |  Sink: {has_snk}  |  Path: {has_pth}  |  Traversal: {path_traversal}</text>'
        )
        svg_parts.append(
            f'<text x="{x+14}" y="{box_y+68}" font-family="-apple-system, sans-serif" font-size="11" fill="#94a3b8">Chain Risk Score: <tspan fill="#f8fafc" font-weight="bold">{chain_score:.2f}</tspan>   Chain Evidence Strength: <tspan fill="#f8fafc" font-weight="bold">{chain_strength:.2f}</tspan></text>'
        )

        svg_parts.append("</svg>")
        svg_content = "\n".join(svg_parts)

        with open(path, "w", encoding="utf-8") as f:
            f.write(svg_content)

        return svg_content
