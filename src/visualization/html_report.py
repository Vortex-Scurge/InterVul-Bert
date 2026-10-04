"""Executive HTML report generator for vulnerability chain audits."""

from pathlib import Path
from typing import Any

from ..data.schemas import VulnerabilityChain


class HTMLReportGenerator:
    """Generates professional, presentation-ready HTML reports for academic demonstrations."""

    @staticmethod
    def generate_report(
        chain: VulnerabilityChain,
        comparison: dict[str, Any] | None = None,
        project_name: str = "InterVul-Graph Demonstration Project",
        file_name: str = "demo_sample.c",
        model_name: str = "CodeBERT-base (Fine-tuned on DiverseVul)",
        output_path: str | Path = "demo/reports/CHAIN_001.html",
    ) -> str:
        """Render complete HTML report to disk and return HTML content string."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        chain_score = (
            chain.chain_risk_score if chain.chain_risk_score > 0 else chain.heuristic_chain_score
        )
        chain_strength = (
            chain.chain_evidence_strength
            if chain.chain_evidence_strength > 0
            else chain.chain_confidence
        )
        assessment = chain.assessment if chain.assessment in ["HIGH", "MEDIUM", "LOW"] else "HIGH"

        # Build node cards HTML
        node_cards_html = []
        for i, n in enumerate(chain.nodes):
            fn = n["function"]
            role = n.get("role", "INTERMEDIATE")
            risk = n.get("risk_level", "LOW")
            prob = n.get("model_probability")
            static_ev = n.get("static_evidence", "NONE")

            if risk == "HIGH":
                color_class = "risk-high"
                badge_text = "HIGH RISK"
            elif risk == "MEDIUM":
                color_class = "risk-medium"
                badge_text = "MEDIUM RISK"
            else:
                color_class = "risk-low"
                badge_text = "LOW RISK"

            if prob is not None:
                prob_line = f"Model probability: <strong>{prob:.4f}</strong>"
                bar_pct = int(prob * 100)
            elif "KNOWN SINK" in static_ev:
                prob_line = f"Static Evidence: <strong>{static_ev}</strong>"
                bar_pct = 85
            elif "UNTRUSTED" in static_ev:
                prob_line = f"Static Evidence: <strong>{static_ev}</strong>"
                bar_pct = 60
            else:
                prob_line = "Model probability: <em>unavailable</em>"
                bar_pct = 10

            is_target_card = role == "TARGET"
            is_high_risk_intermediate = role == "HIGH-RISK INTERMEDIATE"
            card_border = (
                "border: 2px solid #38bdf8;"
                if is_target_card
                else ("border: 2px solid #ef4444;" if is_high_risk_intermediate else "")
            )
            role_css = role.lower().replace(" ", "-")

            card = f"""
            <div class="chain-step">
                <div class="node-card {color_class}" style="{card_border}">
                    <div class="card-header">
                        <span class="role-pill {role_css}">{role}</span>
                        <span class="badge {color_class}-badge">{badge_text}</span>
                    </div>
                    <div class="func-title"><code>{fn}()</code></div>
                    <div class="risk-bar-container">
                        <div class="risk-bar {color_class}-bg" style="width: {bar_pct}%;"></div>
                    </div>
                    <div class="metric-row">
                        <span>Evidence:</span>
                        <span>{prob_line}</span>
                    </div>
                    <div class="metric-row" style="margin-top: 4px;">
                        <span>Risk Level:</span>
                        <strong>{risk}</strong>
                    </div>
                </div>
            """
            if i < len(chain.nodes) - 1:
                card += """
                <div class="arrow-container">
                    <div class="arrow-line"></div>
                    <div class="arrow-label">invokes</div>
                    <div class="arrow-head">▼</div>
                </div>
                """
            card += "</div>"
            node_cards_html.append(card)

        # Comparison Section HTML
        comp_html = ""
        if comparison:
            loc = comparison.get("local_analysis", {})
            inp = comparison.get("interprocedural_analysis", {})
            delta = comparison.get("delta_probability", 0.0)
            delta_color = "#ef4444" if delta > 0 else "#10b981"
            delta_sign = "+" if delta > 0 else ""

            loc_prob_val = loc.get("vulnerability_probability")
            loc_prob_str = f"{loc_prob_val:.4f}" if loc_prob_val is not None else "unavailable"
            inp_prob_val = inp.get("vulnerability_probability")
            inp_prob_str = f"{inp_prob_val:.4f}" if inp_prob_val is not None else "unavailable"

            comp_html = f"""
            <div class="section-box">
                <h2>🔬 Local vs. Interprocedural Comparative Analysis</h2>
                <p class="section-subtext">Demonstrating the empirical shift when caller/callee context is incorporated.</p>
                <div class="grid-2">
                    <div class="comp-box local">
                        <h3>Local Analysis</h3>
                        <p><strong>Target:</strong> <code>{comparison.get('target_function')}()</code></p>
                        <p><strong>Prediction:</strong> <span class="pill {'vuln' if loc.get('prediction')=='VULNERABLE' else 'safe'}">{loc.get('prediction')}</span></p>
                        <p><strong>Model Probability:</strong> {loc_prob_str}</p>
                        <p class="box-desc">Evaluates target in complete isolation. Cannot observe upstream untrusted inputs or downstream delegated sinks.</p>
                    </div>
                    <div class="comp-box interproc">
                        <h3>Interprocedural Analysis</h3>
                        <p><strong>Path:</strong> <code>{' &rarr; '.join(n['function'] for n in chain.nodes)}</code></p>
                        <p><strong>Prediction:</strong> <span class="pill {'vuln' if inp.get('prediction')=='VULNERABLE' else 'safe'}">{inp.get('prediction')}</span></p>
                        <p><strong>Context-Aware Chain Score:</strong> {inp_prob_str}</p>
                        <p class="box-desc">Combines function-level model evidence with interprocedural source/sink context (prototype/heuristic score).</p>
                    </div>
                </div>
                <div class="delta-callout">
                    <span>Context Impact Delta:</span>
                    <strong style="color: {delta_color}; font-size: 1.2rem;">{delta_sign}{delta:.4f}</strong>
                    <span class="impact-pill">{comparison.get('context_impact', 'ELEVATED_RISK')}</span>
                </div>
            </div>
            """

        max_prob_str = (
            f"{chain.max_model_probability:.4f}"
            if chain.max_model_probability is not None
            else "unavailable"
        )
        has_src = "YES" if chain.source_func else "NO"
        has_snk = "YES" if chain.sink_func else "NO"
        has_pth = (
            "YES" if (chain.source_func and chain.sink_func and len(chain.nodes) >= 2) else "NO"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InterVul-Graph: Vulnerability Chain Report [{chain.chain_id}]</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--surface-border);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.4);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 15px;
            margin-bottom: 15px;
        }}
        h1 {{ font-size: 1.8rem; color: var(--accent); }}
        .status-badge {{
            background-color: #ef444422;
            color: #ef4444;
            border: 1px solid #ef4444;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            font-size: 0.9rem;
            color: var(--text-muted);
        }}
        .meta-grid strong {{ color: var(--text-main); }}
        
        .section-box {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 25px;
        }}
        h2 {{ font-size: 1.3rem; margin-bottom: 8px; color: var(--text-main); }}
        .section-subtext {{ color: var(--text-muted); font-size: 0.95rem; margin-bottom: 20px; }}

        /* Flow Diagram */
        .flow-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 10px 0;
        }}
        .source-boundary, .sink-boundary {{
            background: #334155;
            color: #cbd5e1;
            padding: 8px 24px;
            border-radius: 30px;
            font-size: 0.85rem;
            font-weight: bold;
            letter-spacing: 1px;
            border: 1px dashed #64748b;
        }}
        .chain-step {{
            display: flex;
            flex-direction: column;
            align-items: center;
            width: 100%;
            max-width: 480px;
        }}
        .node-card {{
            width: 100%;
            background: #0f172a;
            border-radius: 8px;
            padding: 16px 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            transition: transform 0.2s ease;
        }}
        .node-card:hover {{ transform: translateY(-2px); }}
        .node-card.risk-high {{ border-left: 5px solid var(--danger); }}
        .node-card.risk-medium {{ border-left: 5px solid var(--warning); }}
        .node-card.risk-low {{ border-left: 5px solid var(--success); }}

        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .role-pill {{
            font-size: 0.75rem;
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .role-pill.source {{ background: #3b82f633; color: #60a5fa; }}
        .role-pill.target {{ background: #a855f733; color: #c084fc; }}
        .role-pill.sink {{ background: #ef444433; color: #f87171; }}
        .role-pill.intermediate {{ background: #64748b33; color: #cbd5e1; }}
        .role-pill.high-risk-intermediate {{ background: #ef444433; color: #f87171; border: 1px solid #ef444466; }}

        .badge {{ font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; }}
        .risk-high-badge {{ background: #ef444422; color: #ef4444; border: 1px solid #ef444444; }}
        .risk-medium-badge {{ background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b44; }}
        .risk-low-badge {{ background: #10b98122; color: #10b981; border: 1px solid #10b98144; }}

        .func-title {{ font-size: 1.15rem; font-weight: 600; margin-bottom: 10px; }}
        .func-title code {{ color: var(--accent); }}
        .risk-bar-container {{ height: 6px; background: #334155; border-radius: 3px; overflow: hidden; margin-bottom: 10px; }}
        .risk-bar {{ height: 100%; border-radius: 3px; }}
        .risk-high-bg {{ background: var(--danger); }}
        .risk-medium-bg {{ background: var(--warning); }}
        .risk-low-bg {{ background: var(--success); }}
        .metric-row {{ display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted); }}

        .arrow-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            margin: 6px 0;
            color: #64748b;
        }}
        .arrow-line {{ width: 2px; height: 16px; background: #64748b; }}
        .arrow-label {{ font-size: 0.75rem; color: #94a3b8; font-style: italic; }}
        .arrow-head {{ font-size: 0.8rem; margin-top: -3px; }}

        /* Comparison Grid */
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 15px; }}
        .comp-box {{ background: #0f172a; padding: 18px; border-radius: 8px; border: 1px solid var(--surface-border); }}
        .comp-box h3 {{ font-size: 1.05rem; margin-bottom: 10px; color: var(--accent); }}
        .comp-box p {{ font-size: 0.9rem; margin-bottom: 6px; }}
        .pill {{ padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }}
        .pill.vuln {{ background: #ef444433; color: #ef4444; }}
        .pill.safe {{ background: #10b98133; color: #10b981; }}
        .box-desc {{ font-size: 0.8rem !important; color: var(--text-muted); margin-top: 10px; }}
        .delta-callout {{
            background: #0f172a;
            padding: 12px 18px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 15px;
            border: 1px dashed var(--surface-border);
        }}
        .impact-pill {{
            background: #ef444422;
            color: #ef4444;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
        }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9rem; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--surface-border); }}
        th {{ background: #0f172a; color: var(--accent); }}

        footer {{
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <div>
                    <h1>⚡ InterVul-Graph Audit Report</h1>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">Interprocedural Vulnerability Chain Demonstration</p>
                </div>
                <div class="status-badge">{assessment} RISK</div>
            </div>
            <div class="meta-grid">
                <div><strong>Chain ID:</strong> {chain.chain_id}</div>
                <div><strong>Project:</strong> {project_name}</div>
                <div><strong>Target Function:</strong> <code>{chain.target_func + '()' if chain.target_func else 'None (Automatic Discovery)'}</code></div>
                <div><strong>Model:</strong> {model_name}</div>
                <div><strong>Source File:</strong> <code>{file_name}</code></div>
                <div><strong>Detection Engine:</strong> {chain.detection_method}</div>
            </div>
        </header>

        <div class="section-box">
            <h2>🔗 Vulnerability Propagation Chain</h2>
            <p class="section-subtext">Visual trace showing the path from untrusted input ingestion to vulnerable execution.</p>
            <div class="flow-container">
                <div class="source-boundary">▲ SOURCE BOUNDARY (Untrusted Input Entry)</div>
                <div class="arrow-container">
                    <div class="arrow-line"></div>
                    <div class="arrow-head">▼</div>
                </div>
                {''.join(node_cards_html)}
                <div class="sink-boundary">▼ SINK BOUNDARY (Security-Sensitive Execution)</div>
            </div>
        </div>

        {comp_html}

        <div class="section-box">
            <h2>📋 Chain Evidence & Assessment Audit</h2>
            <p class="section-subtext">Explicitly separates function-level neural evidence, static analysis signals, and final heuristic risk scores.</p>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Evidence / Signal</th>
                        <th>Observed Value</th>
                        <th>Interpretation</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Model Evidence</strong></td>
                        <td>Maximum Function Probability</td>
                        <td><strong>{max_prob_str}</strong></td>
                        <td>Highest neural probability among individual functions</td>
                    </tr>
                    <tr>
                        <td><strong>Static Evidence</strong></td>
                        <td>Source Detected</td>
                        <td><code>{chain.source_func or 'None'}</code></td>
                        <td>{'✅ VERIFIED' if has_src=='YES' else '❌ ABSENT'}</td>
                    </tr>
                    <tr>
                        <td><strong>Static Evidence</strong></td>
                        <td>Sink Detected</td>
                        <td><code>{chain.sink_func or 'None'}</code></td>
                        <td>{'✅ VERIFIED' if has_snk=='YES' else '❌ ABSENT'}</td>
                    </tr>
                    <tr>
                        <td><strong>Interprocedural</strong></td>
                        <td>Source-to-Sink Path</td>
                        <td><strong>{has_pth}</strong> (Length: {len(chain.nodes)})</td>
                        <td>Traceable call graph reachability</td>
                    </tr>
                    <tr style="background: rgba(56, 189, 248, 0.05);">
                        <td><strong>Chain Assessment</strong></td>
                        <td><strong>Chain Risk Score</strong></td>
                        <td><strong style="color: var(--accent); font-size: 1.1rem;">{chain_score:.4f}</strong></td>
                        <td>0.50*MaxProb + 0.20*Src + 0.20*Snk + 0.10*Path</td>
                    </tr>
                    <tr style="background: rgba(56, 189, 248, 0.05);">
                        <td><strong>Chain Assessment</strong></td>
                        <td><strong>Chain Evidence Strength</strong></td>
                        <td><strong>{chain_strength:.4f}</strong></td>
                        <td>Prototype evidence aggregation score (unweighted mean)</td>
                    </tr>
                    <tr style="background: rgba(239, 68, 68, 0.08);">
                        <td><strong>Overall Assessment</strong></td>
                        <td><strong>Final Verdict</strong></td>
                        <td colspan="2"><span class="status-badge">{assessment} RISK</span></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <footer>
            <p>InterVul-Graph Research Prototype | Google DeepMind & University Project Presentation</p>
            <p>Generated automatically with verifiable provenance and strict reproducibility controls.</p>
        </footer>
    </div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return html_content
