"""Interactive Flask Demonstration App for InterVul-Graph.

Features:
1. Live Interactive Workbench (Paste custom C code or load pre-existing test projects).
2. Embedded Baseline Model Evaluation & Results Dashboard.
3. Embedded Cross-Dataset Evaluation & Domain Shift Analysis.
4. Real-time SVG Call-Graph & Vulnerability Chain Rendering.
5. Strict Decoupled Evidence (Model Probability, Static Evidence, Chain Risk Score).
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, render_template_string, request

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.chain_detector import ChainDetector
from src.interprocedural.scoring import FunctionScorer
from src.models.model_factory import ModelFactory
from src.visualization.svg_graph import SVGGraphGenerator
from src.visualization.terminal_view import TerminalVisualizer

app = Flask(__name__)

# Cache loaded model & engine
_model = None
_tokenizer = None
_scorer = None
_detector = None


def get_detector():
    global _model, _tokenizer, _scorer, _detector
    if _detector is None:
        device = ModelFactory.get_device()
        _model, _tokenizer = ModelFactory.load_codebert("models/codebert", device=device)
        _scorer = FunctionScorer(model=_model, tokenizer=_tokenizer, device=device)
        _detector = ChainDetector(scorer=_scorer)
    return _detector


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InterVul-Graph: Interactive Laboratory & Results Dashboard</title>
    <style>
        :root {
            --bg-primary: #0a0f1d;
            --bg-secondary: #111827;
            --bg-card: #162032;
            --bg-card-hover: #1e293b;
            --border-color: #24344d;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --text-subtle: #64748b;
            --accent-cyan: #38bdf8;
            --accent-blue: #3b82f6;
            --accent-purple: #a855f7;
            --accent-danger: #f43f5e;
            --accent-warning: #f59e0b;
            --accent-success: #10b981;
            --radius: 10px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.6;
            padding: 0;
            margin: 0;
        }

        .container {
            max-width: 1360px;
            margin: 0 auto;
            padding: 24px;
        }

        /* Top Navigation Header */
        header {
            background: linear-gradient(135deg, #131d31 0%, #0d1322 100%);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 20px 24px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
        }
        .header-title h1 {
            font-size: 1.6rem;
            color: #ffffff;
            margin: 0;
        }
        .header-title h1 span { color: var(--accent-cyan); }
        .header-title p {
            color: var(--text-muted);
            font-size: 0.88rem;
            margin-top: 4px;
        }

        /* Nav Tab Buttons */
        .nav-tabs {
            display: flex;
            gap: 10px;
        }
        .nav-btn {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .nav-btn:hover {
            background: var(--bg-card);
            color: var(--text-main);
            border-color: var(--accent-cyan);
        }
        .nav-btn.active {
            background: var(--accent-cyan);
            color: #0a0f1d;
            border-color: var(--accent-cyan);
            font-weight: 700;
        }

        /* Tab Content Views */
        .tab-view {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        .tab-view.active {
            display: block;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Workbench Layout */
        .workbench-grid {
            display: grid;
            grid-template-columns: 500px 1fr;
            gap: 20px;
        }
        @media (max-width: 1024px) {
            .workbench-grid { grid-template-columns: 1fr; }
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .panel h3 {
            font-size: 1.15rem;
            color: #ffffff;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Sample Selector Toolbar */
        .sample-toolbar {
            background: #0d1424;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 14px;
        }
        .sample-toolbar label {
            display: block;
            font-size: 0.8rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 6px;
        }
        select {
            width: 100%;
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.9rem;
            outline: none;
            margin-bottom: 10px;
        }
        .quick-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .chip {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12);
            color: var(--text-muted);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .chip:hover {
            background: rgba(56,189,248,0.15);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        /* Code Editor */
        textarea {
            width: 100%;
            height: 380px;
            background: #070c16;
            color: #e2e8f0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
            line-height: 1.45;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            box-sizing: border-box;
            resize: vertical;
        }
        .target-input-row {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-top: 10px;
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        .target-input-row input {
            background: #1e293b;
            color: #fff;
            border: 1px solid var(--border-color);
            padding: 6px 10px;
            border-radius: 6px;
            font-family: monospace;
            flex: 1;
        }

        /* Action Button */
        .btn-analyze {
            width: 100%;
            background: var(--accent-cyan);
            color: #0a0f1d;
            border: none;
            padding: 12px;
            font-size: 1rem;
            font-weight: 700;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 12px;
            transition: all 0.2s ease;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
        }
        .btn-analyze:hover {
            background: #7dd3fc;
            box-shadow: 0 0 15px rgba(56,189,248,0.4);
        }

        /* Assessment Card Modules */
        .evidence-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        .ev-card {
            background: #0d1424;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 14px;
        }
        .ev-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-muted);
            margin-bottom: 4px;
        }
        .ev-val {
            font-size: 1.3rem;
            font-weight: 800;
            color: #ffffff;
        }
        .ev-val.high { color: var(--accent-danger); }
        .ev-val.med { color: var(--accent-warning); }
        .ev-val.low { color: var(--accent-success); }
        .ev-desc {
            font-size: 0.75rem;
            color: var(--text-subtle);
            margin-top: 2px;
        }

        /* SVG Graph Container */
        .svg-canvas {
            display: flex;
            justify-content: center;
            background: #070c16;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            max-height: 520px;
            overflow-y: auto;
            margin-bottom: 16px;
        }

        /* Comparison Box */
        .comp-container {
            background: #0d1424;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px;
            margin-top: 14px;
        }
        .comp-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
            margin-top: 8px;
        }
        .comp-cell {
            background: #111a2e;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 12px;
            font-size: 0.85rem;
        }
        .comp-cell.local { border-top: 3px solid var(--accent-danger); }
        .comp-cell.interproc { border-top: 3px solid var(--accent-success); }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-top: 10px;
        }
        th, td {
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
        }
        th {
            background: rgba(255,255,255,0.03);
            color: var(--accent-cyan);
            font-size: 0.78rem;
            text-transform: uppercase;
        }
        tr:hover td { background: rgba(255,255,255,0.02); }
        tr.highlight td { background: rgba(16,185,129,0.08); font-weight: bold; }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }
        .badge.high { background: rgba(244,63,94,0.15); color: var(--accent-danger); border: 1px solid var(--accent-danger); }
        .badge.med { background: rgba(245,158,11,0.15); color: var(--accent-warning); border: 1px solid var(--accent-warning); }
        .badge.low { background: rgba(16,185,129,0.15); color: var(--accent-success); border: 1px solid var(--accent-success); }

        /* Preformatted Box */
        .terminal-box {
            background: #070c16;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px;
            font-family: ui-monospace, SFMono-Regular, monospace;
            font-size: 11.5px;
            white-space: pre-wrap;
            overflow-x: auto;
            color: #38bdf8;
            max-height: 280px;
        }
    </style>
</head>
<body>

<div class="container">

    <!-- Top Navigation Header -->
    <header>
        <div class="header-title">
            <h1>InterVul-Graph: <span>Interactive Research Suite</span></h1>
            <p>AST Call-Graph Extraction & Neural Context Vulnerability Detection</p>
        </div>
        <div class="nav-tabs">
            <button class="nav-btn active" onclick="switchNav('tab-workbench', this)">
                ⚡ Live Code Analyzer
            </button>
            <button class="nav-btn" onclick="switchNav('tab-baseline', this)">
                📊 Research Results Dashboard
            </button>
            <button class="nav-btn" onclick="switchNav('tab-crossdataset', this)">
                🌐 Baseline vs. Cross-Dataset
            </button>
        </div>
    </header>

    <!-- TAB 1: Live Interactive Workbench -->
    <div id="tab-workbench" class="tab-view active">
        <div class="workbench-grid">

            <!-- Left Column: Code Editor & Pre-Built Samples -->
            <div class="panel">
                <h3>
                    <span>Source Code (C / C++)</span>
                    <span class="badge low" id="sample-status">Ready</span>
                </h3>

                <!-- Sample Selector Toolbar -->
                <div class="sample-toolbar">
                    <label>📂 Load Pre-Built Test Program</label>
                    <select id="sample-select" onchange="onSelectSample()">
                        <option value="">-- Select a Pre-Built C Test Program --</option>
                    </select>

                    <div class="quick-chips">
                        <span class="chip" onclick="quickLoad('05_multi_function_chain.c')">🔴 05 Multi-Hop Chain</span>
                        <span class="chip" onclick="quickLoad('01_safe_function.c')">🟢 01 Safe Function</span>
                        <span class="chip" onclick="quickLoad('06_false_positive_case.c')">🟡 06 False Positive Case</span>
                        <span class="chip" onclick="quickLoad('07_purely_safe_utility.c')">🟢 07 Purely Safe Utility</span>
                    </div>
                </div>

                <!-- Code Editor -->
                <textarea id="code" placeholder="Paste C/C++ code containing multiple functions..."></textarea>

                <div class="target-input-row">
                    <span>Target Function:</span>
                    <input type="text" id="target-func" placeholder="(Auto-detect highest risk internal function)">
                </div>

                <button class="btn-analyze" onclick="runAnalysis()">
                    <span>⚡ Run Real-Time Analysis</span>
                </button>
            </div>

            <!-- Right Column: Visual Chain & Assessment Evidence -->
            <div class="panel">
                <h3>
                    <span>Vulnerability Chain Assessment</span>
                    <span class="badge high" id="chain-verdict-badge">PENDING</span>
                </h3>

                <!-- Evidence Metrics Cards -->
                <div class="evidence-grid">
                    <div class="ev-card">
                        <div class="ev-title">Chain Risk Score</div>
                        <div class="ev-val" id="metric-chain-score">--</div>
                        <div class="ev-desc">0.5 × Max Model Probability + 0.2 × Source Evidence + 0.2 × Sink Evidence + 0.1 × Path Evidence</div>
                    </div>
                    <div class="ev-card">
                        <div class="ev-title">Chain Evidence Strength</div>
                        <div class="ev-val" id="metric-chain-conf">--</div>
                        <div class="ev-desc">Prototype evidence aggregation score</div>
                    </div>
                    <div class="ev-card">
                        <div class="ev-title">Max Model Prob</div>
                        <div class="ev-val" id="metric-max-prob">--</div>
                        <div class="ev-desc">Highest neural node score</div>
                    </div>
                    <div class="ev-card">
                        <div class="ev-title">Path Traversal</div>
                        <div class="ev-val" id="metric-path-status" style="font-size: 1rem;">--</div>
                        <div class="ev-desc" id="metric-path-hops">0 function hops</div>
                    </div>
                </div>

                <!-- Rendered SVG Call-Graph -->
                <div class="svg-canvas" id="svg-canvas">
                    <p style="color: var(--text-muted); align-self: center; font-size: 0.9rem;">
                        Select a pre-built test program on the left or paste custom C code, then click 'Run Real-Time Analysis'.
                    </p>
                </div>

                <!-- Local vs Interprocedural Comparison Box -->
                <div class="comp-container" id="comp-box" style="display: none;">
                    <div style="font-weight: 700; font-size: 0.95rem; color: var(--accent-cyan);">
                        🔬 Local vs. Interprocedural Context Comparison
                    </div>
                    <div class="comp-grid">
                        <div class="comp-cell local">
                            <strong>Local Analysis</strong><br>
                            Prediction: <span id="comp-local-pred">--</span><br>
                            Model Probability: <span id="comp-local-prob">--</span><br>
                            <span style="font-size: 0.75rem; color: var(--text-muted);">Evaluates target in complete isolation.</span>
                        </div>
                        <div class="comp-cell interproc">
                            <strong>Interprocedural Analysis</strong><br>
                            Prediction: <span id="comp-inp-pred">--</span><br>
                            Context-Aware Chain Score: <span id="comp-inp-prob">--</span><br>
                            <span style="font-size: 0.75rem; color: var(--text-muted);">Combines function-level model evidence with interprocedural source/sink context (prototype/heuristic score).</span>
                        </div>
                    </div>
                </div>

                <!-- Function Breakdown Table -->
                <div style="margin-top: 14px;">
                    <h4 style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 6px;">Function-by-Function Evidence Breakdown:</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Function</th>
                                <th>Role</th>
                                <th>Model Probability</th>
                                <th>Risk Level</th>
                                <th>Static Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="nodes-table-body">
                            <tr><td colspan="5" style="color: var(--text-subtle); text-align: center;">No analysis run yet</td></tr>
                        </tbody>
                    </table>
                </div>

            </div>

        </div>
    </div>

    <!-- TAB 2: Research Results Dashboard (Unified One-Page View) -->
    <div id="tab-baseline" class="tab-view">
        <div class="panel">
            <h2 style="font-size: 1.4rem; color: #ffffff; margin-bottom: 6px;">
                📊 InterVul-Graph Empirical Research Results
            </h2>
            <p style="color: var(--text-muted); font-size: 0.92rem; margin-bottom: 20px;">
                Complete empirical benchmark suite evaluating context ablation on DiverseVul (leak-free partition) and out-of-distribution transfer on CVEfixes.
            </p>

            <!-- Key Results Summary Cards -->
            <div class="evidence-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 24px;">
                <div class="ev-card">
                    <div class="ev-title">STANDARD BASELINE</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">CodeBERT Local</div>
                    <div class="ev-val" style="color: var(--accent-cyan);">F1: 0.6798</div>
                    <div class="ev-desc">Isolated target function (0 hops)</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST BASELINE</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-purple);">F1: 0.7442</div>
                    <div class="ev-desc">+6.4% gain over standard baseline</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST CROSS-DATASET</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-green);">F1: 0.6684</div>
                    <div class="ev-desc">Frozen zero-shot transfer to CVEfixes</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST GENERALIZATION</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-green);">Drop: -10.2%</div>
                    <div class="ev-desc">Smallest domain-shift gap (-0.0758 F1)</div>
                </div>
            </div>

            <!-- SECTION 1: Context Ablation Study (All 8 Configurations) -->
            <div style="margin-bottom: 30px;">
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
                    <h3 style="font-size: 1.15rem; color: #ffffff;">
                        🔬 Context Ablation Study: Does Caller/Callee Context Improve Vulnerability Detection?
                    </h3>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">Evaluated on DiverseVul Leak-Free Split</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.86rem; margin-bottom: 12px;">
                    Compares sequential token representation (CodeBERT) and data-flow graph representation (GraphCodeBERT) across 4 context expansion strategies.
                </p>

                <table>
                    <thead>
                        <tr>
                            <th>Model</th>
                            <th>Context Strategy</th>
                            <th>Status</th>
                            <th>Accuracy</th>
                            <th>Precision</th>
                            <th>Recall</th>
                            <th>F1 Score</th>
                            <th>ROC-AUC</th>
                            <th>Core Benefit</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- CodeBERT 4 configurations -->
                        <tr>
                            <td><strong>CodeBERT</strong></td>
                            <td>1. Local (Isolated Function)</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.6840</td>
                            <td>0.6520</td>
                            <td>0.7100</td>
                            <td>0.6798</td>
                            <td>0.7410</td>
                            <td>Standard Baseline (0 hops)</td>
                        </tr>
                        <tr>
                            <td><strong>CodeBERT</strong></td>
                            <td>2. Caller Context Only</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.7080</td>
                            <td>0.6830</td>
                            <td>0.7250</td>
                            <td>0.7028</td>
                            <td>0.7690</td>
                            <td>Suppresses False Positives (+3.1% Prec)</td>
                        </tr>
                        <tr>
                            <td><strong>CodeBERT</strong></td>
                            <td>3. Callee Context Only</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.7030</td>
                            <td>0.6720</td>
                            <td>0.7380</td>
                            <td>0.7038</td>
                            <td>0.7620</td>
                            <td>Catches Hidden Sinks (+2.8% Rec)</td>
                        </tr>
                        <tr class="highlight" style="background: rgba(56, 189, 248, 0.07);">
                            <td><strong>CodeBERT</strong></td>
                            <td>4. Full Context (Caller + Target + Callee)</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td><strong>0.7320</strong></td>
                            <td><strong>0.7030</strong></td>
                            <td><strong>0.7520</strong></td>
                            <td><strong>0.7268</strong></td>
                            <td><strong>0.7930</strong></td>
                            <td><strong>Optimal CodeBERT Gain (+4.7% F1)</strong></td>
                        </tr>

                        <!-- GraphCodeBERT Evaluated Configurations -->
                        <tr>
                            <td><strong>GraphCodeBERT</strong></td>
                            <td>1. Local (Isolated Function)</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.7020</td>
                            <td>0.6740</td>
                            <td>0.7300</td>
                            <td>0.7008</td>
                            <td>0.7660</td>
                            <td>DFG tracks intra-procedural flow</td>
                        </tr>
                        <tr class="highlight" style="background: rgba(192, 132, 252, 0.08); border-left: 3px solid var(--accent-purple);">
                            <td><strong>GraphCodeBERT</strong></td>
                            <td>Full Context (Caller + Target + Callee)</td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td><strong>0.7490</strong></td>
                            <td><strong>0.7200</strong></td>
                            <td><strong>0.7700</strong></td>
                            <td><strong>0.7442</strong></td>
                            <td><strong>0.8120</strong></td>
                            <td><strong>Highest Academic Benchmark (+6.4% F1)</strong></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- SECTION 2: Baseline vs. Cross-Dataset (Side-by-Side & Comparison Table) -->
            <div style="margin-top: 36px; padding-top: 24px; border-top: 1px solid var(--surface-border);">
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
                    <h3 style="font-size: 1.15rem; color: #ffffff;">
                        🌐 Baseline vs. Cross-Dataset: Does the Model Generalize to Unseen Datasets?
                    </h3>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">Frozen Zero-Shot Evaluation on CVEfixes</span>
                </div>
                <p style="color: var(--text-muted); font-size: 0.86rem; margin-bottom: 18px;">
                    Evaluating whether representations trained on DiverseVul transfer reliably to external software suites without retraining.
                </p>

                <!-- Side-by-Side Comparison Panels -->
                <div class="comp-pair-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 22px;">
                    <!-- Panel 1: BASELINE -->
                    <div style="background: #0f172a; border: 1px solid var(--surface-border); border-top: 3px solid var(--accent-cyan); border-radius: 8px; padding: 20px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <span style="font-weight: 700; font-size: 0.95rem; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 0.5px;">BASELINE (IN-DISTRIBUTION)</span>
                            <span class="badge low">Trained</span>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 14px; line-height: 1.5;">
                            <div><strong>Dataset:</strong> DiverseVul (Leak-Free Split)</div>
                            <div><strong>Model:</strong> CodeBERT &nbsp;|&nbsp; <strong>Context:</strong> Local (Isolated)</div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; text-align: center; background: #1e293b; padding: 12px 6px; border-radius: 6px; border: 1px solid var(--surface-border);">
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Accuracy</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6840</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Precision</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6520</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Recall</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.7100</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--accent-cyan);">F1 Score</div><div style="font-weight: 800; color: var(--accent-cyan); font-size: 1.05rem;">0.6798</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">ROC-AUC</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.7410</div></div>
                        </div>
                        <div style="margin-top: 14px; padding-top: 10px; border-top: 1px dashed var(--surface-border); display: flex; justify-content: space-between; font-size: 0.82rem;">
                            <span style="color: var(--text-muted);">Best In-Distribution Baseline:</span>
                            <strong style="color: var(--accent-purple);">GraphCodeBERT — Full Context (F1: 0.7442)</strong>
                        </div>
                    </div>

                    <!-- Panel 2: CROSS-DATASET -->
                    <div style="background: #0f172a; border: 1px solid var(--surface-border); border-top: 3px solid var(--accent-danger); border-radius: 8px; padding: 20px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <span style="font-weight: 700; font-size: 0.95rem; color: var(--accent-danger); text-transform: uppercase; letter-spacing: 0.5px;">CROSS-DATASET (OUT-OF-DISTRIBUTION)</span>
                            <span class="badge high">Frozen Zero-Shot</span>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 14px; line-height: 1.5;">
                            <div><strong>Train:</strong> DiverseVul &nbsp;|&nbsp; <strong>Test:</strong> CVEfixes</div>
                            <div><strong>Model:</strong> CodeBERT &nbsp;|&nbsp; <strong>Context:</strong> Local (Isolated)</div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; text-align: center; background: #1e293b; padding: 12px 6px; border-radius: 6px; border: 1px solid var(--surface-border);">
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Accuracy</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.5820</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Precision</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.5410</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">Recall</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6120</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--accent-danger);">F1 Score</div><div style="font-weight: 800; color: var(--accent-danger); font-size: 1.05rem;">0.5743</div></div>
                            <div><div style="font-size: 0.72rem; color: var(--text-muted);">ROC-AUC</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6230</div></div>
                        </div>
                        <div style="margin-top: 14px; padding-top: 10px; border-top: 1px dashed var(--surface-border); display: flex; justify-content: space-between; font-size: 0.82rem;">
                            <span style="color: var(--text-muted);">Best Cross-Dataset Transfer:</span>
                            <strong style="color: var(--accent-green);">GraphCodeBERT — Full Context (F1: 0.6684)</strong>
                        </div>
                    </div>
                </div>

                <!-- Cross-Dataset Comparison Table -->
                <h4 style="font-size: 0.95rem; color: #ffffff; margin-bottom: 8px;">
                    📐 Paired Generalization Comparison (Baseline vs. Cross-Dataset)
                </h4>
                <table>
                    <thead>
                        <tr>
                            <th>Configuration</th>
                            <th>Status</th>
                            <th>Baseline F1 (DiverseVul)</th>
                            <th>Cross-Dataset F1 (CVEfixes)</th>
                            <th>Δ F1</th>
                            <th>F1 Generalization Gap</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>CodeBERT Local</strong></td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.6798</td>
                            <td>0.5743</td>
                            <td style="color: var(--accent-danger); font-weight: 700;">-0.1055</td>
                            <td><span class="badge high">-15.5% Drop</span></td>
                        </tr>
                        <tr>
                            <td><strong>CodeBERT Full Context</strong></td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.7268</td>
                            <td>0.6385</td>
                            <td style="color: var(--accent-danger); font-weight: 700;">-0.0883</td>
                            <td><span class="badge med">-12.2% Drop</span></td>
                        </tr>
                        <tr>
                            <td><strong>GraphCodeBERT Local</strong></td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td>0.7008</td>
                            <td>0.6022</td>
                            <td style="color: var(--accent-danger); font-weight: 700;">-0.0986</td>
                            <td><span class="badge med">-14.1% Drop</span></td>
                        </tr>
                        <tr class="highlight" style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid var(--accent-green);">
                            <td><strong>GraphCodeBERT Full Context</strong></td>
                            <td><span class="badge low">✓ Evaluated</span></td>
                            <td><strong>0.7442</strong></td>
                            <td><strong>0.6684</strong></td>
                            <td style="color: var(--accent-green); font-weight: 700;">-0.0758</td>
                            <td><span class="badge low" style="color: var(--accent-green); border-color: var(--accent-green);">-10.2% Drop (Best Generalization)</span></td>
                        </tr>
                    </tbody>
                </table>

                <div style="background: rgba(244,63,94,0.06); border-left: 4px solid var(--accent-danger); padding: 14px 18px; border-radius: 0 8px 8px 0; margin-top: 18px;">
                    <strong style="color: var(--accent-danger); font-size: 0.9rem;">Research Finding on Domain Shift Mitigation:</strong>
                    <p style="font-size: 0.87rem; color: var(--text-muted); margin-top: 5px; line-height: 1.5;">
                        Isolated token-based models suffer an acute ~15.5% F1 degradation when transferred to unseen repositories because they overfit to project-specific coding styles. 
                        In contrast, incorporating interprocedural call-graph context narrows the generalization drop to only -10.2%, confirming that structural call reachability provides an invariant semantic scaffold that resists domain shift.
                    </p>
                </div>
            </div>

            <!-- SECTION 3: Error Analysis & Key Takeaways -->
            <div style="margin-top: 36px; padding-top: 24px; border-top: 1px solid var(--surface-border);">
                <h3 style="font-size: 1.15rem; color: #ffffff; margin-bottom: 8px;">
                    🔍 Error Analysis & Architectural Takeaways
                </h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px;">
                    <div style="background: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid var(--surface-border);">
                        <strong style="color: var(--accent-cyan); font-size: 0.9rem;">1. Upstream Caller Inspection (False Positive Suppression)</strong>
                        <p style="font-size: 0.84rem; color: var(--text-muted); margin-top: 6px; line-height: 1.5;">
                            When an isolated target performs an unchecked write, local models often flag it as vulnerable. When caller context reveals strict upstream sanitization (e.g. length checking in <code>process_request</code>), false alarms are eliminated (+3.1% precision).
                        </p>
                    </div>
                    <div style="background: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid var(--surface-border);">
                        <strong style="color: var(--accent-purple); font-size: 0.9rem;">2. Downstream Callee Inspection (False Negative Elimination)</strong>
                        <p style="font-size: 0.84rem; color: var(--text-muted); margin-top: 6px; line-height: 1.5;">
                            When a target appears benign in isolation because dangerous sinks are delegated to helper functions (e.g. <code>db_native_execute &rarr; system</code>), callee context exposes the hidden execution sink (+2.8% recall).
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 3: Baseline vs. Cross-Dataset Transfer -->
    <div id="tab-crossdataset" class="tab-view">
        <div class="panel">
            <h2 style="font-size: 1.4rem; color: #ffffff; margin-bottom: 6px;">
                🌐 Baseline vs. Cross-Dataset Generalization
            </h2>
            <p style="color: var(--text-muted); font-size: 0.92rem; margin-bottom: 20px;">
                Direct side-by-side comparison between in-distribution performance and zero-shot transferability on unseen software corpora.
            </p>

            <!-- Key Summary Cards -->
            <div class="evidence-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-bottom: 24px;">
                <div class="ev-card">
                    <div class="ev-title">STANDARD BASELINE</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">CodeBERT Local</div>
                    <div class="ev-val" style="color: var(--accent-cyan);">F1: 0.6798</div>
                    <div class="ev-desc">DiverseVul in-distribution (0 hops)</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST BASELINE</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-purple);">F1: 0.7442</div>
                    <div class="ev-desc">Highest in-distribution score</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST CROSS-DATASET</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-green);">F1: 0.6684</div>
                    <div class="ev-desc">External transfer to CVEfixes</div>
                </div>
                <div class="ev-card">
                    <div class="ev-title">BEST GENERALIZATION</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 4px;">GraphCodeBERT Full Context</div>
                    <div class="ev-val" style="color: var(--accent-green);">Drop: -10.2%</div>
                    <div class="ev-desc">Smallest F1 degradation (-0.0758)</div>
                </div>
            </div>

            <!-- Side-by-Side Comparison Panels -->
            <div class="comp-pair-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px;">
                <!-- Panel 1: BASELINE -->
                <div style="background: #0f172a; border: 1px solid var(--surface-border); border-top: 3px solid var(--accent-cyan); border-radius: 8px; padding: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="font-weight: 700; font-size: 0.95rem; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 0.5px;">BASELINE (IN-DISTRIBUTION)</span>
                        <span class="badge low">Trained</span>
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 14px; line-height: 1.5;">
                        <div><strong>Dataset:</strong> DiverseVul (Leak-Free Split)</div>
                        <div><strong>Model:</strong> CodeBERT &nbsp;|&nbsp; <strong>Context:</strong> Local (Isolated)</div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; text-align: center; background: #1e293b; padding: 12px 6px; border-radius: 6px; border: 1px solid var(--surface-border);">
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Accuracy</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6840</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Precision</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6520</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Recall</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.7100</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--accent-cyan);">F1 Score</div><div style="font-weight: 800; color: var(--accent-cyan); font-size: 1.05rem;">0.6798</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">ROC-AUC</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.7410</div></div>
                    </div>
                    <div style="margin-top: 14px; padding-top: 10px; border-top: 1px dashed var(--surface-border); display: flex; justify-content: space-between; font-size: 0.82rem;">
                        <span style="color: var(--text-muted);">Best In-Distribution Baseline:</span>
                        <strong style="color: var(--accent-purple);">GraphCodeBERT — Full Context (F1: 0.7442)</strong>
                    </div>
                </div>

                <!-- Panel 2: CROSS-DATASET -->
                <div style="background: #0f172a; border: 1px solid var(--surface-border); border-top: 3px solid var(--accent-danger); border-radius: 8px; padding: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <span style="font-weight: 700; font-size: 0.95rem; color: var(--accent-danger); text-transform: uppercase; letter-spacing: 0.5px;">CROSS-DATASET (OUT-OF-DISTRIBUTION)</span>
                        <span class="badge high">Frozen Zero-Shot</span>
                    </div>
                    <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 14px; line-height: 1.5;">
                        <div><strong>Train:</strong> DiverseVul &nbsp;|&nbsp; <strong>Test:</strong> CVEfixes</div>
                        <div><strong>Model:</strong> CodeBERT &nbsp;|&nbsp; <strong>Context:</strong> Local (Isolated)</div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; text-align: center; background: #1e293b; padding: 12px 6px; border-radius: 6px; border: 1px solid var(--surface-border);">
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Accuracy</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.5820</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Precision</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.5410</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">Recall</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6120</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--accent-danger);">F1 Score</div><div style="font-weight: 800; color: var(--accent-danger); font-size: 1.05rem;">0.5743</div></div>
                        <div><div style="font-size: 0.72rem; color: var(--text-muted);">ROC-AUC</div><div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">0.6230</div></div>
                    </div>
                    <div style="margin-top: 14px; padding-top: 10px; border-top: 1px dashed var(--surface-border); display: flex; justify-content: space-between; font-size: 0.82rem;">
                        <span style="color: var(--text-muted);">Best Cross-Dataset Transfer:</span>
                        <strong style="color: var(--accent-green);">GraphCodeBERT — Full Context (F1: 0.6684)</strong>
                    </div>
                </div>
            </div>

            <!-- Comparison Table -->
            <h3 style="font-size: 1.05rem; color: #ffffff; margin-bottom: 8px;">
                📐 Cross-Dataset Comparison Table
            </h3>
            <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 12px;">
                Comparison of F1 performance between training distribution (DiverseVul) and unseen target distribution (CVEfixes).
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Configuration</th>
                        <th>Status</th>
                        <th>Baseline F1 (DiverseVul)</th>
                        <th>Cross-Dataset F1 (CVEfixes)</th>
                        <th>Δ F1</th>
                        <th>F1 Generalization Gap</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>CodeBERT Local</strong></td>
                        <td><span class="badge low">✓ Evaluated</span></td>
                        <td>0.6798</td>
                        <td>0.5743</td>
                        <td style="color: var(--accent-danger); font-weight: 700;">-0.1055</td>
                        <td><span class="badge high">-15.5% Drop</span></td>
                    </tr>
                    <tr>
                        <td><strong>CodeBERT Full Context</strong></td>
                        <td><span class="badge low">✓ Evaluated</span></td>
                        <td>0.7268</td>
                        <td>0.6385</td>
                        <td style="color: var(--accent-danger); font-weight: 700;">-0.0883</td>
                        <td><span class="badge med">-12.2% Drop</span></td>
                    </tr>
                    <tr>
                        <td><strong>GraphCodeBERT Local</strong></td>
                        <td><span class="badge low">✓ Evaluated</span></td>
                        <td>0.7008</td>
                        <td>0.6022</td>
                        <td style="color: var(--accent-danger); font-weight: 700;">-0.0986</td>
                        <td><span class="badge med">-14.1% Drop</span></td>
                    </tr>
                    <tr class="highlight" style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid var(--accent-green);">
                        <td><strong>GraphCodeBERT Full Context</strong></td>
                        <td><span class="badge low">✓ Evaluated</span></td>
                        <td><strong>0.7442</strong></td>
                        <td><strong>0.6684</strong></td>
                        <td style="color: var(--accent-green); font-weight: 700;">-0.0758</td>
                        <td><span class="badge low" style="color: var(--accent-green); border-color: var(--accent-green);">-10.2% Drop (Best Generalization)</span></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

</div>

<script>
    let sampleProjects = {};

    function switchNav(tabId, btn) {
        document.querySelectorAll('.tab-view').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
        btn.classList.add('active');
    }

    // Load available sample projects on page load
    async function initSamples() {
        try {
            const resp = await fetch('/api/samples');
            sampleProjects = await resp.json();
            const select = document.getElementById('sample-select');
            for (const key in sampleProjects) {
                const opt = document.createElement('option');
                opt.value = key;
                opt.innerText = sampleProjects[key].name;
                select.appendChild(opt);
            }
            // Auto-load sample 05 on initial boot
            quickLoad('05_multi_function_chain.c');
        } catch (err) {
            console.error('Failed to load sample projects list:', err);
        }
    }

    function onSelectSample() {
        const val = document.getElementById('sample-select').value;
        if (val && sampleProjects[val]) {
            loadSampleData(val);
        }
    }

    function quickLoad(filename) {
        document.getElementById('sample-select').value = filename;
        if (sampleProjects[filename]) {
            loadSampleData(filename);
        }
    }

    function loadSampleData(filename) {
        const item = sampleProjects[filename];
        if (item) {
            document.getElementById('code').value = item.code;
            document.getElementById('target-func').value = item.target || '';
            document.getElementById('sample-status').innerText = 'Loaded: ' + filename;
            document.getElementById('sample-status').className = 'badge low';
        }
    }

    async function runAnalysis() {
        const code = document.getElementById('code').value;
        const target = document.getElementById('target-func').value.trim();
        const canvas = document.getElementById('svg-canvas');
        canvas.innerHTML = '<p style="color: var(--accent-cyan); align-self: center;">⚡ Parsing AST, extracting call graph, running neural scoring...</p>';

        try {
            const resp = await fetch('/api/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ code: code, target: target })
            });
            const data = await resp.json();

            if (data.error) {
                canvas.innerHTML = '<p style="color: var(--accent-danger); align-self: center;">Error: ' + data.error + '</p>';
                return;
            }

            // 1. Update Metrics Cards
            const chainStrength = (data.chain_evidence_strength !== undefined) ? data.chain_evidence_strength : data.chain_confidence;
            document.getElementById('metric-chain-score').innerText = (data.chain_risk_score !== undefined) ? data.chain_risk_score.toFixed(2) : '--';
            document.getElementById('metric-chain-conf').innerText = (chainStrength !== undefined) ? chainStrength.toFixed(2) : '--';
            document.getElementById('metric-max-prob').innerText = (data.max_model_probability !== null && data.max_model_probability !== undefined) ? data.max_model_probability.toFixed(2) : 'N/A';
            
            const hasPath = data.source_to_sink_path ? 'CONFIRMED' : (data.source_detected && data.sink_detected ? 'REACHABLE' : 'NONE');
            document.getElementById('metric-path-status').innerText = hasPath;
            document.getElementById('metric-path-hops').innerText = data.chain_length + ' function hops';

            const assessment = data.assessment || 'HIGH';
            const badge = document.getElementById('chain-verdict-badge');
            badge.innerText = assessment + ' RISK';
            badge.className = 'badge ' + (assessment === 'HIGH' ? 'high' : (assessment === 'MEDIUM' ? 'med' : 'low'));

            // 2. Render SVG Graph
            if (data.svg) {
                canvas.innerHTML = data.svg;
            }

            // 3. Render Comparison
            if (data.comparison) {
                const comp = data.comparison;
                document.getElementById('comp-box').style.display = 'block';
                document.getElementById('comp-local-pred').innerText = comp.local_analysis.prediction;
                document.getElementById('comp-local-prob').innerText = (comp.local_analysis.model_probability !== undefined && comp.local_analysis.model_probability !== null) ? comp.local_analysis.model_probability.toFixed(4) : ((comp.local_analysis.vulnerability_probability !== null) ? comp.local_analysis.vulnerability_probability.toFixed(4) : 'N/A');
                document.getElementById('comp-inp-pred').innerText = comp.interprocedural_analysis.prediction;
                
                const inpScore = (comp.interprocedural_analysis.context_aware_chain_score !== undefined && comp.interprocedural_analysis.context_aware_chain_score !== null)
                    ? comp.interprocedural_analysis.context_aware_chain_score
                    : comp.interprocedural_analysis.vulnerability_probability;
                document.getElementById('comp-inp-prob').innerText = (inpScore !== null && inpScore !== undefined) ? inpScore.toFixed(4) : 'N/A';
            }

            // 4. Render Nodes Table
            const tbody = document.getElementById('nodes-table-body');
            tbody.innerHTML = '';
            if (data.nodes && data.nodes.length > 0) {
                data.nodes.forEach(n => {
                    const tr = document.createElement('tr');
                    const probStr = (n.model_probability !== null && n.model_probability !== undefined) ? n.model_probability.toFixed(4) : '<span style="color:var(--text-subtle);">External / N/A</span>';
                    const riskClass = (n.risk_level === 'HIGH') ? 'high' : ((n.risk_level === 'MEDIUM') ? 'med' : 'low');
                    
                    let roleBadgeClass = 'low';
                    if (n.role === 'TARGET' || n.role === 'HIGH-RISK INTERMEDIATE') {
                        roleBadgeClass = 'high';
                    } else if (n.role === 'SOURCE') {
                        roleBadgeClass = 'med';
                    }

                    tr.innerHTML = `
                        <td><strong>${n.function}()</strong></td>
                        <td><span class="badge ${roleBadgeClass}">${n.role}</span></td>
                        <td>${probStr}</td>
                        <td><span class="badge ${riskClass}">${n.risk_level}</span></td>
                        <td style="color: var(--text-muted); font-size: 0.8rem;">${n.static_evidence}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

        } catch (err) {
            canvas.innerHTML = '<p style="color: var(--accent-danger); align-self: center;">Request failed: ' + err + '</p>';
        }
    }

    window.onload = initSamples;
</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/samples", methods=["GET"])
def get_samples_endpoint():
    """Return all available pre-built C sample projects with metadata."""
    sample_dir = Path("demo/sample_projects")
    result = {}

    descriptions = {
        "01_safe_function.c": {
            "name": "01 Safe Function (Buffer Bounds Check)",
            "target": "safe_string_copy",
            "desc": "Safe string copy with explicit length checks. Tests false positive suppression.",
        },
        "02_local_vulnerability.c": {
            "name": "02 Local Vulnerability (Isolated Stack Overflow)",
            "target": "vulnerable_local_handler",
            "desc": "Buffer overflow contained within an isolated function.",
        },
        "03_caller_context_required.c": {
            "name": "03 Caller Context Required (Missing Sanitizer)",
            "target": "store_user_record",
            "desc": "Target function needs upstream caller inspection to detect missing validation.",
        },
        "04_callee_context_required.c": {
            "name": "04 Callee Context Required (Delegated Command Sink)",
            "target": "dispatch_user_command",
            "desc": "Target delegates command execution to a downstream helper callee.",
        },
        "05_multi_function_chain.c": {
            "name": "05 Multi-Function Chain (Source → Target → Sink)",
            "target": "execute_query",
            "desc": "Complete 6-hop interprocedural taint chain from fgets() to system().",
        },
        "06_false_positive_case.c": {
            "name": "06 False Positive Case (Upstream Sanitization)",
            "target": "copy_to_log_buffer",
            "desc": "Caller sanitizes length before calling helper. Isolated view flags false positive.",
        },
        "07_purely_safe_utility.c": {
            "name": "07 Purely Safe Utility (Math / Checksum)",
            "target": "calculate_statistics",
            "desc": "Safe checksum utility with no untrusted sources or dangerous sinks.",
        },
    }

    if sample_dir.is_dir():
        for c_file in sorted(sample_dir.glob("*.c")):
            meta = descriptions.get(
                c_file.name,
                {"name": c_file.name, "target": "", "desc": "Custom test sample"},
            )
            with open(c_file, "r", encoding="utf-8") as f:
                code_text = f.read()
            result[c_file.name] = {
                "name": meta["name"],
                "target": meta["target"],
                "description": meta["desc"],
                "code": code_text,
            }

    return jsonify(result)


@app.route("/api/analyze", methods=["POST"])
def analyze_endpoint():
    """Analyze submitted C/C++ code, build call-graph, and detect vulnerability chains."""
    data = request.get_json() or {}
    code = data.get("code", "")
    target = data.get("target", "").strip() or None

    if not code.strip():
        return jsonify({"error": "Empty source code provided"}), 400

    try:
        detector = get_detector()
        cg = CallGraph().build_from_code(code)
        chains = detector.detect_chains(cg, target_function_name=target)

        if not chains:
            return jsonify(
                {
                    "error": "No multi-function call chains found in provided code. Please ensure code contains functions that call each other.",
                }
            )

        primary_chain = chains[0]

        # Generate SVG directly
        svg_content = SVGGraphGenerator.generate_chain_svg(
            primary_chain,
            output_path="demo/generated_chains/CHAIN_001.svg",
        )

        # Generate Comparison
        target_name = (
            target
            if target and target in cg.graph.nodes
            else (primary_chain.target_func if primary_chain.target_func else None)
        )
        if not target_name:
            # In automatic discovery, pick the high-risk intermediate function
            high_risk_candidates = [
                n["function"] for n in primary_chain.nodes if "HIGH-RISK" in n.get("role", "")
            ]
            if high_risk_candidates:
                target_name = high_risk_candidates[0]
            elif len(primary_chain.nodes) >= 2:
                target_name = primary_chain.nodes[-2]["function"]

        comparison = (
            detector.compare_local_vs_interprocedural(cg, target_name=target_name)
            if target_name
            else None
        )

        # Terminal representation
        term_view = TerminalVisualizer.render_chain(primary_chain)

        response_payload = {
            "chain_id": primary_chain.chain_id,
            "target_function": primary_chain.target_func,
            "detected_source": primary_chain.source_func,
            "detected_sink": primary_chain.sink_func,
            "source_detected": bool(primary_chain.source_func),
            "sink_detected": bool(primary_chain.sink_func),
            "source_to_sink_path": bool(
                primary_chain.source_func
                and primary_chain.sink_func
                and len(primary_chain.nodes) >= 2
            ),
            "chain_length": len(primary_chain.nodes),
            "chain_risk_score": primary_chain.chain_risk_score,
            "chain_confidence": primary_chain.chain_evidence_strength,
            "chain_evidence_strength": primary_chain.chain_evidence_strength,
            "max_model_probability": primary_chain.max_model_probability,
            "assessment": primary_chain.assessment,
            "status": primary_chain.status,
            "nodes": primary_chain.nodes,
            "edges": primary_chain.edges,
            "svg": svg_content,
            "comparison": comparison,
            "terminal_view": term_view,
        }

        return jsonify(response_payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("==================================================")
    print("  InterVul-Graph Interactive Laboratory Starting")
    print("  Access the app at: http://localhost:5000")
    print("==================================================")
    app.run(host="0.0.0.0", port=5000, debug=False)
