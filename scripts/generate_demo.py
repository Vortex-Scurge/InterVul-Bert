"""Single-command visual demonstration script for supervisor presentations."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import shutil
from pathlib import Path

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.chain_detector import ChainDetector
from src.interprocedural.scoring import FunctionScorer
from src.models.model_factory import ModelFactory
from src.utils.logger import get_logger
from src.visualization.html_report import HTMLReportGenerator
from src.visualization.svg_graph import SVGGraphGenerator
from src.visualization.terminal_view import TerminalVisualizer

logger = get_logger("scripts.generate_demo")


def main():
    parser = argparse.ArgumentParser(
        description="Generate live demonstration assets for InterVul-Graph."
    )
    parser.add_argument(
        "--file",
        type=str,
        default="demo/sample_projects/05_multi_function_chain.c",
        help="Path to sample C/C++ project file",
    )
    parser.add_argument(
        "--target", type=str, default="execute_query", help="Target function to inspect"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="models/codebert",
        help="Trained model path or HF name",
    )
    args = parser.parse_args()

    sample_file = Path(args.file)
    if not sample_file.is_file():
        logger.error(f"Sample demonstration file not found: {sample_file}")
        return

    with open(sample_file, "r", encoding="utf-8") as f:
        code = f.read()

    # Setup directories
    reports_dir = Path("demo/reports")
    chains_dir = Path("demo/generated_chains")
    figures_dir = Path("results/figures")
    reports_dir.mkdir(parents=True, exist_ok=True)
    chains_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Model & Engine
    device = ModelFactory.get_device()
    model, tokenizer = ModelFactory.load_codebert(args.model, device=device)
    scorer = FunctionScorer(model=model, tokenizer=tokenizer, device=device)
    detector = ChainDetector(scorer=scorer)

    # 2. Extract AST Call-Graph
    cg = CallGraph().build_from_code(code)

    # 3. Detect Security-Relevant Chain
    chains = detector.detect_chains(cg, target_function_name=args.target)
    if not chains:
        logger.error("No valid vulnerability chains detected.")
        return
    primary_chain = chains[0]

    # 4. Compare Local vs Interprocedural
    comparison = detector.compare_local_vs_interprocedural(cg, target_name=args.target)

    # 5. Generate Outputs
    html_path = reports_dir / f"{primary_chain.chain_id}.html"
    svg_path = chains_dir / f"{primary_chain.chain_id}.svg"
    fig_svg_path = figures_dir / f"{primary_chain.chain_id}.svg"

    HTMLReportGenerator.generate_report(
        chain=primary_chain,
        comparison=comparison,
        project_name="InterVul-Graph Core Demonstration",
        file_name=sample_file.name,
        model_name="CodeBERT (Interprocedural Context)",
        output_path=html_path,
    )

    SVGGraphGenerator.generate_chain_svg(primary_chain, output_path=svg_path)
    shutil.copyfile(svg_path, fig_svg_path)

    # 6. Terminal Display Matching Exact Specification
    print(TerminalVisualizer.render_chain(primary_chain))

    # Chain representation formatted
    chain_str = "\n      ↓\n".join(n["function"] for n in primary_chain.nodes)

    max_prob_str = (
        f"{primary_chain.max_model_probability:.4f}"
        if primary_chain.max_model_probability is not None
        else "unavailable"
    )

    print("==================================================")
    print("             InterVul-Graph Demo")
    print("==================================================")
    print("Model:\nCodeBERT\n")
    if primary_chain.target_func:
        print(f"Target:\n{primary_chain.target_func}()\n")
    print(f"Detected source:\n{primary_chain.source_func or 'None'}()\n")
    print(f"Detected sink:\n{primary_chain.sink_func or 'None'}()\n")
    print(f"Chain:\n{chain_str}\n")
    print(f"Maximum Model Probability:\n{max_prob_str}\n")
    print(f"Chain Risk Score:\n{primary_chain.chain_risk_score:.4f}\n")
    print(f"Chain Evidence Strength:\n{primary_chain.chain_evidence_strength:.4f}\n")
    print(f"Overall Assessment:\n{primary_chain.assessment} RISK\n")
    print(f"Report generated:\n{html_path}\n")
    print(f"Graph generated:\n{svg_path}")
    print("==================================================")


if __name__ == "__main__":
    main()
