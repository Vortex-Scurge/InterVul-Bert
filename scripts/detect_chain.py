"""CLI script to detect and score security-relevant chains in source code."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
from pathlib import Path

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.chain_detector import ChainDetector
from src.interprocedural.scoring import FunctionScorer
from src.models.model_factory import ModelFactory
from src.utils.logger import get_logger
from src.visualization.terminal_view import TerminalVisualizer

logger = get_logger("scripts.detect_chain")


def main():
    parser = argparse.ArgumentParser(
        description="Detect and score vulnerability chains in C/C++ code."
    )
    parser.add_argument(
        "--file", type=str, default="demo/sample_projects/05_multi_function_chain.c"
    )
    parser.add_argument("--target", type=str, default="execute_query", help="Target function name")
    parser.add_argument("--model", type=str, default="models/codebert")
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    device = ModelFactory.get_device()
    model, tokenizer = ModelFactory.load_codebert(args.model, device=device)
    scorer = FunctionScorer(model=model, tokenizer=tokenizer, device=device)
    detector = ChainDetector(scorer=scorer)

    cg = CallGraph().build_from_code(source_code)
    chains = detector.detect_chains(cg, target_function_name=args.target)

    if not chains:
        print("No candidate chains identified.")
        return

    primary_chain = chains[0]
    print(TerminalVisualizer.render_chain(primary_chain))


if __name__ == "__main__":
    main()
