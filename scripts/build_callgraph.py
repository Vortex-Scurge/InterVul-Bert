"""CLI script to parse C/C++ source code and construct call graphs."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
import json
from pathlib import Path

from src.callgraph.graph_builder import CallGraph
from src.utils.logger import get_logger

logger = get_logger("scripts.build_callgraph")


def main():
    parser = argparse.ArgumentParser(description="Extract call graph from C/C++ source file.")
    parser.add_argument(
        "--file",
        type=str,
        default="demo/sample_projects/05_multi_function_chain.c",
        help="Source file path",
    )
    parser.add_argument("--lang", type=str, default="c", help="Language (c or cpp)")
    parser.add_argument(
        "--output_json", type=str, default=None, help="Path to export call graph JSON"
    )
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    cg = CallGraph().build_from_code(source_code, language=args.lang)
    exported = cg.export_dict()

    print("\n" + "=" * 50)
    print(f"CALL GRAPH EXTRACTED: {file_path.name}")
    print("=" * 50)
    print(f"Functions (Nodes): {len(exported['nodes'])}")
    for node in exported["nodes"]:
        print(f"  • {node}()")

    print(f"\nCall Sites (Edges): {len(exported['edges'])}")
    for caller, callee in exported["edges"]:
        print(f"  • {caller}()  --->  {callee}()")
    print("=" * 50 + "\n")

    if args.output_json:
        out_p = Path(args.output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(exported, f, indent=2)
        logger.info(f"Call graph exported to {out_p}")


if __name__ == "__main__":
    main()
