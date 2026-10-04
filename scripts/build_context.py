"""CLI script to build interprocedural context sequences for a target function."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import argparse
from pathlib import Path

from src.callgraph.graph_builder import CallGraph
from src.interprocedural.context_builder import ContextBuilder
from src.utils.logger import get_logger

logger = get_logger("scripts.build_context")


def main():
    parser = argparse.ArgumentParser(
        description="Build context representation for a target function."
    )
    parser.add_argument(
        "--file", type=str, default="demo/sample_projects/05_multi_function_chain.c"
    )
    parser.add_argument(
        "--target", type=str, default="execute_query", help="Name of target function"
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="full",
        choices=["local", "caller", "callee", "full", "multihop"],
    )
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        logger.error(f"File not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    cg = CallGraph().build_from_code(code)
    target_node = cg.get_node(args.target)
    if not target_node:
        logger.error(f"Target function '{args.target}' not found in {file_path.name}")
        return

    callers = [cg.get_node(c).code for c in cg.get_direct_callers(args.target) if cg.get_node(c)]
    callees = [cg.get_node(c).code for c in cg.get_direct_callees(args.target) if cg.get_node(c)]

    if args.strategy == "local":
        result = ContextBuilder.build_local_context(target_node.code)
    elif args.strategy == "caller":
        result = ContextBuilder.build_caller_context(target_node.code, callers)
    elif args.strategy == "callee":
        result = ContextBuilder.build_callee_context(target_node.code, callees)
    else:
        result = ContextBuilder.build_full_context(target_node.code, callers, callees)

    print("\n" + "=" * 60)
    print(f"INTERPROCEDURAL CONTEXT: {args.target}() [{args.strategy.upper()}]")
    print("=" * 60)
    print(result)
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
