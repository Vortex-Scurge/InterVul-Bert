"""Call graph construction and path traversal using NetworkX."""

from typing import Any

import networkx as nx

from ..data.schemas import CallGraphEdge, CallGraphNode
from ..utils.logger import get_logger
from .ast_visitor import ASTVisitor, ExtractedFunction
from .parser import CodeParser

logger = get_logger("InterVul-Graph.callgraph.builder")

DEFAULT_SOURCES = {
    "recv",
    "read",
    "scanf",
    "fscanf",
    "fgets",
    "getenv",
    "getchar",
    "fread",
    "getc",
    "process_request",
    "handle_input",
    "receive_packet",
    "parse_user_input",
    "handle_request",
    "read_socket",
}

DEFAULT_SINKS = {
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "memcpy",
    "memmove",
    "system",
    "popen",
    "execve",
    "execl",
    "free",
    "malloc",
    "execute_query",
    "db_query",
    "eval",
    "passthru",
}


class CallGraph:
    """Interprocedural call graph representation."""

    def __init__(
        self,
        sources: set[str] | None = None,
        sinks: set[str] | None = None,
    ):
        self.graph = nx.DiGraph()
        self.sources = set(sources) if sources else set(DEFAULT_SOURCES)
        self.sinks = set(sinks) if sinks else set(DEFAULT_SINKS)
        self.functions: dict[str, ExtractedFunction] = {}

    def build_from_code(self, source_code: str, language: str = "c") -> "CallGraph":
        """Parse source code string and construct call graph."""
        parser = CodeParser(default_language=language)
        tree = parser.parse_string(source_code, language=language)
        self.functions = ASTVisitor.extract_functions(tree, source_code)

        # Add function nodes
        for fn_name, fn in self.functions.items():
            is_src = (fn_name in self.sources) or any(
                s in fn_name.lower() for s in ["input", "request", "recv", "source"]
            )
            is_snk = (fn_name in self.sinks) or any(
                s in fn_name.lower() for s in ["query", "exec", "sink", "system"]
            )

            node = CallGraphNode(
                name=fn_name,
                code=fn.code,
                start_line=fn.start_line,
                end_line=fn.end_line,
                is_source=is_src,
                is_sink=is_snk,
            )
            self.graph.add_node(fn_name, data=node)

        # Add edges and external callee nodes
        for caller_name, fn in self.functions.items():
            for call in fn.calls:
                callee_name = call.callee_name
                is_external = callee_name not in self.functions

                if is_external:
                    # Create placeholder node for external sink/callee
                    is_snk = (callee_name in self.sinks) or any(
                        s in callee_name.lower() for s in ["query", "exec", "system", "strcpy"]
                    )
                    is_src = callee_name in self.sources
                    ext_node = CallGraphNode(
                        name=callee_name,
                        code=f"/* External call: {callee_name} */",
                        start_line=call.call_line,
                        end_line=call.call_line,
                        is_source=is_src,
                        is_sink=is_snk,
                        features={"external": True},
                    )
                    self.graph.add_node(callee_name, data=ext_node)

                edge = CallGraphEdge(
                    caller=caller_name,
                    callee=callee_name,
                    call_site_line=call.call_line,
                    arguments=call.arguments,
                    call_type=(
                        "recursive"
                        if caller_name == callee_name
                        else ("external" if is_external else "direct")
                    ),
                )
                self.graph.add_edge(caller_name, callee_name, data=edge)

        return self

    def get_node(self, name: str) -> CallGraphNode | None:
        """Retrieve node data for a given function."""
        if name in self.graph.nodes:
            return self.graph.nodes[name].get("data")
        return None

    def get_direct_callers(self, func_name: str) -> list[str]:
        """Get direct callers of a function."""
        if func_name not in self.graph:
            return []
        return list(self.graph.predecessors(func_name))

    def get_direct_callees(self, func_name: str) -> list[str]:
        """Get direct callees of a function."""
        if func_name not in self.graph:
            return []
        return list(self.graph.successors(func_name))

    def get_multi_hop_callers(self, func_name: str, max_hops: int = 2) -> list[str]:
        """Get ancestor callers up to max_hops."""
        callers: set[str] = set()
        frontier = {func_name}
        for _ in range(max_hops):
            next_frontier = set()
            for fn in frontier:
                for pred in self.get_direct_callers(fn):
                    if pred != func_name and pred not in callers:
                        callers.add(pred)
                        next_frontier.add(pred)
            frontier = next_frontier
            if not frontier:
                break
        return list(callers)

    def get_multi_hop_callees(self, func_name: str, max_hops: int = 2) -> list[str]:
        """Get descendant callees up to max_hops."""
        callees: set[str] = set()
        frontier = {func_name}
        for _ in range(max_hops):
            next_frontier = set()
            for fn in frontier:
                for succ in self.get_direct_callees(fn):
                    if succ != func_name and succ not in callees:
                        callees.add(succ)
                        next_frontier.add(succ)
            frontier = next_frontier
            if not frontier:
                break
        return list(callees)

    def find_all_chains(self, max_depth: int = 6) -> list[list[str]]:
        """Find all linear paths through the call graph up to max_depth."""
        all_chains: list[list[str]] = []
        nodes = list(self.graph.nodes)

        # Roots: nodes with in-degree 0 or marked as sources
        roots = [
            n
            for n in nodes
            if self.graph.in_degree(n) == 0 or (self.get_node(n) and self.get_node(n).is_source)
        ]
        if not roots:
            roots = nodes

        for root in roots:
            stack: list[tuple[str, list[str]]] = [(root, [root])]
            while stack:
                curr, path = stack.pop()
                successors = list(self.graph.successors(curr))
                # Terminal condition
                if not successors or len(path) >= max_depth:
                    if len(path) >= 2:
                        all_chains.append(path)
                    continue

                expanded = False
                for succ in successors:
                    if succ not in path:  # avoid cycles
                        stack.append((succ, path + [succ]))
                        expanded = True
                if not expanded and len(path) >= 2:
                    all_chains.append(path)

        # Deduplicate paths
        unique_chains = []
        seen = set()
        for p in all_chains:
            t = tuple(p)
            if t not in seen:
                seen.add(t)
                unique_chains.append(p)

        return sorted(unique_chains, key=lambda c: len(c), reverse=True)

    def export_dict(self) -> dict[str, Any]:
        """Export internal graph format matching requested specification:
        {
          "nodes": ["main", "process_request", "validate_input", "execute_query"],
          "edges": [["main", "process_request"], ["process_request", "validate_input"], ...]
        }
        """
        nodes_list = list(self.graph.nodes)
        edges_list = [[u, v] for u, v in self.graph.edges]
        return {
            "nodes": nodes_list,
            "edges": edges_list,
        }
