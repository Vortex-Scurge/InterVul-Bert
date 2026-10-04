"""Tests for Tree-sitter AST parsing and Call-Graph extraction."""

from src.callgraph.ast_visitor import ASTVisitor
from src.callgraph.graph_builder import CallGraph
from src.callgraph.parser import CodeParser

SAMPLE_C_CODE = """
#include <stdio.h>
#include <stdlib.h>

void execute_query(char *query) {
    system(query);
}

void validate_input(char *buf) {
    execute_query(buf);
}

void process_request(void) {
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);
    validate_input(user_input);
}

int main(void) {
    process_request();
    return 0;
}
"""


def test_tree_sitter_parser():
    parser = CodeParser()
    tree = parser.parse_string(SAMPLE_C_CODE)
    assert tree.root_node.type == "translation_unit"


def test_ast_visitor():
    parser = CodeParser()
    tree = parser.parse_string(SAMPLE_C_CODE)
    functions = ASTVisitor.extract_functions(tree, SAMPLE_C_CODE)

    assert "main" in functions
    assert "process_request" in functions
    assert "validate_input" in functions
    assert "execute_query" in functions

    # Verify calls
    main_calls = [c.callee_name for c in functions["main"].calls]
    assert "process_request" in main_calls

    proc_calls = [c.callee_name for c in functions["process_request"].calls]
    assert "validate_input" in proc_calls


def test_call_graph_builder():
    cg = CallGraph().build_from_code(SAMPLE_C_CODE)
    exported = cg.export_dict()

    assert "main" in exported["nodes"]
    assert "process_request" in exported["nodes"]
    assert "validate_input" in exported["nodes"]
    assert "execute_query" in exported["nodes"]

    assert ["main", "process_request"] in exported["edges"]
    assert ["process_request", "validate_input"] in exported["edges"]
    assert ["validate_input", "execute_query"] in exported["edges"]

    # Check callers and callees
    callers = cg.get_direct_callers("validate_input")
    assert "process_request" in callers

    callees = cg.get_direct_callees("validate_input")
    assert "execute_query" in callees
