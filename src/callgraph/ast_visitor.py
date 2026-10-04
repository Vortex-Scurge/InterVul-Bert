"""AST Visitor for extracting function definitions and call sites from C/C++ AST."""

from dataclasses import dataclass, field

from tree_sitter import Node, Tree

from ..utils.logger import get_logger

logger = get_logger("InterVul-Graph.callgraph.visitor")


@dataclass
class ExtractedCall:
    """Represents a function call site inside a function body."""

    callee_name: str
    arguments: list[str]
    call_line: int
    is_external: bool = False


@dataclass
class ExtractedFunction:
    """Represents an extracted function definition."""

    name: str
    signature: str
    code: str
    start_line: int
    end_line: int
    calls: list[ExtractedCall] = field(default_factory=list)


class ASTVisitor:
    """Traverses Tree-sitter AST to extract functions and interprocedural calls."""

    @staticmethod
    def _extract_identifier_from_declarator(node: Node) -> str:
        """Recursively inspect declarators to find the core function identifier."""
        if node.type == "identifier":
            return node.text.decode("utf-8")
        if node.type == "field_identifier":
            return node.text.decode("utf-8")
        if node.type == "destructor_name":
            return node.text.decode("utf-8")

        for child in node.children:
            if child.type in [
                "function_declarator",
                "pointer_declarator",
                "parenthesized_declarator",
                "qualified_identifier",
            ]:
                res = ASTVisitor._extract_identifier_from_declarator(child)
                if res:
                    return res
            elif child.type in ["identifier", "field_identifier"]:
                return child.text.decode("utf-8")
        return ""

    @classmethod
    def _find_call_expressions(cls, node: Node, source_bytes: bytes) -> list[ExtractedCall]:
        """Find all call_expression nodes within a function body."""
        calls: list[ExtractedCall] = []

        def recurse(current: Node):
            if current.type == "call_expression":
                fn_node = current.child_by_field_name("function")
                args_node = current.child_by_field_name("arguments")

                fn_name = ""
                if fn_node:
                    if fn_node.type in ["identifier", "field_identifier"]:
                        fn_name = fn_node.text.decode("utf-8")
                    elif fn_node.type == "field_expression":
                        field = fn_node.child_by_field_name("field")
                        if field:
                            fn_name = field.text.decode("utf-8")
                        else:
                            fn_name = fn_node.text.decode("utf-8")
                    else:
                        fn_name = fn_node.text.decode("utf-8")

                arg_strings = []
                if args_node:
                    for child in args_node.named_children:
                        arg_strings.append(child.text.decode("utf-8"))

                call_line = current.start_point[0] + 1
                if fn_name:
                    calls.append(
                        ExtractedCall(
                            callee_name=fn_name,
                            arguments=arg_strings,
                            call_line=call_line,
                        )
                    )

            for child in current.children:
                recurse(child)

        recurse(node)
        return calls

    @classmethod
    def extract_functions(cls, tree: Tree, source_code: str) -> dict[str, ExtractedFunction]:
        """Extract all function definitions and their outgoing calls from an AST tree."""
        source_bytes = source_code.encode("utf-8")
        functions: dict[str, ExtractedFunction] = {}

        def visit(node: Node):
            if node.type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                fn_name = ""
                if declarator:
                    fn_name = cls._extract_identifier_from_declarator(declarator)

                if fn_name:
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    code = source_bytes[node.start_byte : node.end_byte].decode(
                        "utf-8", errors="replace"
                    )

                    # Extract calls inside this function
                    calls = cls._find_call_expressions(node, source_bytes)

                    functions[fn_name] = ExtractedFunction(
                        name=fn_name,
                        signature=(
                            declarator.text.decode("utf-8", errors="replace")
                            if declarator
                            else fn_name
                        ),
                        code=code,
                        start_line=start_line,
                        end_line=end_line,
                        calls=calls,
                    )

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return functions
