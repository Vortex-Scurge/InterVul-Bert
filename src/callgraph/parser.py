"""Tree-sitter parser initialization and AST generation for C and C++."""

from pathlib import Path

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser, Tree

from ..utils.logger import get_logger

logger = get_logger("InterVul-Graph.callgraph.parser")


class CodeParser:
    """Initializes Tree-sitter parsers for C and C++ code."""

    def __init__(self, default_language: str = "c"):
        self.c_lang = Language(tsc.language())
        self.cpp_lang = Language(tscpp.language())

        self.c_parser = Parser(self.c_lang)
        self.cpp_parser = Parser(self.cpp_lang)
        self.default_language = default_language.lower()

    def parse_string(self, source_code: str, language: str | None = None) -> Tree:
        """Parse source code string into a Tree-sitter Tree."""
        lang = (language or self.default_language).lower()
        code_bytes = source_code.encode("utf-8")
        if lang in ["cpp", "c++", "cxx", "cc"]:
            return self.cpp_parser.parse(code_bytes)
        return self.c_parser.parse(code_bytes)

    def parse_file(self, file_path: str | Path) -> Tree:
        """Parse source code from file path."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path.resolve()}")
        ext = path.suffix.lower()
        lang = "cpp" if ext in [".cpp", ".cc", ".cxx", ".hpp", ".h++"] else "c"
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        return self.parse_string(code, language=lang)
