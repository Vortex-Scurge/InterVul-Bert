"""Code cleaning, normalization, and comment handling utilities."""

import re


class CodeCleaner:
    """Preprocesses raw source code for language models."""

    @staticmethod
    def strip_comments(code: str) -> str:
        """Remove C/C++ style line and block comments."""
        # Remove single line comments // ...
        code = re.sub(r"//.*?\n", "\n", code)
        # Remove multi-line comments /* ... */
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        return code

    @staticmethod
    def normalize_whitespace(code: str) -> str:
        """Collapse redundant blank lines while preserving indentation structure."""
        lines = [line.rstrip() for line in code.splitlines()]
        # Remove excessive consecutive empty lines
        cleaned_lines = []
        consecutive_empty = 0
        for line in lines:
            if not line:
                consecutive_empty += 1
                if consecutive_empty <= 1:
                    cleaned_lines.append(line)
            else:
                consecutive_empty = 0
                cleaned_lines.append(line)
        return "\n".join(cleaned_lines).strip()

    @classmethod
    def clean(cls, code: str, remove_comments: bool = False) -> str:
        """Full cleaning pipeline."""
        if not code:
            return ""
        if remove_comments:
            code = cls.strip_comments(code)
        return cls.normalize_whitespace(code)
