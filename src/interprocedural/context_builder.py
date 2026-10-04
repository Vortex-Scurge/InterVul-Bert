"""Interprocedural context aggregation strategies for transformer models."""

from ..preprocessing.cleaner import CodeCleaner


class ContextBuilder:
    """Constructs multi-function context sequences for transformer input."""

    @staticmethod
    def build_local_context(target_code: str) -> str:
        """Isolated target function without interprocedural information."""
        return CodeCleaner.clean(target_code)

    @staticmethod
    def build_caller_context(target_code: str, callers: list[str]) -> str:
        """Prepend caller functions before target function."""
        sections = []
        for i, c_code in enumerate(callers):
            sections.append(f"// === CALLER FUNCTION {i+1} ===\n{CodeCleaner.clean(c_code)}")
        sections.append(f"// === TARGET FUNCTION ===\n{CodeCleaner.clean(target_code)}")
        return "\n\n".join(sections)

    @staticmethod
    def build_callee_context(target_code: str, callees: list[str]) -> str:
        """Append callee functions after target function."""
        sections = [f"// === TARGET FUNCTION ===\n{CodeCleaner.clean(target_code)}"]
        for i, c_code in enumerate(callees):
            sections.append(f"// === CALLEE FUNCTION {i+1} ===\n{CodeCleaner.clean(c_code)}")
        return "\n\n".join(sections)

    @staticmethod
    def build_full_context(target_code: str, callers: list[str], callees: list[str]) -> str:
        """Combine callers, target, and callees into a unified sequence."""
        sections = []
        for i, c_code in enumerate(callers):
            sections.append(f"// === CALLER {i+1} ===\n{CodeCleaner.clean(c_code)}")

        sections.append(f"// === TARGET FUNCTION ===\n{CodeCleaner.clean(target_code)}")

        for i, c_code in enumerate(callees):
            sections.append(f"// === CALLEE {i+1} ===\n{CodeCleaner.clean(c_code)}")

        return "\n\n".join(sections)

    @staticmethod
    def build_chain_context(chain_functions: list[dict[str, str]]) -> str:
        """Format an entire vulnerability chain from Source to Sink.

        Args:
            chain_functions: List of dicts with 'name', 'code', 'role'
        """
        sections = []
        for step, fn in enumerate(chain_functions):
            role_label = fn.get("role", "INTERMEDIATE").upper()
            fn_name = fn.get("name", f"func_{step}")
            clean_code = CodeCleaner.clean(fn.get("code", ""))
            sections.append(
                f"// [CHAIN STEP {step+1}] ROLE: {role_label} | FUNC: {fn_name}\n{clean_code}"
            )
        return "\n\n".join(sections)
