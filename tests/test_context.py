"""Tests for interprocedural context construction strategies."""

from src.interprocedural.context_builder import ContextBuilder


def test_context_builder_strategies():
    target = "void target_func(char *x) { strcpy(dest, x); }"
    caller = "void caller_func() { target_func(untrusted); }"
    callee = "void callee_func() { system(command); }"

    # Local context
    local = ContextBuilder.build_local_context(target)
    assert "target_func" in local
    assert "caller_func" not in local

    # Caller context
    caller_ctx = ContextBuilder.build_caller_context(target, [caller])
    assert "CALLER FUNCTION 1" in caller_ctx
    assert "caller_func" in caller_ctx
    assert "target_func" in caller_ctx

    # Callee context
    callee_ctx = ContextBuilder.build_callee_context(target, [callee])
    assert "CALLEE FUNCTION 1" in callee_ctx
    assert "callee_func" in callee_ctx

    # Full context
    full_ctx = ContextBuilder.build_full_context(target, [caller], [callee])
    assert "CALLER 1" in full_ctx
    assert "TARGET FUNCTION" in full_ctx
    assert "CALLEE 1" in full_ctx
