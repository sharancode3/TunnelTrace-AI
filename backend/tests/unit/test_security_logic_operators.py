"""Unit tests for three-valued Kleene logic and allowlisted deterministic operators."""

from __future__ import annotations

import pytest

from app.security.policy.logic import (
    LogicalState,
    kleene_all,
    kleene_and,
    kleene_any,
    kleene_not,
    kleene_or,
)
from app.security.policy.operators import (
    OperatorEvaluationError,
    evaluate_operator,
)


class TestKleeneLogic:
    """Rigorous tests for 3-valued Kleene logic truth tables."""

    def test_kleene_not(self) -> None:
        assert kleene_not(LogicalState.TRUE) == LogicalState.FALSE
        assert kleene_not(LogicalState.FALSE) == LogicalState.TRUE
        assert kleene_not(LogicalState.UNKNOWN) == LogicalState.UNKNOWN

    def test_kleene_and(self) -> None:
        # TRUE AND X
        assert kleene_and(LogicalState.TRUE, LogicalState.TRUE) == LogicalState.TRUE
        assert kleene_and(LogicalState.TRUE, LogicalState.FALSE) == LogicalState.FALSE
        assert kleene_and(LogicalState.TRUE, LogicalState.UNKNOWN) == LogicalState.UNKNOWN

        # FALSE AND X (Short-circuit falsity)
        assert kleene_and(LogicalState.FALSE, LogicalState.TRUE) == LogicalState.FALSE
        assert kleene_and(LogicalState.FALSE, LogicalState.FALSE) == LogicalState.FALSE
        assert kleene_and(LogicalState.FALSE, LogicalState.UNKNOWN) == LogicalState.FALSE

        # UNKNOWN AND X
        assert kleene_and(LogicalState.UNKNOWN, LogicalState.TRUE) == LogicalState.UNKNOWN
        assert kleene_and(LogicalState.UNKNOWN, LogicalState.FALSE) == LogicalState.FALSE
        assert kleene_and(LogicalState.UNKNOWN, LogicalState.UNKNOWN) == LogicalState.UNKNOWN

    def test_kleene_or(self) -> None:
        # TRUE OR X (Short-circuit truth)
        assert kleene_or(LogicalState.TRUE, LogicalState.TRUE) == LogicalState.TRUE
        assert kleene_or(LogicalState.TRUE, LogicalState.FALSE) == LogicalState.TRUE
        assert kleene_or(LogicalState.TRUE, LogicalState.UNKNOWN) == LogicalState.TRUE

        # FALSE OR X
        assert kleene_or(LogicalState.FALSE, LogicalState.TRUE) == LogicalState.TRUE
        assert kleene_or(LogicalState.FALSE, LogicalState.FALSE) == LogicalState.FALSE
        assert kleene_or(LogicalState.FALSE, LogicalState.UNKNOWN) == LogicalState.UNKNOWN

        # UNKNOWN OR X
        assert kleene_or(LogicalState.UNKNOWN, LogicalState.TRUE) == LogicalState.TRUE
        assert kleene_or(LogicalState.UNKNOWN, LogicalState.FALSE) == LogicalState.UNKNOWN
        assert kleene_or(LogicalState.UNKNOWN, LogicalState.UNKNOWN) == LogicalState.UNKNOWN

    def test_kleene_all(self) -> None:
        assert kleene_all([LogicalState.TRUE, LogicalState.TRUE]) == LogicalState.TRUE
        assert kleene_all([LogicalState.TRUE, LogicalState.FALSE]) == LogicalState.FALSE
        assert kleene_all([LogicalState.TRUE, LogicalState.UNKNOWN]) == LogicalState.UNKNOWN
        assert kleene_all([LogicalState.FALSE, LogicalState.UNKNOWN]) == LogicalState.FALSE
        assert kleene_all([]) == LogicalState.TRUE

    def test_kleene_any(self) -> None:
        assert kleene_any([LogicalState.FALSE, LogicalState.TRUE]) == LogicalState.TRUE
        assert kleene_any([LogicalState.FALSE, LogicalState.FALSE]) == LogicalState.FALSE
        assert kleene_any([LogicalState.FALSE, LogicalState.UNKNOWN]) == LogicalState.UNKNOWN
        assert kleene_any([LogicalState.TRUE, LogicalState.UNKNOWN]) == LogicalState.TRUE
        assert kleene_any([]) == LogicalState.FALSE


class TestAllowlistedOperators:
    """Tests for safe allowlisted operator evaluation."""

    def test_equals_and_not_equals(self) -> None:
        assert evaluate_operator("equals", "IKEv2", "IKEv2") == LogicalState.TRUE
        assert evaluate_operator("equals", "IKEv1", "IKEv2") == LogicalState.FALSE
        assert evaluate_operator("equals", None, "IKEv2") == LogicalState.UNKNOWN

        assert evaluate_operator("not_equals", "3DES", "3DES") == LogicalState.FALSE
        assert evaluate_operator("not_equals", "AES-256-GCM", "3DES") == LogicalState.TRUE
        assert evaluate_operator("not_equals", None, "3DES") == LogicalState.UNKNOWN

    def test_in_set_and_not_in_set(self) -> None:
        allowed_ciphers = ["AES-128-GCM-16", "AES-256-GCM-16", "AES-256-CBC"]
        assert evaluate_operator("in_set", "AES-256-GCM-16", allowed_ciphers) == LogicalState.TRUE
        assert evaluate_operator("in_set", "3DES-CBC", allowed_ciphers) == LogicalState.FALSE
        assert evaluate_operator("in_set", None, allowed_ciphers) == LogicalState.UNKNOWN

        disallowed_ciphers = ["DES-CBC", "3DES-CBC", "NULL"]
        assert evaluate_operator("not_in_set", "AES-128-GCM-16", disallowed_ciphers) == LogicalState.TRUE
        assert evaluate_operator("not_in_set", "3DES-CBC", disallowed_ciphers) == LogicalState.FALSE
        assert evaluate_operator("not_in_set", None, disallowed_ciphers) == LogicalState.UNKNOWN

    def test_comparison_operators(self) -> None:
        assert evaluate_operator("greater_or_equal", 256, 128) == LogicalState.TRUE
        assert evaluate_operator("greater_or_equal", 128, 128) == LogicalState.TRUE
        assert evaluate_operator("greater_or_equal", 64, 128) == LogicalState.FALSE
        assert evaluate_operator("greater_or_equal", None, 128) == LogicalState.UNKNOWN

        assert evaluate_operator("less_than", 14, 14) == LogicalState.FALSE
        assert evaluate_operator("less_or_equal", 14, 14) == LogicalState.TRUE

    def test_exists_and_not_exists(self) -> None:
        assert evaluate_operator("exists", "AES-GCM", None) == LogicalState.TRUE
        assert evaluate_operator("exists", None, None) == LogicalState.FALSE

        assert evaluate_operator("not_exists", None, None) == LogicalState.TRUE
        assert evaluate_operator("not_exists", "AES-GCM", None) == LogicalState.FALSE

    def test_contains(self) -> None:
        assert evaluate_operator("contains", "AES-256-GCM", "GCM") == LogicalState.TRUE
        assert evaluate_operator("contains", "AES-256-CBC", "GCM") == LogicalState.FALSE
        assert evaluate_operator("contains", None, "GCM") == LogicalState.UNKNOWN

    def test_unsafe_operator_rejection(self) -> None:
        with pytest.raises(OperatorEvaluationError):
            evaluate_operator("eval", "code", "code")

        with pytest.raises(OperatorEvaluationError):
            evaluate_operator("__import__", "os", "os")
