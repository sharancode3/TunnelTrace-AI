"""Deterministic Allowlisted Operators for Policy Assertions.

Evaluates observed fact values against declarative rule expectations using
3-valued Kleene logic. Rejects arbitrary expression execution.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from app.security.policy.logic import LogicalState


class OperatorEvaluationError(ValueError):
    """Raised when an unknown or disallowed operator is encountered."""

    pass


class Operator(str, Enum):
    """Allowlist of deterministic comparison operators."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN_SET = "in_set"
    NOT_IN_SET = "not_in_set"
    GREATER_THAN = "greater_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_THAN = "less_than"
    LESS_OR_EQUAL = "less_or_equal"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    CONTAINS = "contains"


EVALUATION_OPERATORS = set(Operator)


def evaluate_operator(
    operator: str | Operator,
    observed: Any,
    expected: Any,
) -> LogicalState:
    """Evaluate an allowlisted operator returning a 3-valued LogicalState.

    If the observed fact is None or UNKNOWN, operators requiring a value return LogicalState.UNKNOWN.
    """
    if isinstance(operator, str):
        try:
            op_enum = Operator(operator.lower())
        except ValueError:
            raise OperatorEvaluationError(f"Unsupported policy operator: '{operator}'") from None
    else:
        op_enum = operator

    # Existence checks handle None directly
    if op_enum == Operator.EXISTS:
        return LogicalState.TRUE if observed is not None else LogicalState.FALSE

    if op_enum == Operator.NOT_EXISTS:
        return LogicalState.TRUE if observed is None else LogicalState.FALSE

    # If observed value is None, all value comparisons are UNKNOWN
    if observed is None:
        return LogicalState.UNKNOWN

    # EQUALS
    if op_enum == Operator.EQUALS:
        # String case-insensitivity support for algorithm names
        if isinstance(observed, str) and isinstance(expected, str):
            return LogicalState.TRUE if observed.strip().upper() == expected.strip().upper() else LogicalState.FALSE
        return LogicalState.TRUE if observed == expected else LogicalState.FALSE

    # NOT_EQUALS
    if op_enum == Operator.NOT_EQUALS:
        if isinstance(observed, str) and isinstance(expected, str):
            return LogicalState.TRUE if observed.strip().upper() != expected.strip().upper() else LogicalState.FALSE
        return LogicalState.TRUE if observed != expected else LogicalState.FALSE

    # IN_SET
    if op_enum == Operator.IN_SET:
        if not isinstance(expected, (list, tuple, set)):
            raise TypeError(f"Operator 'in_set' requires list or tuple for expected values, got {type(expected)}")
        # Check string normalization if applicable
        if isinstance(observed, str):
            obs_norm = observed.strip().upper()
            norm_set = {str(x).strip().upper() for x in expected}
            return LogicalState.TRUE if obs_norm in norm_set else LogicalState.FALSE
        return LogicalState.TRUE if observed in expected else LogicalState.FALSE

    # NOT_IN_SET
    if op_enum == Operator.NOT_IN_SET:
        if not isinstance(expected, (list, tuple, set)):
            raise TypeError(f"Operator 'not_in_set' requires list or tuple for expected values, got {type(expected)}")
        if isinstance(observed, str):
            obs_norm = observed.strip().upper()
            norm_set = {str(x).strip().upper() for x in expected}
            return LogicalState.TRUE if obs_norm not in norm_set else LogicalState.FALSE
        return LogicalState.TRUE if observed not in expected else LogicalState.FALSE

    # CONTAINS
    if op_enum == Operator.CONTAINS:
        if isinstance(observed, (list, tuple, set)):
            return LogicalState.TRUE if expected in observed else LogicalState.FALSE
        if isinstance(observed, str):
            return LogicalState.TRUE if str(expected).lower() in observed.lower() else LogicalState.FALSE
        return LogicalState.UNKNOWN

    # Numeric comparisons
    if op_enum in (
        Operator.GREATER_THAN,
        Operator.GREATER_OR_EQUAL,
        Operator.LESS_THAN,
        Operator.LESS_OR_EQUAL,
    ):
        try:
            obs_num = float(observed)
            exp_num = float(expected)
        except (ValueError, TypeError):
            # Type mismatch for numeric comparison yields UNKNOWN / non-decidable
            return LogicalState.UNKNOWN

        if op_enum == Operator.GREATER_THAN:
            return LogicalState.TRUE if obs_num > exp_num else LogicalState.FALSE

        if op_enum == Operator.GREATER_OR_EQUAL:
            return LogicalState.TRUE if obs_num >= exp_num else LogicalState.FALSE

        if op_enum == Operator.LESS_THAN:
            return LogicalState.TRUE if obs_num < exp_num else LogicalState.FALSE

        if op_enum == Operator.LESS_OR_EQUAL:
            return LogicalState.TRUE if obs_num <= exp_num else LogicalState.FALSE

    return LogicalState.UNKNOWN
