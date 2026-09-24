"""Three-Valued Kleene Logic for Policy-as-Code Evaluation.

Under the TunnelTrace epistemic model, evidence absence (UNKNOWN) is a first-class state.
Python two-valued booleans (True/False) fail to represent "unobservable" without falsely
conflating it with violation (False). Kleene 3-valued logic guarantees mathematically sound
reasoning over partial captures.
"""

from __future__ import annotations

from enum import Enum


class LogicalState(str, Enum):
    """The three discrete epistemic truth values in policy evaluation."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_bool(cls, val: bool | None) -> LogicalState:
        """Map standard Python boolean or None to LogicalState."""
        if val is True:
            return cls.TRUE
        if val is False:
            return cls.FALSE
        return cls.UNKNOWN


def kleene_not(val: LogicalState) -> LogicalState:
    """Three-valued NOT truth table.

    NOT(TRUE)    = FALSE
    NOT(FALSE)   = TRUE
    NOT(UNKNOWN) = UNKNOWN
    """
    if val == LogicalState.TRUE:
        return LogicalState.FALSE
    if val == LogicalState.FALSE:
        return LogicalState.TRUE
    return LogicalState.UNKNOWN


def kleene_and(left: LogicalState, right: LogicalState) -> LogicalState:
    """Three-valued AND truth table.

    FALSE AND *       = FALSE  (short-circuit falsification)
    * AND FALSE       = FALSE
    TRUE AND TRUE     = TRUE
    TRUE AND UNKNOWN  = UNKNOWN
    UNKNOWN AND TRUE  = UNKNOWN
    UNKNOWN AND UNKNOWN = UNKNOWN
    """
    if left == LogicalState.FALSE or right == LogicalState.FALSE:
        return LogicalState.FALSE
    if left == LogicalState.TRUE and right == LogicalState.TRUE:
        return LogicalState.TRUE
    return LogicalState.UNKNOWN


def kleene_or(left: LogicalState, right: LogicalState) -> LogicalState:
    """Three-valued OR truth table.

    TRUE OR *         = TRUE  (short-circuit satisfaction)
    * OR TRUE         = TRUE
    FALSE OR FALSE    = FALSE
    FALSE OR UNKNOWN  = UNKNOWN
    UNKNOWN OR FALSE  = UNKNOWN
    UNKNOWN OR UNKNOWN = UNKNOWN
    """
    if left == LogicalState.TRUE or right == LogicalState.TRUE:
        return LogicalState.TRUE
    if left == LogicalState.FALSE and right == LogicalState.FALSE:
        return LogicalState.FALSE
    return LogicalState.UNKNOWN


def kleene_all(items: list[LogicalState]) -> LogicalState:
    """Reduce list of LogicalState with Kleene AND. Empty list is TRUE."""
    if not items:
        return LogicalState.TRUE
    res = LogicalState.TRUE
    for item in items:
        res = kleene_and(res, item)
        if res == LogicalState.FALSE:
            return LogicalState.FALSE
    return res


def kleene_any(items: list[LogicalState]) -> LogicalState:
    """Reduce list of LogicalState with Kleene OR. Empty list is FALSE."""
    if not items:
        return LogicalState.FALSE
    res = LogicalState.FALSE
    for item in items:
        res = kleene_or(res, item)
        if res == LogicalState.TRUE:
            return LogicalState.TRUE
    return res
