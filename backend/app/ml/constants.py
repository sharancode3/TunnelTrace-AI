"""
Constants and Class Definitions for TunnelTrace AI Machine Learning.
Freezes the 7 canonical supervised encrypted-traffic categories.
UNKNOWN_UNSEEN / OOD is strictly a post-classification rejection state, NEVER class 8.
"""

from app.ml.dataset import CANONICAL_CLASSES, INT_TO_LABEL, LABEL_TO_INT

SEVEN_KNOWN_CLASSES: tuple[str, ...] = tuple(CANONICAL_CLASSES)

__all__ = [
    "SEVEN_KNOWN_CLASSES",
    "CANONICAL_CLASSES",
    "LABEL_TO_INT",
    "INT_TO_LABEL",
]
