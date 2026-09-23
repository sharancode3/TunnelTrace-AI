"""Machine Learning subsystem for TunnelTrace AI.

Provides leakage-safe tabular feature extraction, session-isolated dataset building,
XGBoost baseline training, and artifact packaging for encrypted ESP flow classification.
"""

from __future__ import annotations

from app.ml.auditor import LeakageAuditor, LeakageDetectedError
from app.ml.dataset import (
    CANONICAL_CLASSES,
    INT_TO_LABEL,
    LABEL_TO_INT,
    MLDatasetBuilder,
    MLDatasetPartition,
)
from app.ml.evaluator import MLEvaluator
from app.ml.extractor import ExtractionError, TabularFeatureExtractor
from app.ml.manifest import ModelManifestBuilder
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.schema import FeatureDefinition, FeatureSchema
from app.ml.trainer import ExperimentResult, TrainingConfig, XGBoostTrainer
from app.ml.weighting import SampleWeightComputer

__all__ = [
    "CANONICAL_CLASSES",
    "INT_TO_LABEL",
    "LABEL_TO_INT",
    "FeatureDefinition",
    "FeatureSchema",
    "TabularFeatureExtractor",
    "ExtractionError",
    "LeakageAuditor",
    "LeakageDetectedError",
    "MLDatasetPartition",
    "MLDatasetBuilder",
    "FeaturePreprocessor",
    "SampleWeightComputer",
    "TrainingConfig",
    "ExperimentResult",
    "XGBoostTrainer",
    "MLEvaluator",
    "ModelManifestBuilder",
]
