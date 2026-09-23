"""Open-Set & Out-of-Distribution (OOD) Gating Subsystem."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
from sklearn.metrics import auc, precision_recall_curve, roc_auc_score


@dataclass
class OODConfig:
    """Persisted configuration and empirically tuned thresholds for OOD gating."""

    entropy_threshold: float = 1.8  # Shannon entropy threshold (bits)
    min_confidence_threshold: float = 0.45  # Minimum acceptable max calibrated probability
    num_classes: int = 7
    log2_num_classes: float = math.log2(7)
    tuning_metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def config_hash(self) -> str:
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OODConfig:
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class OODDecision:
    """Structured decision output for a single classified flow."""

    is_ood: bool
    status: str  # KNOWN_ACCEPTED, UNKNOWN_UNSEEN, OUT_OF_DISTRIBUTION
    entropy: float
    normalized_entropy: float
    max_confidence: float
    rejection_reason: str | None  # HIGH_ENTROPY, LOW_CONFIDENCE, DUAL_TRIGGER, or None


class OODDetector:
    """Dual-signal Open-Set / Out-of-Distribution gate using calibrated entropy and max confidence.

    Traffic that does not match the 7 closed-set categories is routed to UNKNOWN_UNSEEN.
    UNKNOWN is NOT an 8th softmax class.
    """

    def __init__(self, config: OODConfig | None = None) -> None:
        self.config = config or OODConfig()

    def compute_entropy(self, probs: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Compute base-2 Shannon entropy and normalized entropy [0, 1].

        H(P) = -sum(p_c * log2(p_c + eps))
        H_norm = H(P) / log2(C)
        """
        eps = 1e-12
        p_clipped = np.clip(probs, eps, 1.0)
        # Normalize in case of float rounding
        p_clipped = p_clipped / p_clipped.sum(axis=1, keepdims=True)

        entropy = -np.sum(p_clipped * np.log2(p_clipped), axis=1)
        normalized_entropy = entropy / self.config.log2_num_classes
        return entropy, normalized_entropy

    def evaluate_flow(self, calibrated_prob_vector: np.ndarray) -> OODDecision:
        """Evaluate a single flow probability vector against the dual OOD gate."""
        if calibrated_prob_vector.ndim == 1:
            p_mat = calibrated_prob_vector.reshape(1, -1)
        else:
            p_mat = calibrated_prob_vector

        entropy_arr, norm_entropy_arr = self.compute_entropy(p_mat)
        entropy = float(entropy_arr[0])
        norm_entropy = float(norm_entropy_arr[0])
        max_conf = float(np.max(p_mat[0]))

        high_entropy = entropy > self.config.entropy_threshold
        low_confidence = max_conf < self.config.min_confidence_threshold

        if high_entropy and low_confidence:
            is_ood = True
            status = "UNKNOWN_UNSEEN"
            reason = "DUAL_TRIGGER"
        elif high_entropy:
            is_ood = True
            status = "UNKNOWN_UNSEEN"
            reason = "HIGH_ENTROPY"
        elif low_confidence:
            is_ood = True
            status = "UNKNOWN_UNSEEN"
            reason = "LOW_CONFIDENCE"
        else:
            is_ood = False
            status = "KNOWN_ACCEPTED"
            reason = None

        return OODDecision(
            is_ood=is_ood,
            status=status,
            entropy=entropy,
            normalized_entropy=norm_entropy,
            max_confidence=max_conf,
            rejection_reason=reason,
        )

    def evaluate_batch(self, probs: np.ndarray) -> list[OODDecision]:
        """Evaluate an (N, C) matrix of calibrated probabilities."""
        return [self.evaluate_flow(probs[i]) for i in range(len(probs))]

    def tune_thresholds(
        self,
        probs_known_val: np.ndarray,
        probs_ood_val: np.ndarray,
        target_frr: float = 0.05,
    ) -> dict[str, Any]:
        """Empirically optimize entropy and min_confidence thresholds using validation OOD data.

        Args:
            probs_known_val: (N_known, 7) calibrated probabilities for known-class validation sessions.
            probs_ood_val: (N_ood, 7) calibrated probabilities for unmodeled OOD validation sessions.
            target_frr: Desired maximum known-class false rejection rate (default 5%).

        Returns:
            Dictionary with AUROC, AUPR, selected thresholds, and operating point metrics.
        """
        # Compute entropy for known and OOD
        ent_known, _ = self.compute_entropy(probs_known_val)
        ent_ood, _ = self.compute_entropy(probs_ood_val)

        conf_known = np.max(probs_known_val, axis=1)
        conf_ood = np.max(probs_ood_val, axis=1)

        # Binary labels: 0 for Known, 1 for OOD
        y_true = np.concatenate([np.zeros(len(ent_known)), np.ones(len(ent_ood))])
        # Higher entropy indicates OOD
        scores_entropy = np.concatenate([ent_known, ent_ood])

        # AUROC based on entropy
        try:
            auroc = float(roc_auc_score(y_true, scores_entropy))
        except Exception:
            auroc = 0.5

        # AUPR based on entropy
        try:
            precision, recall, _ = precision_recall_curve(y_true, scores_entropy)
            aupr = float(auc(recall, precision))
        except Exception:
            aupr = 0.5

        # Grid search over candidate thresholds
        candidate_entropies = np.percentile(ent_known, np.linspace(80, 99, 20))
        candidate_confs = np.percentile(conf_known, np.linspace(1, 20, 20))

        best_tau = float(candidate_entropies[len(candidate_entropies) // 2])
        best_cmin = float(candidate_confs[len(candidate_confs) // 2])
        best_ood_recall = -1.0
        best_frr = 1.0

        for tau in candidate_entropies:
            for c_min in candidate_confs:
                # Known rejections (False Rejections)
                known_rejected = (ent_known > tau) | (conf_known < c_min)
                frr = float(np.mean(known_rejected))

                # OOD detections (True Positives for OOD)
                ood_detected = (ent_ood > tau) | (conf_ood < c_min)
                odr = float(np.mean(ood_detected))

                if frr <= target_frr:
                    if (odr > best_ood_recall) or (abs(odr - best_ood_recall) < 1e-4 and frr < best_frr):
                        best_ood_recall = odr
                        best_frr = frr
                        best_tau = float(tau)
                        best_cmin = float(c_min)

        # Fallback if no candidate achieved <= target_frr
        if best_ood_recall < 0.0:
            best_tau = float(np.percentile(ent_known, 95))
            best_cmin = float(np.percentile(conf_known, 5))
            known_rejected = (ent_known > best_tau) | (conf_known < best_cmin)
            best_frr = float(np.mean(known_rejected))
            ood_detected = (ent_ood > best_tau) | (conf_ood < best_cmin)
            best_ood_recall = float(np.mean(ood_detected))

        self.config.entropy_threshold = float(round(best_tau, 4))
        self.config.min_confidence_threshold = float(round(best_cmin, 4))

        self.config.tuning_metrics = {
            "auroc": auroc,
            "aupr": aupr,
            "selected_entropy_threshold": self.config.entropy_threshold,
            "selected_min_confidence": self.config.min_confidence_threshold,
            "validation_false_rejection_rate": best_frr,
            "validation_ood_detection_rate": best_ood_recall,
            "validation_known_acceptance_rate": 1.0 - best_frr,
        }

        return self.config.tuning_metrics

    def evaluate_test_set(
        self,
        probs_known_test: np.ndarray,
        probs_ood_test: np.ndarray,
    ) -> dict[str, Any]:
        """Evaluate frozen thresholds once on locked held-out TEST and OOD_TEST partitions."""
        ent_known, _ = self.compute_entropy(probs_known_test)
        ent_ood, _ = self.compute_entropy(probs_ood_test)
        conf_known = np.max(probs_known_test, axis=1)
        conf_ood = np.max(probs_ood_test, axis=1)

        y_true = np.concatenate([np.zeros(len(ent_known)), np.ones(len(ent_ood))])
        scores_entropy = np.concatenate([ent_known, ent_ood])

        try:
            auroc = float(roc_auc_score(y_true, scores_entropy))
        except Exception:
            auroc = 0.5

        try:
            precision, recall, _ = precision_recall_curve(y_true, scores_entropy)
            aupr = float(auc(recall, precision))
        except Exception:
            aupr = 0.5

        tau = self.config.entropy_threshold
        c_min = self.config.min_confidence_threshold

        known_rejected = (ent_known > tau) | (conf_known < c_min)
        ood_detected = (ent_ood > tau) | (conf_ood < c_min)

        return {
            "test_auroc": auroc,
            "test_aupr": aupr,
            "test_false_rejection_rate": float(np.mean(known_rejected)),
            "test_ood_detection_rate": float(np.mean(ood_detected)),
            "test_known_acceptance_rate": float(1.0 - np.mean(known_rejected)),
            "entropy_threshold": tau,
            "min_confidence_threshold": c_min,
        }
