"""Session-level dataset partitioner enforcing zero-leakage and GroupKFold compatibility."""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SplitAssignment:
    """Represents a session assigned to an ML split."""

    session_id: UUID | str
    split_type: str  # TRAIN, VALIDATION, TEST, OOD_HOLDOUT
    group_id: str
    workload_class: str


@dataclass
class LeakageAuditResult:
    """Result of an automated zero-leakage cross-split audit."""

    is_clean: bool
    total_sessions: int
    split_counts: dict[str, int] = field(default_factory=dict)
    class_distribution_per_split: dict[str, dict[str, int]] = field(
        default_factory=dict
    )
    session_overlaps: dict[str, list[str]] = field(default_factory=dict)
    sha_overlaps: dict[str, list[str]] = field(default_factory=dict)
    error_messages: list[str] = field(default_factory=list)


class SessionLevelSplitter:
    """Partitions dataset sessions into Train, Validation, Test, and OOD holdout splits.

    Guarantees:
    1. Session-level isolation: an entire experimental session (and all its packets/flows)
       belongs to exactly one split. No session is ever fragmented across splits.
    2. Zero leakage: Automated intersection assertions prove disjoint partitions.
    3. Stratification: Sessions within each supervised class are distributed proportionally.
    4. Dedicated OOD routing: OOD_HOLDOUT sessions are quarantined from training/validation.
    """

    def __init__(
        self,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_seed: int = 42,
    ) -> None:
        tol = 1e-5
        total_ratio = train_ratio + val_ratio + test_ratio
        if abs(total_ratio - 1.0) > tol:
            raise ValueError(
                f"Split ratios must sum to 1.0 (got {total_ratio:.4f} for {train_ratio}, {val_ratio}, {test_ratio})"
            )
        if any(r < 0 for r in (train_ratio, val_ratio, test_ratio)):
            raise ValueError("Split ratios cannot be negative")

        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.random_seed = random_seed

    def partition(
        self,
        sessions: Sequence[Any],
    ) -> list[SplitAssignment]:
        """Partitions an iterable of sessions into SplitAssignments.

        Accepts either DatasetSession ORM objects or dict-like objects containing:
        - id / session_id
        - workload_class
        - (optional) scenario_id / testbed_run_id for group_id
        """
        # Group sessions by workload class
        class_buckets: dict[str, list[Any]] = defaultdict(list)
        ood_sessions: list[Any] = []

        for s in sessions:
            cls = (
                getattr(s, "workload_class", None)
                or (s.get("workload_class") if isinstance(s, dict) else None)
                or "UNKNOWN"
            )
            if cls.upper() in ("OOD_HOLDOUT", "OOD", "UNMODELED"):
                ood_sessions.append(s)
            else:
                class_buckets[cls].append(s)

        assignments: list[SplitAssignment] = []

        # 1. Assign OOD sessions strictly to OOD_HOLDOUT
        for s in ood_sessions:
            s_id = getattr(s, "id", None) or (
                s.get("id") or s.get("session_id") if isinstance(s, dict) else str(s)
            )
            assignments.append(
                SplitAssignment(
                    session_id=s_id,
                    split_type="OOD_HOLDOUT",
                    group_id=f"group_ood_{s_id}",
                    workload_class="OOD_HOLDOUT",
                )
            )

        # 2. Stratify supervised classes across train / val / test
        for cls_name, cls_sessions in sorted(class_buckets.items()):
            shuffled = list(cls_sessions)
            # Use deterministic seed combined with class name for reproducible shuffle
            cls_rng = random.Random(f"{self.random_seed}_{cls_name}")
            cls_rng.shuffle(shuffled)

            n = len(shuffled)
            n_train = int(round(n * self.train_ratio))
            n_val = int(round(n * self.val_ratio))
            # Test gets remainder to ensure all sessions are partitioned
            n_test = n - n_train - n_val
            if n_test < 0:
                n_test = 0
                n_val = max(0, n - n_train)

            train_slice = shuffled[:n_train]
            val_slice = shuffled[n_train : n_train + n_val]
            test_slice = shuffled[n_train + n_val :]

            for s in train_slice:
                s_id = getattr(s, "id", None) or (
                    s.get("id") or s.get("session_id") if isinstance(s, dict) else str(s)
                )
                assignments.append(
                    SplitAssignment(
                        session_id=s_id,
                        split_type="TRAIN",
                        group_id=f"group_{s_id}",
                        workload_class=cls_name,
                    )
                )

            for s in val_slice:
                s_id = getattr(s, "id", None) or (
                    s.get("id") or s.get("session_id") if isinstance(s, dict) else str(s)
                )
                assignments.append(
                    SplitAssignment(
                        session_id=s_id,
                        split_type="VALIDATION",
                        group_id=f"group_{s_id}",
                        workload_class=cls_name,
                    )
                )

            for s in test_slice:
                s_id = getattr(s, "id", None) or (
                    s.get("id") or s.get("session_id") if isinstance(s, dict) else str(s)
                )
                assignments.append(
                    SplitAssignment(
                        session_id=s_id,
                        split_type="TEST",
                        group_id=f"group_{s_id}",
                        workload_class=cls_name,
                    )
                )

        return assignments

    @staticmethod
    def audit_leakage(
        assignments: Sequence[SplitAssignment],
        session_sha_map: dict[str | UUID, str] | None = None,
    ) -> LeakageAuditResult:
        """Performs a mathematical zero-leakage audit across all assigned splits.

        Asserts that:
        1. Every session ID appears in exactly one split (pairwise intersections are empty).
        2. If SHA-256 hashes are provided, no two splits share identical capture payloads.
        3. OOD_HOLDOUT contains zero training or validation data.
        """
        split_to_sessions: dict[str, set[str]] = defaultdict(set)
        split_to_classes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        split_to_shas: dict[str, set[str]] = defaultdict(set)

        errors: list[str] = []
        session_overlaps: dict[str, list[str]] = {}
        sha_overlaps: dict[str, list[str]] = {}

        for a in assignments:
            sid_str = str(a.session_id)
            split_to_sessions[a.split_type].add(sid_str)
            split_to_classes[a.split_type][a.workload_class] += 1
            if session_sha_map and a.session_id in session_sha_map:
                split_to_shas[a.split_type].add(session_sha_map[a.session_id])

        splits = list(split_to_sessions.keys())

        # Pairwise session ID intersection check
        for i in range(len(splits)):
            for j in range(i + 1, len(splits)):
                s1, s2 = splits[i], splits[j]
                overlap = split_to_sessions[s1] & split_to_sessions[s2]
                if overlap:
                    overlap_list = sorted(overlap)
                    session_overlaps[f"{s1}_x_{s2}"] = overlap_list
                    errors.append(
                        f"CRITICAL LEAKAGE: {len(overlap)} sessions overlap between {s1} and {s2}."
                    )

        # Pairwise SHA-256 intersection check
        if session_sha_map:
            sha_splits = list(split_to_shas.keys())
            for i in range(len(sha_splits)):
                for j in range(i + 1, len(sha_splits)):
                    s1, s2 = sha_splits[i], sha_splits[j]
                    overlap = split_to_shas[s1] & split_to_shas[s2]
                    if overlap:
                        overlap_list = sorted(overlap)
                        sha_overlaps[f"{s1}_x_{s2}"] = overlap_list
                        errors.append(
                            f"CRITICAL SHA LEAKAGE: {len(overlap)} PCAP SHAs overlap between {s1} and {s2}."
                        )

        # OOD isolation check
        ood_sessions = split_to_sessions.get("OOD_HOLDOUT", set())
        train_sessions = split_to_sessions.get("TRAIN", set())
        if ood_sessions & train_sessions:
            errors.append("CRITICAL LEAKAGE: OOD sessions detected inside TRAIN split.")

        is_clean = len(errors) == 0

        counts = {s: len(sessions) for s, sessions in split_to_sessions.items()}
        class_dist = {
            s: dict(cls_counts) for s, cls_counts in split_to_classes.items()
        }

        return LeakageAuditResult(
            is_clean=is_clean,
            total_sessions=len(assignments),
            split_counts=counts,
            class_distribution_per_split=class_dist,
            session_overlaps=session_overlaps,
            sha_overlaps=sha_overlaps,
            error_messages=errors,
        )
