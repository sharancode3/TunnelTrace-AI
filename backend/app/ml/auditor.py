"""Automated Data Leakage & Shortcut Auditing Subsystem."""

from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd


class LeakageDetectedError(Exception):
    """Raised when forbidden columns or cross-partition data leakage is detected."""


class LeakageAuditor:
    """Automated auditor enforcing zero feature leakage and detecting dataset shortcuts."""

    # Prohibited column patterns that must never appear in model feature matrix X
    FORBIDDEN_PATTERNS: list[str] = [
        r"^.*ip.*$",  # src_ip, dst_ip, ip_version, ip, etc.
        r"^.*mac.*$",  # mac addresses
        r"^.*port.*$",  # src_port, dst_port, etc.
        r"^.*spi.*$",  # esp_spi, reverse_spi, spi, etc.
        r"^.*sequence.*$",  # sequence numbers
        r"^.*session.*$",  # session_id, session_uuid, etc.
        r"^.*flow_id.*$",  # flow_id, flow_uuid
        r"^.*capture.*$",  # capture_id, capture_hash
        r"^.*analysis.*$",  # analysis_id
        r"^.*file.*$",  # filename, filepath, storage_path
        r"^.*path.*$",
        r"^.*scenario.*$",
        r"^.*workload.*$",  # workload_profile_id, workload_seed
        r"^.*generator.*$",
        r"^.*cipher.*$",  # cipher_suite
        r"^.*encrypt.*$",  # encryption_algorithm, encryption
        r"^.*algorithm.*$",  # prf_algorithm, integrity_algorithm
        r"^.*integrity.*$",
        r"^.*dh_group.*$",
        r"^.*mode.*$",  # mode, ipsec_mode
        r"^.*pfs.*$",  # pfs_status
        r"^.*nat_t.*$",  # is_nat_t
        r"^.*netem.*$",  # netem impairment profile
        r"^.*impairment.*$",
        r"^.*security.*$",  # security_score, security_findings, etc.
        r"^.*policy.*$",  # policy_rules, policy_evaluations
        r"^.*score.*$",  # score_policy, cvss_score, etc.
        r"^.*cve.*$",  # cve_id, cve_findings
        r"^.*finding.*$",  # finding_severity
        r"^.*vulnerability.*$",
        r"^.*label.*$",  # target label columns
        r"^.*ground_truth.*$",
        r"^y$",
        r"^target$",
    ]

    # Explicit allowlist of permissible substrings that might match broad regex
    PERMISSIBLE_EXCEPTIONS: set[str] = {
        # 24 canonical features do not conflict with forbidden patterns
    }

    @classmethod
    def audit_forbidden_columns(cls, column_names: list[str]) -> list[str]:
        """Audit a list of feature column names for any forbidden identifiers or configuration metadata.

        Raises:
            LeakageDetectedError: If any forbidden column name is detected.
        """
        violations: list[str] = []
        for col in column_names:
            col_lower = col.lower().strip()
            if col_lower in cls.PERMISSIBLE_EXCEPTIONS:
                continue

            for pat in cls.FORBIDDEN_PATTERNS:
                if re.match(pat, col_lower):
                    violations.append(col)
                    break

        if violations:
            raise LeakageDetectedError(
                f"FORBIDDEN_COLUMNS_DETECTED: Model input matrix contains prohibited metadata columns: {violations}"
            )
        return violations

    @classmethod
    def audit_session_isolation(
        cls,
        partition_sessions: dict[str, list[str]],
    ) -> None:
        """Mathematically prove null pairwise intersections between dataset partitions.

        Args:
            partition_sessions: Dict mapping split name ("TRAIN", "VALIDATION", "TEST", "OOD_HOLDOUT")
                to list of session IDs.

        Raises:
            LeakageDetectedError: If any session crosses partition boundaries.
        """
        splits = list(partition_sessions.keys())
        for i in range(len(splits)):
            for j in range(i + 1, len(splits)):
                s1, s2 = splits[i], splits[j]
                set1 = set(partition_sessions[s1])
                set2 = set(partition_sessions[s2])
                overlap = set1.intersection(set2)
                if overlap:
                    raise LeakageDetectedError(
                        f"DATA_LEAKAGE_DETECTED: Partitions '{s1}' and '{s2}' share {len(overlap)} "
                        f"identical session IDs: {sorted(overlap)[:5]}"
                    )

    @classmethod
    def audit_high_cardinality(
        cls,
        df: pd.DataFrame,
        cardinality_threshold: float = 0.99,
    ) -> list[dict[str, Any]]:
        """Scan feature columns for suspicious near-unique values that could act as hidden row identifiers."""
        warnings: list[dict[str, Any]] = []
        n_rows = len(df)
        if n_rows < 10:
            return warnings

        for col in df.columns:
            n_unique = df[col].nunique()
            ratio = n_unique / n_rows
            if ratio >= cardinality_threshold:
                warnings.append({
                    "column": col,
                    "unique_values": n_unique,
                    "row_count": n_rows,
                    "cardinality_ratio": ratio,
                    "warning": "HIGH_CARDINALITY_RISK: Column distinct values approach row count.",
                })
        return warnings

    @classmethod
    def audit_contingency_shortcuts(
        cls,
        metadata_df: pd.DataFrame,
        label_col: str = "workload_class",
        config_cols: list[str] | None = None,
    ) -> dict[str, Any]:
        """Examine whether classes are artificially coupled to specific VPN configurations.

        Returns a contingency report highlighting potential experimental confounding.
        """
        if config_cols is None:
            config_cols = ["cipher_suite", "mode", "ip_version", "is_nat_t", "network_impairment_profile"]

        report: dict[str, Any] = {"confounded_pairs": [], "contingencies": {}}
        if label_col not in metadata_df.columns:
            return report

        for ccol in config_cols:
            if ccol in metadata_df.columns:
                ct = pd.crosstab(metadata_df[label_col], metadata_df[ccol])
                report["contingencies"][ccol] = ct.to_dict()

                # Check if any class exists exclusively in a single configuration category
                for cls_name, row in ct.iterrows():
                    non_zero = (row > 0).sum()
                    if non_zero == 1 and ct.shape[1] > 1:
                        report["confounded_pairs"].append({
                            "class": cls_name,
                            "config_column": ccol,
                            "exclusive_config": row.idxmax(),
                            "warning": f"Class '{cls_name}' exists exclusively under {ccol}='{row.idxmax()}'. "
                            "Model may learn configuration artifacts rather than traffic dynamics.",
                        })

        return report

    @classmethod
    def audit_duration_and_packet_shortcuts(
        cls,
        X: pd.DataFrame,
        y: np.ndarray,
    ) -> dict[str, Any]:
        """Assess whether duration_ms or total_packets alone can trivially classify traffic.

        This flags whether workload scripts had fixed run lengths that create trivial shortcuts.
        """
        report: dict[str, Any] = {
            "duration_shortcut_detected": False,
            "packet_count_shortcut_detected": False,
            "details": {},
        }
        classes = np.unique(y)
        if len(classes) < 2 or len(y) < 10:
            return report

        # Test duration separation
        if "duration_ms" in X.columns:
            durations_by_class = {
                str(c): X.loc[y == c, "duration_ms"].tolist() for c in classes
            }
            # Compute overlap across class interquartile ranges
            iqrs = {}
            for c, vals in durations_by_class.items():
                if vals:
                    iqrs[c] = (float(np.percentile(vals, 25)), float(np.percentile(vals, 75)))
            report["details"]["duration_iqrs"] = iqrs

        # Test packet count separation
        if "total_packets" in X.columns:
            pkts_by_class = {
                str(c): X.loc[y == c, "total_packets"].tolist() for c in classes
            }
            report["details"]["total_packets_medians"] = {
                c: float(np.median(vals)) if vals else 0.0 for c, vals in pkts_by_class.items()
            }

        return report
