"""Experiment Matrix Planner: coverage-aware randomized session scheduling with anti-shortcut design."""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from lab.workloads.models import WorkloadClass
from pydantic import BaseModel, Field


@dataclass(frozen=True)
class AntiShortcutDimension:
    """A dimension across which workload data must be counterbalanced."""

    name: str
    values: list[str]


@dataclass(frozen=True)
class PlannedScenario:
    """A planned scenario mapping scenario profile to parameters."""

    scenario_id: str
    mode: str
    ip_version: str
    cipher_suite: str
    pfs_status: str
    is_nat_t: bool


@dataclass
class MatrixCoverageReport:
    """Audit summary of anti-shortcut dimension representation across recorded sessions."""

    total_planned_scenarios: int
    active_sessions_analyzed: int
    dimension_coverage: dict[str, Any] = field(default_factory=dict)
    uncovered_scenarios: list[str] = field(default_factory=list)
    anti_shortcut_warnings: list[str] = field(default_factory=list)


class PlannedSessionRow(BaseModel):
    """A single planned experimental trial in the matrix."""

    row_id: str
    workload_class: WorkloadClass
    workload_profile_id: str
    scenario_id: str
    random_seed: int
    duration_seconds: float = 10.0
    status: str = "PLANNED"  # PLANNED, EXECUTING, ACCEPTED, REJECTED, BLOCKED


class CoverageReport(BaseModel):
    """Multi-dimensional summary of class representation across IPsec configurations."""

    total_planned: int
    class_counts: dict[str, int] = Field(default_factory=dict)
    class_by_mode: dict[str, dict[str, int]] = Field(default_factory=dict)
    class_by_cipher: dict[str, dict[str, int]] = Field(default_factory=dict)
    class_by_ip_version: dict[str, dict[str, int]] = Field(default_factory=dict)
    class_by_impairment: dict[str, dict[str, int]] = Field(default_factory=dict)
    anti_shortcut_warnings: list[str] = Field(default_factory=list)


class MatrixPlanner:
    """Schedules independent experimental sessions ensuring anti-shortcut coverage."""

    SUPPORTED_SCENARIOS = [
        "01_tunnel_ipv4_aes256gcm_pfs.yaml",
        "02_tunnel_ipv4_aes256cbc_hmacsha256_nopfs.yaml",
        "03_transport_ipv4_aes256gcm.yaml",
        "04_tunnel_ipv6_aes256gcm_pfs.yaml",
        "05_tunnel_ipv4_netem_impairment.yaml",
        "06_tunnel_ipv4_natt.yaml",
    ]

    SUPERVISED_CLASSES = [
        WorkloadClass.WEB,
        WorkloadClass.VIDEO_STREAMING,
        WorkloadClass.VOIP,
        WorkloadClass.CHAT_MESSAGING,
        WorkloadClass.EMAIL,
        WorkloadClass.ICMP,
        WorkloadClass.FILE_TRANSFER,
    ]

    @classmethod
    def evaluate_coverage(cls, sessions: Sequence[Any]) -> MatrixCoverageReport:
        """Evaluates observed sessions against anti-shortcut matrix requirements."""
        observed_scenarios = set()
        ciphers_by_class: dict[str, set[str]] = defaultdict(set)
        modes_by_class: dict[str, set[str]] = defaultdict(set)
        ip_versions_by_class: dict[str, set[str]] = defaultdict(set)
        pfs_by_class: dict[str, set[str]] = defaultdict(set)
        natt_by_class: dict[str, set[bool]] = defaultdict(set)

        for s in sessions:
            scen = getattr(s, "scenario_id", None) or (
                s.get("scenario_id") if isinstance(s, dict) else ""
            )
            w_class = getattr(s, "workload_class", None) or (
                s.get("workload_class") if isinstance(s, dict) else "UNKNOWN"
            )
            cipher = getattr(s, "cipher_suite", None) or (
                s.get("cipher_suite") if isinstance(s, dict) else ""
            )
            mode = getattr(s, "mode", None) or (
                s.get("mode") if isinstance(s, dict) else ""
            )
            ip_ver = getattr(s, "ip_version", None) or (
                s.get("ip_version") if isinstance(s, dict) else ""
            )
            pfs = getattr(s, "pfs_status", None) or (
                s.get("pfs_status") if isinstance(s, dict) else ""
            )
            is_natt = bool(
                getattr(s, "is_nat_t", False)
                if hasattr(s, "is_nat_t")
                else (s.get("is_nat_t", False) if isinstance(s, dict) else False)
            )

            if scen:
                observed_scenarios.add(scen)
            if cipher:
                ciphers_by_class[w_class].add(cipher)
            if mode:
                modes_by_class[w_class].add(mode)
            if ip_ver:
                ip_versions_by_class[w_class].add(ip_ver)
            if pfs:
                pfs_by_class[w_class].add(pfs)
            natt_by_class[w_class].add(is_natt)

        uncovered = [sc for sc in cls.SUPPORTED_SCENARIOS if sc not in observed_scenarios]

        warnings = []
        for c, ciphers in ciphers_by_class.items():
            if len(ciphers) == 1 and len(sessions) > 7:
                warnings.append(
                    f"Class '{c}' only represented with a single cipher suite ({list(ciphers)[0]}). Shortcut risk."
                )

        dim_cov = {
            "cipher_suites_per_class": {c: sorted(ciphers) for c, ciphers in ciphers_by_class.items()},
            "modes_per_class": {c: sorted(modes) for c, modes in modes_by_class.items()},
            "ip_versions_per_class": {c: sorted(ips) for c, ips in ip_versions_by_class.items()},
            "pfs_statuses_per_class": {c: sorted(pfs_set) for c, pfs_set in pfs_by_class.items()},
        }

        return MatrixCoverageReport(
            total_planned_scenarios=len(cls.SUPPORTED_SCENARIOS),
            active_sessions_analyzed=len(sessions),
            dimension_coverage=dim_cov,
            uncovered_scenarios=uncovered,
            anti_shortcut_warnings=warnings,
        )

    def create_balanced_plan(
        self,
        experiment_seed: int = 1337,
        sessions_per_class: int = 2,
        include_ood: bool = False,
    ) -> list[PlannedSessionRow]:
        """Generate balanced, randomized session schedule spanning diverse IPsec configurations."""
        rng = random.Random(experiment_seed)
        rows: list[PlannedSessionRow] = []
        classes_to_plan = list(self.SUPERVISED_CLASSES)
        if include_ood:
            classes_to_plan.append(WorkloadClass.OOD_HOLDOUT)

        scenario_idx = 0
        for w_class in classes_to_plan:
            for rep in range(sessions_per_class):
                scen = self.SUPPORTED_SCENARIOS[scenario_idx % len(self.SUPPORTED_SCENARIOS)]
                scenario_idx += 1

                session_seed = rng.randint(1000, 999999)
                row_id = f"plan-{w_class.name.lower()}-{scen.split('.')[0]}-{rep+1}"

                rows.append(
                    PlannedSessionRow(
                        row_id=row_id,
                        workload_class=w_class,
                        workload_profile_id=f"{w_class.name.lower()}-v1",
                        scenario_id=scen,
                        random_seed=session_seed,
                    )
                )

        rng.shuffle(rows)
        return rows

    def compute_coverage_report(self, rows: list[PlannedSessionRow]) -> CoverageReport:
        """Analyze plan for confounding / shortcut risks."""
        report = CoverageReport(total_planned=len(rows))

        for r in rows:
            c = r.workload_class.value
            report.class_counts[c] = report.class_counts.get(c, 0) + 1

            mode = "Transport" if "transport" in r.scenario_id else "Tunnel"
            cipher = "AES-CBC" if "cbc" in r.scenario_id else "AES-GCM"
            ip_ver = "IPv6" if "ipv6" in r.scenario_id else "IPv4"
            impair = "Netem" if "impairment" in r.scenario_id else "Baseline"

            if c not in report.class_by_mode:
                report.class_by_mode[c] = {}
            report.class_by_mode[c][mode] = report.class_by_mode[c].get(mode, 0) + 1

            if c not in report.class_by_cipher:
                report.class_by_cipher[c] = {}
            report.class_by_cipher[c][cipher] = report.class_by_cipher[c].get(cipher, 0) + 1

            if c not in report.class_by_ip_version:
                report.class_by_ip_version[c] = {}
            report.class_by_ip_version[c][ip_ver] = report.class_by_ip_version[c].get(ip_ver, 0) + 1

            if c not in report.class_by_impairment:
                report.class_by_impairment[c] = {}
            report.class_by_impairment[c][impair] = report.class_by_impairment[c].get(impair, 0) + 1

        for c, ciphers in report.class_by_cipher.items():
            if len(ciphers) == 1 and report.class_counts[c] > 1:
                report.anti_shortcut_warnings.append(
                    f"Class '{c}' only tested under a single cipher family ({list(ciphers.keys())[0]}). Risk of cipher shortcut."
                )

        return report
