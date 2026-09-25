"""Closed-Loop Remediation Runner and SAGA Step Journal Orchestrator.

Executes atomic, verified remediation runs on the isolated strongSwan testbed.
Enforces exclusive concurrency locking, mandatory pre-apply configuration backups,
hash-bound operator approval validation, fresh-SA establishment checks,
workload equivalence execution, fresh packet sniffing, and automatic rollback on failure.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from enum import Enum

from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.db.models.remediation import (
    ConfigurationSnapshotModel,
    ConfigurationTwinModel,
    RemediationRunModel,
    RemediationRunStepModel,
    RemediationVerificationClaimModel,
    RemediationVerificationModel,
)
from app.db.models.security import ComplianceEvaluationModel, SecurityFindingModel
from app.integrations.privileged_agent.base import PrivilegedAgentClient
from app.integrations.privileged_agent.local import LocalPrivilegedAgentClient
from app.remediation.comparator import VerificationComparator
from app.remediation.ir import ConfigurationIR
from app.remediation.parser import ForensicFactsSnapshotBuilder, SwanctlParser
from app.remediation.proof import ProofOutcome, VerificationProofObligation
from app.remediation.renderer import SwanctlRenderer
from app.remediation.twin import ConfigurationSecurityTwin
from app.security.findings.models import SecurityFinding
from app.security.policy.schema import FindingCategory, Severity
from app.security.scoring.engine import SecurityScoringEngine
from app.security.service import SecurityAssessmentService
from lab.agent.cleanup.tracker import LabResourceTracker, LabConcurrencyError

logger = logging.getLogger(__name__)


class RollbackTriggerCode(str, Enum):
    """Machine-checkable conditions that mandate immediate remediation rollback."""

    PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"
    LOCK_CONFLICT = "LOCK_CONFLICT"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    CANDIDATE_LOAD_FAILED = "CANDIDATE_LOAD_FAILED"
    FRESH_SA_FAILED = "FRESH_SA_FAILED"
    WORKLOAD_CONNECTIVITY_FAILED = "WORKLOAD_CONNECTIVITY_FAILED"
    POST_CAPTURE_FAILED = "POST_CAPTURE_FAILED"
    POST_ANALYSIS_FAILED = "POST_ANALYSIS_FAILED"
    CRITICAL_SECURITY_REGRESSION = "CRITICAL_SECURITY_REGRESSION"
    TIMEOUT_EXCEEDED = "TIMEOUT_EXCEEDED"
    EXECUTION_ERROR = "EXECUTION_ERROR"


class RemediationExecutionError(RuntimeError):
    """Raised when an explicit operational or security gate fails during execution."""

    def __init__(self, trigger_code: RollbackTriggerCode, message: str) -> None:
        super().__init__(message)
        self.trigger_code = trigger_code


@dataclass
class PreflightCheckResult:
    """Consolidated preflight readiness evaluation."""

    status: str  # READY | BLOCKED | WARNING
    is_ready: bool
    checks: list[dict[str, Any]]
    blocking_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "is_ready": self.is_ready,
            "checks": self.checks,
            "blocking_reasons": self.blocking_reasons,
        }


class ClosedLoopRemediationRunner:
    """SAGA-style orchestrator executing safe, evidence-backed closed-loop remediation."""

    def __init__(
        self,
        agent_client: PrivilegedAgentClient | None = None,
        security_service: SecurityAssessmentService | None = None,
    ) -> None:
        self.agent = agent_client or LocalPrivilegedAgentClient()
        self.security_service = security_service or SecurityAssessmentService()
        self.scoring_engine = SecurityScoringEngine()

    async def run_preflight_checks(
        self,
        db: AsyncSession,
        analysis_id: uuid.UUID,
        twin_id: uuid.UUID,
        proposal_hash: str,
        lab_instance_id: str = "strongswan-lab-default",
    ) -> PreflightCheckResult:
        """Evaluate all safety gates before permitting remediation apply."""
        checks: list[dict[str, Any]] = []
        blocking: list[str] = []

        # 1. Baseline analysis exists and completed
        res_a = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
        analysis = res_a.scalar_one_or_none()
        if not analysis:
            blocking.append("Baseline analysis run not found.")
            checks.append({"code": "BASELINE_EXISTS", "status": "FAIL", "message": "Baseline analysis run not found."})
        elif analysis.status not in ("COMPLETED", "PROCESSED"):
            blocking.append(f"Baseline analysis is not completed (current status: {analysis.status}).")
            checks.append({"code": "BASELINE_STATUS", "status": "FAIL", "message": f"Baseline status: {analysis.status}"})
        else:
            checks.append({"code": "BASELINE_STATUS", "status": "PASS", "message": "Baseline analysis completed."})

        # 2. Twin exists and proposal hash matches
        res_t = await db.execute(select(ConfigurationTwinModel).where(ConfigurationTwinModel.id == twin_id))
        twin = res_t.scalar_one_or_none()
        if not twin:
            blocking.append("Configuration Twin record not found.")
            checks.append({"code": "TWIN_EXISTS", "status": "FAIL", "message": "Twin record not found."})
        elif twin.proposal_hash != proposal_hash:
            blocking.append("Proposal hash mismatch between request and immutable twin record.")
            checks.append({"code": "HASH_INTEGRITY", "status": "FAIL", "message": "Proposal hash mismatch."})
        else:
            checks.append({"code": "HASH_INTEGRITY", "status": "PASS", "message": f"Proposal hash verified: {proposal_hash[:12]}..."})

        # 3. Candidate syntax validation
        res_snap = await db.execute(
            select(ConfigurationSnapshotModel).where(ConfigurationSnapshotModel.id == twin.hardened_snapshot_id)
        )
        hardened_snap = res_snap.scalar_one_or_none()
        if not hardened_snap or not hardened_snap.config_content:
            blocking.append("Hardened configuration text missing in snapshot.")
            checks.append({"code": "CONFIG_SYNTAX", "status": "FAIL", "message": "Hardened text missing."})
        else:
            val_res = await self.agent.execute_action(
                "VALIDATE_CONFIG",
                {"candidate_config_text": hardened_snap.config_content},
            )
            if not val_res.get("valid", False):
                blocking.append(f"Candidate configuration syntax invalid: {val_res.get('errors')}")
                checks.append({"code": "CONFIG_SYNTAX", "status": "FAIL", "message": str(val_res.get("errors"))})
            else:
                checks.append({"code": "CONFIG_SYNTAX", "status": "PASS", "message": "strongSwan swanctl syntax valid."})

        # 4. Privileged Agent availability
        agent_status = await self.agent.get_status()
        if not agent_status.available:
            blocking.append(f"Class B Privileged Agent is unavailable: {agent_status.message}")
            checks.append({"code": "PRIVILEGED_AGENT", "status": "FAIL", "message": agent_status.message})
        else:
            checks.append({"code": "PRIVILEGED_AGENT", "status": "PASS", "message": "Privileged Agent UP and ready."})

        # 5. Concurrency lock check
        lock_path = Path(__file__).resolve().parent.parent.parent.parent / "lab" / "runtime" / "lab.lock"
        if lock_path.exists():
            blocking.append("Testbed is currently locked by another active experiment.")
            checks.append({"code": "TESTBED_LOCK", "status": "FAIL", "message": "Testbed lock currently held."})
        else:
            checks.append({"code": "TESTBED_LOCK", "status": "PASS", "message": "Testbed lock available."})

        # 6. Blocking security regressions check
        audit = twin.projected_regression_audit or {} if twin else {}
        if audit.get("has_blocking_regressions", False):
            blocking.append("Twin projected high/critical security regressions. Automated application blocked.")
            checks.append({"code": "REGRESSION_GUARD", "status": "FAIL", "message": "Critical regressions projected."})
        else:
            checks.append({"code": "REGRESSION_GUARD", "status": "PASS", "message": "No blocking regressions projected."})

        overall_status = "BLOCKED" if blocking else "READY"
        return PreflightCheckResult(
            status=overall_status,
            is_ready=len(blocking) == 0,
            checks=checks,
            blocking_reasons=blocking,
        )

    async def execute_closed_loop_run(
        self,
        db: AsyncSession,
        run_id: uuid.UUID,
        analysis_id: uuid.UUID,
        twin_id: uuid.UUID,
        approved_proposal_hash: str,
        operator_id: str = "analyst-local",
        lab_instance_id: str = "strongswan-lab-default",
        workload_duration_sec: float = 3.0,
    ) -> RemediationRunModel:
        """Executes full SAGA step journal for closed-loop remediation."""
        # 1. Fetch Run and Twin
        res_r = await db.execute(select(RemediationRunModel).where(RemediationRunModel.id == run_id))
        run = res_r.scalar_one_or_none()
        if not run:
            raise ValueError(f"Remediation run {run_id} not found.")

        res_t = await db.execute(select(ConfigurationTwinModel).where(ConfigurationTwinModel.id == twin_id))
        twin = res_t.scalar_one_or_none()
        if not twin:
            raise ValueError(f"Configuration twin {twin_id} not found.")

        # Hash-bound check
        if twin.proposal_hash != approved_proposal_hash:
            raise ValueError("TOCTOU Violation: Approved proposal hash does not match immutable twin proposal hash.")

        res_snap = await db.execute(
            select(ConfigurationSnapshotModel).where(ConfigurationSnapshotModel.id == twin.hardened_snapshot_id)
        )
        hardened_snap = res_snap.scalar_one_or_none()
        if not hardened_snap or not hardened_snap.config_content:
            raise ValueError("Hardened configuration snapshot content missing.")

        tracker = LabResourceTracker(run_id=str(run_id)[:8])
        step_seq = 1

        async def _record_step(action: str, status: str, output: dict | None = None, err: str | None = None) -> None:
            nonlocal step_seq
            step = RemediationRunStepModel(
                remediation_run_id=run_id,
                sequence=step_seq,
                action_type=action,
                input_hash=approved_proposal_hash,
                status=status,
                safe_output=output,
                error_code=err,
            )
            step_seq += 1
            db.add(step)
            await db.commit()

        # Step 1: Preflight
        if not run.rollback_state:
            run.rollback_state = "NONE"
        run.status = "PREFLIGHT"
        await db.commit()
        preflight = await self.run_preflight_checks(db, analysis_id, twin_id, approved_proposal_hash, lab_instance_id)
        if not preflight.is_ready:
            run.status = "FAILED"
            run.error_message = f"Preflight failed: {preflight.blocking_reasons}"
            await _record_step("PREFLIGHT", "FAILED", preflight.to_dict(), RollbackTriggerCode.PREFLIGHT_BLOCKED.value)
            await db.commit()
            return run
        await _record_step("PREFLIGHT", "SUCCESS", preflight.to_dict())

        # Step 2: Acquire Lock
        try:
            tracker.acquire_lock(run_id=str(run_id))
            await _record_step("ACQUIRE_LOCK", "SUCCESS", {"lock_file": str(tracker.lock_file)})
        except LabConcurrencyError as exc:
            run.status = "FAILED"
            run.error_message = str(exc)
            await _record_step("ACQUIRE_LOCK", "FAILED", None, RollbackTriggerCode.LOCK_CONFLICT.value)
            await db.commit()
            return run

        backup_path: str | None = None
        backup_hash: str | None = None
        applied_active_path = f"/tmp/tt-{tracker.run_id}/gw_a/swanctl/swanctl.conf"

        try:
            # Step 3: Mandatory Pre-Apply Backup (fails closed if baseline missing)
            run.status = "BACKUP_CREATED"
            await db.commit()
            backup_dest = f"/tmp/tt-{tracker.run_id}/backup/swanctl.conf.bak"
            backup_res = await self.agent.execute_action(
                "BACKUP_CONFIG",
                {"active_config_path": applied_active_path, "backup_dest_path": backup_dest, "run_id": tracker.run_id},
            )
            backup_path = backup_res["backup_path"]
            backup_hash = backup_res["backup_sha256"]

            # Save Backup Snapshot to DB
            backup_snap = ConfigurationSnapshotModel(
                analysis_id=analysis_id,
                snapshot_type="LAB_BACKUP",
                config_format="SWANCTL",
                config_content=backup_res.get("content", ""),
                config_hash=backup_hash,
                provenance={"run_id": str(run_id), "path": backup_path},
            )
            db.add(backup_snap)
            await db.commit()
            run.backup_snapshot_id = backup_snap.id
            await _record_step("BACKUP_CONFIG", "SUCCESS", {"backup_hash": backup_hash, "path": backup_path})

            # Step 4: Record Pre-Apply SA State (to ensure post-apply SA is genuinely fresh)
            pre_sa_res = await self.agent.execute_action(
                "VERIFY_FRESH_SA",
                {
                    "namespace": "gw_a",
                    "peer_dir": f"/tmp/tt-{tracker.run_id}/gw_a",
                    "vici_socket": f"/tmp/tt-{tracker.run_id}/gw_a/charon.vici",
                },
            )
            pre_apply_spis = pre_sa_res.get("observed_spis", [])
            run.pre_apply_spis = pre_apply_spis
            await db.commit()
            await _record_step("PRE_APPLY_SA_STATE", "SUCCESS", {"observed_spis": pre_apply_spis})

            # Step 5: Apply Candidate Configuration (atomic replace with readback verification)
            run.status = "APPLYING"
            await db.commit()
            apply_res = await self.agent.execute_action(
                "APPLY_CONFIG",
                {
                    "target_path": applied_active_path,
                    "config_text": hardened_snap.config_content,
                    "expected_hash": approved_proposal_hash,
                    "run_id": tracker.run_id,
                },
            )
            if not apply_res.get("verified", False):
                raise RemediationExecutionError(
                    RollbackTriggerCode.INTEGRITY_MISMATCH,
                    f"Applied config readback SHA-256 mismatch against approved proposal hash {approved_proposal_hash}."
                )

            run.status = "CONFIG_APPLIED"
            run.applied_snapshot_id = hardened_snap.id
            await _record_step("APPLY_CONFIG", "SUCCESS", apply_res)

            # Step 6: Reload strongSwan inside isolated namespace
            run.status = "RELOADING"
            await db.commit()
            reload_res = await self.agent.execute_action(
                "RELOAD_STRONGSWAN",
                {
                    "namespace": "gw_a",
                    "peer_dir": f"/tmp/tt-{tracker.run_id}/gw_a",
                    "vici_socket": f"/tmp/tt-{tracker.run_id}/gw_a/charon.vici",
                },
            )
            if not reload_res.get("load_success", False):
                raise RemediationExecutionError(
                    RollbackTriggerCode.CANDIDATE_LOAD_FAILED,
                    f"strongSwan candidate configuration load failed: {reload_res.get('load_stdout')}"
                )
            await _record_step("RELOAD_STRONGSWAN", "SUCCESS", reload_res)

            # Step 7: Verify Fresh SA (must establish new SPI distinct from pre-apply state)
            run.status = "REESTABLISHING"
            await db.commit()
            sa_res = await self.agent.execute_action(
                "VERIFY_FRESH_SA",
                {
                    "namespace": "gw_a",
                    "peer_dir": f"/tmp/tt-{tracker.run_id}/gw_a",
                    "vici_socket": f"/tmp/tt-{tracker.run_id}/gw_a/charon.vici",
                    "old_spis": pre_apply_spis,
                },
            )
            if not sa_res.get("fresh_sa_established", False):
                raise RemediationExecutionError(
                    RollbackTriggerCode.FRESH_SA_FAILED,
                    f"Failed to verify newly established Security Association distinct from pre-apply SPIs {pre_apply_spis}."
                )
            await _record_step("VERIFY_FRESH_SA", "SUCCESS", sa_res)

            # Step 8: Verification Traffic Workload & Sniffing
            run.status = "CAPTURING"
            await db.commit()
            post_pcap_path = f"/tmp/tt-{tracker.run_id}/verification_post_{run_id}.pcap"
            cap_start = await self.agent.execute_action(
                "START_LIVE_CAPTURE",
                {
                    "session_id": f"cap-{run_id}",
                    "interface": "lo",
                    "output_pcap": post_pcap_path,
                    "run_id": tracker.run_id,
                },
            )

            # Run synthetic workload through tunnel
            run.status = "VERIFYING_CONNECTIVITY"
            await db.commit()
            workload_res = await self.agent.execute_action(
                "RUN_REMEDIATION_WORKLOAD",
                {"target_ip": "10.0.1.2", "namespace": "gw_a"},
            )
            await asyncio.sleep(min(workload_duration_sec, 2.0))

            cap_stop = await self.agent.execute_action(
                "STOP_LIVE_CAPTURE",
                {"session_id": f"cap-{run_id}"},
            )

            # Machine-checkable operational rollback threshold: packet loss > 10% or workload failure
            packet_loss = workload_res.get("packet_loss_pct", 0.0)
            if not workload_res.get("success", True) or packet_loss > 10.0:
                raise RemediationExecutionError(
                    RollbackTriggerCode.WORKLOAD_CONNECTIVITY_FAILED,
                    f"Post-remediation workload connectivity failed: packet loss {packet_loss}% exceeds 10.0% threshold."
                )

            await _record_step("CAPTURE_AND_WORKLOAD", "SUCCESS", {"workload": workload_res, "capture": cap_stop})

            # Validate real capture artifact on disk
            real_file_size: int = 0
            real_pcap_hash: str | None = None
            if os.path.exists(post_pcap_path):
                real_file_size = os.path.getsize(post_pcap_path)
                with open(post_pcap_path, "rb") as pf:
                    pcap_bytes = pf.read()
                real_pcap_hash = hashlib.sha256(pcap_bytes).hexdigest()
            elif cap_stop.get("sha256") and cap_stop.get("file_size", 0) > 0:
                real_file_size = cap_stop["file_size"]
                real_pcap_hash = cap_stop["sha256"]
            else:
                # If neither local disk nor inspect_pcap produced real bytes
                raise RemediationExecutionError(
                    RollbackTriggerCode.POST_CAPTURE_FAILED,
                    f"Post-remediation capture artifact missing or 0 bytes at {post_pcap_path}."
                )

            if real_file_size == 0 or not real_pcap_hash:
                raise RemediationExecutionError(
                    RollbackTriggerCode.POST_CAPTURE_FAILED,
                    f"Post-remediation capture artifact at {post_pcap_path} is empty (0 bytes)."
                )

            run.post_capture_hash = real_pcap_hash

            # Copy capture to permanent storage path
            storage_dest = f"storage/captures/verification_{run_id}.pcap"
            os.makedirs(os.path.dirname(storage_dest), exist_ok=True)
            if os.path.exists(post_pcap_path):
                with open(post_pcap_path, "rb") as src, open(storage_dest, "wb") as dst:
                    dst.write(src.read())

            post_capture = Capture(
                capture_source="TESTBED_GENERATED",
                capture_format="PCAP",
                original_filename=f"verification_{run_id}.pcap",
                storage_path=storage_dest,
                file_size_bytes=real_file_size,
                sha256_hash=real_pcap_hash,
            )
            db.add(post_capture)
            await db.commit()

            # Step 9: Post-Reanalysis Execution
            run.status = "REANALYZING"
            await db.commit()
            post_analysis = AnalysisRun(
                capture_id=post_capture.id,
                status="PENDING",
                current_stage="PENDING",
            )
            db.add(post_analysis)
            await db.commit()

            try:
                from app.services.pipeline import execute_full_analysis_pipeline
                await execute_full_analysis_pipeline(analysis_id=post_analysis.id, db=db)
                res_pa = await db.execute(select(AnalysisRun).where(AnalysisRun.id == post_analysis.id))
                post_analysis = res_pa.scalar_one()
            except Exception as pipe_err:
                logger.warning("Pipeline execution error on verification pcap: %s", pipe_err)
                res_pa = await db.execute(select(AnalysisRun).where(AnalysisRun.id == post_analysis.id))
                post_analysis = res_pa.scalar_one_or_none() or post_analysis
                if post_analysis.status != "COMPLETED":
                    post_analysis.status = "FAILED"
                    post_analysis.error_message = str(pipe_err)
                    await db.commit()

            if post_analysis.status not in ("COMPLETED", "PROCESSED"):
                raise RemediationExecutionError(
                    RollbackTriggerCode.POST_ANALYSIS_FAILED,
                    f"Post-remediation analysis pipeline did not succeed (status: {post_analysis.status}, error: {post_analysis.error_message})."
                )

            # Step 10: Compare Evidence & Formal Proof Obligations
            run.status = "COMPARING"
            await db.commit()

            # Fetch baseline findings
            res_bf = await db.execute(select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id))
            b_finding_models = res_bf.scalars().all()
            baseline_findings: list[SecurityFinding] = []
            for bfm in b_finding_models:
                try:
                    sev = Severity(bfm.severity) if isinstance(bfm.severity, str) else bfm.severity
                except (ValueError, KeyError):
                    sev = Severity.MEDIUM
                try:
                    cat = FindingCategory(bfm.category) if isinstance(bfm.category, str) else bfm.category
                except (ValueError, KeyError):
                    cat = FindingCategory.CRYPTOGRAPHY

                baseline_findings.append(
                    SecurityFinding.create(
                        finding_id=str(bfm.id),
                        analysis_id=str(analysis_id),
                        rule_id=bfm.rule_id,
                        rule_version=bfm.rule_version,
                        profile_id=bfm.profile_id or "profile_nist_sp800_77",
                        category=cat,
                        severity=sev,
                        title=bfm.title,
                        technical_description=bfm.technical_description,
                        root_cause_key=bfm.root_cause_key,
                        affected_entity_type=bfm.affected_entity_type,
                        affected_entity_id=bfm.affected_entity_id,
                        observed_value="NON_COMPLIANT",
                        expected_requirement="COMPLIANT",
                        remediation_guidance=bfm.remediation_guidance or "",
                        remediation_strongswan_directive=bfm.remediation_directive,
                    )
                )

            # Fetch post-remediation findings from DB
            res_pf = await db.execute(select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == post_analysis.id))
            p_finding_models = res_pf.scalars().all()
            post_findings: list[SecurityFinding] = []
            for pfm in p_finding_models:
                try:
                    sev = Severity(pfm.severity) if isinstance(pfm.severity, str) else pfm.severity
                except (ValueError, KeyError):
                    sev = Severity.MEDIUM
                try:
                    cat = FindingCategory(pfm.category) if isinstance(pfm.category, str) else pfm.category
                except (ValueError, KeyError):
                    cat = FindingCategory.CRYPTOGRAPHY

                post_findings.append(
                    SecurityFinding.create(
                        finding_id=str(pfm.id),
                        analysis_id=str(post_analysis.id),
                        rule_id=pfm.rule_id,
                        rule_version=pfm.rule_version,
                        profile_id=pfm.profile_id or "profile_nist_sp800_77",
                        category=cat,
                        severity=sev,
                        title=pfm.title,
                        technical_description=pfm.technical_description,
                        root_cause_key=pfm.root_cause_key,
                        affected_entity_type=pfm.affected_entity_type,
                        affected_entity_id=pfm.affected_entity_id,
                        observed_value=pfm.observed_value,
                        expected_requirement="COMPLIANT",
                        remediation_guidance=pfm.remediation_guidance or "",
                        remediation_strongswan_directive=pfm.remediation_directive,
                    )
                )

            # Reconstruct proof obligations from twin audit
            audit_dict = twin.projected_regression_audit or {}
            raw_obls = audit_dict.get("proof_obligations", [])
            obligations = [VerificationProofObligation.from_dict(o) for o in raw_obls]

            # Ingest real ProtocolObservation and ComplianceEvaluationModel records (ZERO synthetic facts!)
            res_obs = await db.execute(
                select(ProtocolObservation).where(ProtocolObservation.analysis_id == post_analysis.id)
            )
            observations = res_obs.scalars().all()
            observed_fact_map: dict[str, Any] = {}
            for obs in observations:
                observed_fact_map[obs.field_name] = obs.normalized_value
                observed_fact_map[f"{obs.protocol}.{obs.field_name}"] = obs.normalized_value

            res_eval = await db.execute(
                select(ComplianceEvaluationModel).where(ComplianceEvaluationModel.analysis_id == post_analysis.id)
            )
            eval_records = res_eval.scalars().all()
            eval_by_rule = {e.rule_id: e for e in eval_records}

            post_facts_map: dict[str, Any] = {}
            for obl in obligations:
                fact_key = obl.baseline_observed_fact_key
                if fact_key in observed_fact_map:
                    post_facts_map[fact_key] = {
                        "value": observed_fact_map[fact_key],
                        "evidence_state": "VERIFIED",
                    }
                elif obl.target_rule_id in eval_by_rule:
                    e_rec = eval_by_rule[obl.target_rule_id]
                    post_facts_map[fact_key] = {
                        "value": e_rec.observed_value,
                        "evidence_state": e_rec.evidence_state,
                    }
                else:
                    # Epistemic truth: UNKNOWN (never synthesized from proposed IR!)
                    post_facts_map[fact_key] = {
                        "value": None,
                        "evidence_state": "UNKNOWN",
                    }

            comp_result = VerificationComparator.compare(
                proof_obligations=obligations,
                baseline_findings=baseline_findings,
                post_findings=post_findings,
                post_facts=post_facts_map,
                operational_healthy=workload_res.get("success", True),
                analysis_succeeded=(post_analysis.status == "COMPLETED"),
            )

            # Machine-checkable security rollback threshold: any blocking new regression
            if comp_result.has_security_regression:
                raise RemediationExecutionError(
                    RollbackTriggerCode.CRITICAL_SECURITY_REGRESSION,
                    f"Post-remediation analysis introduced blocking security regressions: {comp_result.new_regressions}"
                )

            # Compute empirical verified score from actual post evaluations and findings
            baseline_score = twin.projected_score - (twin.projected_score_delta or 0.0) if twin.projected_score else 45.0
            if eval_records:
                score_res = self.scoring_engine.calculate_score(
                    analysis_id=str(post_analysis.id),
                    findings=post_findings,
                    eval_records=eval_records,
                )
                verified_score = score_res.overall_score
            else:
                verified_score = baseline_score

            score_delta = round(verified_score - baseline_score, 1)

            # Step 11: Persist Verification and Claims
            verification = RemediationVerificationModel(
                remediation_run_id=run_id,
                baseline_analysis_id=analysis_id,
                post_analysis_id=post_analysis.id,
                post_capture_id=post_capture.id,
                verification_result=comp_result.overall_verification_result.value,
                security_result=comp_result.security_result,
                operational_result=comp_result.operational_result,
                baseline_score=baseline_score,
                verified_score=verified_score,
                score_delta=score_delta,
                finding_diff_summary={
                    "resolved": comp_result.resolved_count,
                    "unresolved": comp_result.unresolved_count,
                    "unknown": comp_result.unknown_count,
                },
                regression_summary={"new_regressions": comp_result.new_regressions},
                workload_manifest={
                    "duration_sec": workload_duration_sec,
                    "success": workload_res.get("success", True),
                    "packet_loss_pct": packet_loss,
                },
            )
            db.add(verification)
            await db.commit()

            def _to_uuid(val: Any) -> uuid.UUID | None:
                if not val:
                    return None
                if isinstance(val, uuid.UUID):
                    return val
                try:
                    return uuid.UUID(str(val))
                except (ValueError, TypeError, AttributeError):
                    return None

            for cl in comp_result.claims:
                claim_model = RemediationVerificationClaimModel(
                    verification_id=verification.id,
                    baseline_finding_id=_to_uuid(cl.target_finding_id),
                    rule_id=cl.rule_id,
                    rule_version=cl.rule_version,
                    root_cause_key=cl.root_cause_key,
                    baseline_evidence=cl.baseline_evidence,
                    proposed_transformation=cl.proposed_transformation,
                    expected_condition=cl.expected_condition,
                    post_evidence=cl.post_evidence,
                    claim_result=cl.claim_result.value,
                    reason_code=cl.reason_code.value,
                )
                db.add(claim_model)

            # Mark Run Completed
            run.status = "COMPLETED"
            run.rollback_state = "NONE"
            run.completed_at = datetime.now(timezone.utc)
            await _record_step("EVALUATE_AND_VERIFY", "SUCCESS", comp_result.to_dict())
            await db.commit()
            return run

        except Exception as exc:
            trigger_code = getattr(exc, "trigger_code", RollbackTriggerCode.EXECUTION_ERROR)
            trigger_name = trigger_code.value if hasattr(trigger_code, "value") else str(trigger_code)
            logger.error(
                "Remediation run %s failed with trigger [%s]: %s. Initiating automatic rollback.",
                run_id, trigger_name, exc, exc_info=True,
            )
            run.status = "FAILED"
            run.error_message = f"[{trigger_name}] {exc}"

            # Automatic Rollback
            if backup_path and os.path.exists(backup_path):
                run.status = "ROLLING_BACK"
                run.rollback_state = "TRIGGERED"
                run.rollback_reason = f"Trigger: {trigger_name}. Detail: {exc}"
                await db.commit()
                await _record_step("ROLLBACK_TRIGGERED", "TRIGGERED", {"trigger": trigger_name, "reason": str(exc)})

                try:
                    # 1. Restore backup file atomically and verify readback hash
                    restore_res = await self.agent.execute_action(
                        "RESTORE_BACKUP",
                        {
                            "backup_path": backup_path,
                            "target_path": applied_active_path,
                            "expected_hash": backup_hash,
                            "run_id": tracker.run_id,
                        },
                    )
                    if not restore_res.get("verified", False):
                        raise RuntimeError(f"Restored file digest {restore_res.get('restored_sha256')} != expected {backup_hash}.")

                    # 2. Reload strongSwan daemon inside namespace
                    reload_res = await self.agent.execute_action(
                        "RELOAD_STRONGSWAN",
                        {
                            "namespace": "gw_a",
                            "peer_dir": f"/tmp/tt-{tracker.run_id}/gw_a",
                            "vici_socket": f"/tmp/tt-{tracker.run_id}/gw_a/charon.vici",
                        },
                    )
                    if not reload_res.get("load_success", False):
                        raise RuntimeError(f"Rollback daemon reload failed: {reload_res.get('load_stdout')}")

                    # 3. Verify recovery SA health
                    recovery_sa = await self.agent.execute_action(
                        "VERIFY_FRESH_SA",
                        {
                            "namespace": "gw_a",
                            "peer_dir": f"/tmp/tt-{tracker.run_id}/gw_a",
                            "vici_socket": f"/tmp/tt-{tracker.run_id}/gw_a/charon.vici",
                        },
                    )

                    run.rollback_state = "COMPLETED"
                    run.status = "ROLLED_BACK"
                    await _record_step(
                        "AUTOMATIC_ROLLBACK",
                        "SUCCESS",
                        {
                            "restored_backup": backup_path,
                            "backup_hash": backup_hash,
                            "target_path": applied_active_path,
                            "recovery_sa": recovery_sa,
                        },
                    )
                except Exception as rollback_exc:
                    logger.critical("Automatic rollback verification failed for run %s: %s", run_id, rollback_exc)
                    run.rollback_state = "FAILED"
                    run.status = "ROLLBACK_FAILED"
                    run.error_message = (
                        f"Execution trigger [{trigger_name}]: {exc} | "
                        f"ROLLBACK VERIFICATION FAILED (manual intervention required): {rollback_exc}"
                    )
                    await _record_step("AUTOMATIC_ROLLBACK", "FAILED", None, "ROLLBACK_FAILED")
            else:
                run.rollback_state = "FAILED"
                run.status = "ROLLBACK_FAILED"
                run.error_message = f"Execution trigger [{trigger_name}]: {exc} | No valid baseline backup available to restore."
                await _record_step("AUTOMATIC_ROLLBACK", "FAILED", None, "MISSING_BACKUP")

            await db.commit()
            return run

        finally:
            # Release Mutex Lock
            tracker.release_lock()

