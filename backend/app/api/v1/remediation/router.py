"""FastAPI Router for Stage 10 Configuration Security Twin & Closed-Loop Remediation."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.websocket.router import ws_manager
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.remediation import (
    ConfigurationSnapshotModel,
    ConfigurationTwinModel,
    RemediationRunModel,
    RemediationRunStepModel,
    RemediationVerificationClaimModel,
    RemediationVerificationModel,
)
from app.db.models.security import ComplianceEvaluationModel, SecurityFindingModel
from app.db.session import get_db_session
from app.remediation.ir import ConfigurationIR
from app.remediation.parser import ForensicFactsSnapshotBuilder, SwanctlParser
from app.remediation.renderer import ConfigurationDiffEngine, SwanctlRenderer
from app.remediation.runner import ClosedLoopRemediationRunner
from app.remediation.twin import ConfigurationSecurityTwin
from app.security.facts.models import EvidenceState, SecurityFact, SubjectType
from app.security.findings.models import SecurityFinding

router = APIRouter(prefix="/analyses/{analysis_id}/remediation", tags=["Remediation & Security Twin"])


# Request / Response Models
class EditProposalRequest(BaseModel):
    proposal_swanctl_text: str = Field(..., description="Custom or edited swanctl.conf configuration text")
    target_finding_ids: list[str] | None = Field(default=None, description="Optional subset of findings to target")


class ApplyRemediationRequest(BaseModel):
    twin_id: uuid.UUID = Field(..., description="Configuration Twin ID being deployed")
    proposal_hash: str = Field(..., description="SHA-256 hash of the operator-approved proposal")
    lab_instance_id: str = Field(default="strongswan-lab-default", description="Allowlisted internal testbed instance")
    operator_id: str = Field(default="analyst-local", description="Authorizing operator identifier")
    confirm_controlled_lab_only: bool = Field(..., description="Must explicitly confirm lab-only deployment")


class PreflightResponse(BaseModel):
    status: str
    is_ready: bool
    checks: list[dict[str, Any]]
    blocking_reasons: list[str]


class TwinResponse(BaseModel):
    twin_id: uuid.UUID
    analysis_id: uuid.UUID
    status: str
    proposal_hash: str
    current_snapshot: dict[str, Any]
    proposed_ir: dict[str, Any]
    rendered_proposed_config: str
    semantic_diff: list[dict[str, Any]]
    text_diff: str
    projected_regression_audit: dict[str, Any]
    projected_score: float | None
    projected_score_delta: float | None
    disclaimer: str


class RemediationRunStepResponse(BaseModel):
    sequence: int
    action_type: str
    status: str
    safe_output: dict[str, Any] | None
    error_code: str | None
    created_at: str


class RemediationRunResponse(BaseModel):
    run_id: uuid.UUID
    twin_id: uuid.UUID
    status: str
    proposal_hash: str
    lab_instance_id: str
    operator_id: str
    rollback_state: str
    rollback_reason: str | None
    error_message: str | None
    steps: list[RemediationRunStepResponse] = []
    executed_at: str
    completed_at: str | None


class VerificationClaimResponse(BaseModel):
    claim_id: str
    rule_id: str
    rule_version: str
    root_cause_key: str
    claim_result: str
    reason_code: str
    expected_condition: str | None
    baseline_evidence: dict[str, Any] | None
    post_evidence: dict[str, Any] | None


class VerificationResponse(BaseModel):
    verification_id: uuid.UUID
    remediation_run_id: uuid.UUID
    baseline_analysis_id: uuid.UUID
    post_analysis_id: uuid.UUID | None
    post_capture_id: uuid.UUID | None
    verification_result: str
    security_result: str
    operational_result: str
    baseline_score: float | None
    verified_score: float | None
    score_delta: float | None
    claims: list[VerificationClaimResponse]
    finding_diff_summary: dict[str, Any] | None
    regression_summary: dict[str, Any] | None
    verified_at: str


# Helper: Initialize or retrieve Twin
async def _get_or_create_twin(
    analysis_id: uuid.UUID,
    db: AsyncSession,
    custom_proposal_text: str | None = None,
) -> ConfigurationTwinModel:
    """Retrieves the latest twin or synthesizes a new one from Stage 8 findings."""
    res_a = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res_a.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis run not found.")

    res_cap = await db.execute(select(Capture).where(Capture.id == analysis.capture_id))
    capture = res_cap.scalar_one_or_none()
    cap_hash = capture.sha256_hash if capture else "0" * 64

    # Fetch baseline findings
    res_f = await db.execute(select(SecurityFindingModel).where(SecurityFindingModel.analysis_id == analysis_id))
    finding_models = res_f.scalars().all()
    baseline_findings: list[SecurityFinding] = []
    for fm in finding_models:
        baseline_findings.append(
            SecurityFinding.create(
                finding_id=str(fm.id),
                analysis_id=str(analysis_id),
                rule_id=fm.rule_id,
                rule_version=fm.rule_version,
                profile_id=fm.profile_id or "profile_nist_sp800_77",
                category=fm.category,
                severity=fm.severity,
                title=fm.title,
                technical_description=fm.technical_description,
                root_cause_key=fm.root_cause_key,
                affected_entity_type=fm.affected_entity_type,
                affected_entity_id=fm.affected_entity_id,
                observed_value="OBSERVED_VALUE",
                expected_requirement="EXPECTED_REQUIREMENT",
                remediation_guidance=fm.remediation_guidance or "",
                remediation_strongswan_directive=fm.remediation_directive,
            )
        )


    # Build Current Snapshot
    current_snapshot = ForensicFactsSnapshotBuilder.build_snapshot(
        analysis_id=str(analysis_id),
        capture_sha256=cap_hash,
        facts=[],
    )

    twin_engine = ConfigurationSecurityTwin()

    if custom_proposal_text:
        proposed_ir = SwanctlParser.parse_text(custom_proposal_text)
    else:
        # Check if an existing twin is in the DB
        res_existing = await db.execute(
            select(ConfigurationTwinModel)
            .where(ConfigurationTwinModel.analysis_id == analysis_id)
            .order_by(desc(ConfigurationTwinModel.created_at))
        )
        existing_twin = res_existing.scalar_one_or_none()
        if existing_twin:
            return existing_twin

        # Deterministically synthesize proposal from findings
        proposed_ir = twin_engine.generate_remediation_proposal(current_snapshot, baseline_findings)

    # Run Policy Projection
    sim_result = twin_engine.run_projection(
        analysis_id=str(analysis_id),
        current_snapshot=current_snapshot,
        proposed_ir=proposed_ir,
        baseline_findings=baseline_findings,
        baseline_score=45.0,  # Contextual baseline
        baseline_risk_score=75.0,
    )

    # Create Snapshots in DB
    current_snap_model = ConfigurationSnapshotModel(
        analysis_id=analysis_id,
        snapshot_type="OBSERVED_CURRENT",
        config_format="OBSERVED_MODEL",
        normalized_ir=current_snapshot.to_configuration_ir().to_dict(),
        config_content=SwanctlRenderer.render(current_snapshot.to_configuration_ir()),
        config_hash=hashlib.sha256(str(current_snapshot.to_dict()).encode()).hexdigest(),
        provenance={"analysis_id": str(analysis_id)},
    )
    db.add(current_snap_model)

    hardened_snap_model = ConfigurationSnapshotModel(
        analysis_id=analysis_id,
        snapshot_type="POLICY_GENERATED_PROPOSED" if not custom_proposal_text else "USER_PROPOSED",
        config_format="SWANCTL",
        normalized_ir=proposed_ir.to_dict(),
        config_content=sim_result.rendered_proposed_config,
        config_hash=sim_result.proposal_hash,
        provenance={"twin_proposal": True},
    )
    db.add(hardened_snap_model)
    await db.flush()

    # Create Twin Record
    twin_model = ConfigurationTwinModel(
        analysis_id=analysis_id,
        observed_snapshot_id=current_snap_model.id,
        hardened_snapshot_id=hardened_snap_model.id,
        proposal_hash=sim_result.proposal_hash,
        projected_score=sim_result.projected_score,
        projected_score_delta=sim_result.projected_score_delta,
        diff_text=sim_result.text_diff,
        semantic_diff=sim_result.semantic_diff,
        projected_regression_audit=sim_result.regression_audit.to_dict(),
        status="PROJECTED",
    )
    db.add(twin_model)
    await db.commit()
    await db.refresh(twin_model)
    return twin_model


@router.get("/twin", response_model=TwinResponse)
async def get_configuration_twin(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> TwinResponse:
    """Retrieve or initialize the counterfactual Configuration Security Twin."""
    twin = await _get_or_create_twin(analysis_id, db)

    # Fetch snapshots
    res_obs = await db.execute(
        select(ConfigurationSnapshotModel).where(ConfigurationSnapshotModel.id == twin.observed_snapshot_id)
    )
    obs_snap = res_obs.scalar_one()

    res_hard = await db.execute(
        select(ConfigurationSnapshotModel).where(ConfigurationSnapshotModel.id == twin.hardened_snapshot_id)
    )
    hard_snap = res_hard.scalar_one()

    return TwinResponse(
        twin_id=twin.id,
        analysis_id=twin.analysis_id,
        status=twin.status,
        proposal_hash=twin.proposal_hash,
        current_snapshot=obs_snap.normalized_ir or {},
        proposed_ir=hard_snap.normalized_ir or {},
        rendered_proposed_config=hard_snap.config_content or "",
        semantic_diff=twin.semantic_diff or [],
        text_diff=twin.diff_text or "",
        projected_regression_audit=twin.projected_regression_audit or {},
        projected_score=float(twin.projected_score) if twin.projected_score is not None else None,
        projected_score_delta=float(twin.projected_score_delta) if twin.projected_score_delta is not None else None,
        disclaimer=(twin.projected_regression_audit or {}).get(
            "disclaimer", "Counterfactual projection only. Fresh lab re-testing required for verification."
        ),
    )


@router.post("/twin/proposals", response_model=TwinResponse)
async def update_twin_proposal(
    analysis_id: uuid.UUID,
    req: EditProposalRequest,
    db: AsyncSession = Depends(get_db_session),
) -> TwinResponse:
    """Update proposed configuration, re-project policies, and create new immutable Twin revision."""
    twin = await _get_or_create_twin(analysis_id, db, custom_proposal_text=req.proposal_swanctl_text)
    return await get_configuration_twin(analysis_id, db)


@router.post("/twin/preflight", response_model=PreflightResponse)
async def run_preflight_gate(
    analysis_id: uuid.UUID,
    twin_id: uuid.UUID = Query(..., description="Twin ID to validate"),
    proposal_hash: str = Query(..., description="Expected proposal hash"),
    db: AsyncSession = Depends(get_db_session),
) -> PreflightResponse:
    """Run all preflight readiness checks before enabling 'Validate in Controlled Lab'."""
    runner = ClosedLoopRemediationRunner()
    res = await runner.run_preflight_checks(db, analysis_id, twin_id, proposal_hash)
    return PreflightResponse(
        status=res.status,
        is_ready=res.is_ready,
        checks=res.checks,
        blocking_reasons=res.blocking_reasons,
    )


@router.post("/apply", response_model=RemediationRunResponse)
async def apply_remediation(
    analysis_id: uuid.UUID,
    req: ApplyRemediationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> RemediationRunResponse:
    """Authorize and execute closed-loop remediation on the isolated strongSwan testbed."""
    if not req.confirm_controlled_lab_only:
        raise HTTPException(
            status_code=400,
            detail="Safety Violation: Must explicitly confirm that execution targets the controlled strongSwan lab only.",
        )

    # Fetch twin
    res_t = await db.execute(select(ConfigurationTwinModel).where(ConfigurationTwinModel.id == req.twin_id))
    twin = res_t.scalar_one_or_none()
    if not twin:
        raise HTTPException(status_code=404, detail="Configuration Twin not found.")

    if twin.proposal_hash != req.proposal_hash:
        raise HTTPException(
            status_code=409,
            detail="Hash Conflict: Proposal changed since operator approved. Re-run preflight and approval.",
        )

    # Create Remediation Run record
    run = RemediationRunModel(
        twin_id=req.twin_id,
        lab_instance_id=req.lab_instance_id,
        proposal_hash=req.proposal_hash,
        operator_id=req.operator_id,
        status="CREATED",
        approval_timestamp=twin.created_at,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Spawn background closed-loop runner
    runner = ClosedLoopRemediationRunner()

    async def _async_exec():
        from app.db.session import get_session_factory
        session_factory = get_session_factory()
        async with session_factory() as run_db:
            await runner.execute_closed_loop_run(
                db=run_db,
                run_id=run.id,
                analysis_id=analysis_id,
                twin_id=req.twin_id,
                approved_proposal_hash=req.proposal_hash,
                operator_id=req.operator_id,
                lab_instance_id=req.lab_instance_id,
            )
            # Broadcast completion event over WebSocket
            await ws_manager.broadcast_to_analysis(
                analysis_id=analysis_id,
                event_type="REMEDIATION_RUN_COMPLETED",
                payload={"run_id": str(run.id), "status": run.status},
            )

    background_tasks.add_task(_async_exec)

    return RemediationRunResponse(
        run_id=run.id,
        twin_id=run.twin_id,
        status=run.status,
        proposal_hash=run.proposal_hash,
        lab_instance_id=run.lab_instance_id,
        operator_id=run.operator_id,
        rollback_state=run.rollback_state,
        rollback_reason=run.rollback_reason,
        error_message=run.error_message,
        steps=[],
        executed_at=run.executed_at.isoformat(),
        completed_at=None,
    )


@router.get("/runs/{run_id}", response_model=RemediationRunResponse)
async def get_remediation_run(
    analysis_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> RemediationRunResponse:
    """Retrieve the live lifecycle status and append-only step journal of a remediation run."""
    res_r = await db.execute(select(RemediationRunModel).where(RemediationRunModel.id == run_id))
    run = res_r.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Remediation run not found.")

    res_steps = await db.execute(
        select(RemediationRunStepModel)
        .where(RemediationRunStepModel.remediation_run_id == run_id)
        .order_by(RemediationRunStepModel.sequence)
    )
    steps = res_steps.scalars().all()

    return RemediationRunResponse(
        run_id=run.id,
        twin_id=run.twin_id,
        status=run.status,
        proposal_hash=run.proposal_hash,
        lab_instance_id=run.lab_instance_id,
        operator_id=run.operator_id,
        rollback_state=run.rollback_state,
        rollback_reason=run.rollback_reason,
        error_message=run.error_message,
        steps=[
            RemediationRunStepResponse(
                sequence=s.sequence,
                action_type=s.action_type,
                status=s.status,
                safe_output=s.safe_output,
                error_code=s.error_code,
                created_at=s.created_at.isoformat(),
            )
            for s in steps
        ],
        executed_at=run.executed_at.isoformat(),
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
    )


@router.get("/verifications/{verification_id}", response_model=VerificationResponse)
async def get_remediation_verification(
    analysis_id: uuid.UUID,
    verification_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VerificationResponse:
    """Retrieve empirical verification outcome, dual-axis results, and Claim Ledger entries."""
    res_v = await db.execute(
        select(RemediationVerificationModel).where(RemediationVerificationModel.id == verification_id)
    )
    ver = res_v.scalar_one_or_none()
    if not ver:
        raise HTTPException(status_code=404, detail="Remediation verification record not found.")

    res_claims = await db.execute(
        select(RemediationVerificationClaimModel).where(
            RemediationVerificationClaimModel.verification_id == verification_id
        )
    )
    claims = res_claims.scalars().all()

    return VerificationResponse(
        verification_id=ver.id,
        remediation_run_id=ver.remediation_run_id,
        baseline_analysis_id=ver.baseline_analysis_id,
        post_analysis_id=ver.post_analysis_id,
        post_capture_id=ver.post_capture_id,
        verification_result=ver.verification_result,
        security_result=ver.security_result,
        operational_result=ver.operational_result,
        baseline_score=float(ver.baseline_score) if ver.baseline_score is not None else None,
        verified_score=float(ver.verified_score) if ver.verified_score is not None else None,
        score_delta=float(ver.score_delta) if ver.score_delta is not None else None,
        claims=[
            VerificationClaimResponse(
                claim_id=str(c.id),
                rule_id=c.rule_id,
                rule_version=c.rule_version,
                root_cause_key=c.root_cause_key,
                claim_result=c.claim_result,
                reason_code=c.reason_code,
                expected_condition=c.expected_condition,
                baseline_evidence=c.baseline_evidence,
                post_evidence=c.post_evidence,
            )
            for c in claims
        ],
        finding_diff_summary=ver.finding_diff_summary,
        regression_summary=ver.regression_summary,
        verified_at=ver.verified_at.isoformat(),
    )


@router.get("/latest-verification", response_model=VerificationResponse | None)
async def get_latest_verification(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VerificationResponse | None:
    """Retrieve the most recent verification record for this baseline analysis."""
    res_v = await db.execute(
        select(RemediationVerificationModel)
        .where(RemediationVerificationModel.baseline_analysis_id == analysis_id)
        .order_by(desc(RemediationVerificationModel.verified_at))
    )
    ver = res_v.scalar_one_or_none()
    if not ver:
        return None

    return await get_remediation_verification(analysis_id, ver.id, db)
