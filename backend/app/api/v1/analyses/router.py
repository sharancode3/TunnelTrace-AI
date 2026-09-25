"""REST API endpoints for asynchronous protocol analysis execution and summary inspection."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.schemas import (
    AnalysisListItemDTO,
    AnalysisOverviewDTO,
    AnalysisRunResponseDTO,
    CreateAnalysisRequestDTO,
    ReplayExecutionResponseDTO,
    TrafficFlowItemDTO,
    TrafficSummaryResponseDTO,
)
from app.replay.models import (
    ForensicReanalysisRequestDTO,
    ReplayLineageDTO,
)
from app.api.v1.security.router import (
    get_compliance_summary,
    get_evidence_graph,
    get_metadata_fingerprintability,
    get_risk_assessment,
    get_security_findings,
    get_security_score,
    get_threat_matrix,
)
from app.api.v1.security.schemas import (
    ComplianceSummaryDTO,
    EvidenceGraphDTO,
    FingerprintabilityDTO,
    RiskAssessmentDTO,
    SecurityFindingDTO,
    SecurityScoreDTO,
    ThreatInstanceDTO,
)
from app.core.errors import AnalysisNotFoundError, CaptureNotFoundError
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import ESPFlow
from app.db.models.security import ScoreAssessmentModel, SecurityFindingModel
from app.db.session import get_db_session
from app.protocol.normalization.models import ProtocolSummaryDTO
from app.protocol.service import ProtocolForensicsService
from app.reporting.snapshot import AnalysisSnapshotBuilder

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post(
    "",
    response_model=AnalysisRunResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue protocol analysis for an ingested capture",
)
async def create_analysis(
    req: CreateAnalysisRequestDTO,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Register an asynchronous protocol forensics run targeting an immutable capture."""
    res_cap = await db.execute(select(Capture).where(Capture.id == req.capture_id))
    capture = res_cap.scalar_one_or_none()
    if not capture:
        raise CaptureNotFoundError(str(req.capture_id))

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture.id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
        schema_version="1.0.0",
        created_at=datetime.now(timezone.utc),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    # Execute deterministic analysis pipeline (dispatches protocol forensics -> reconstruction -> ML inference -> security assessment)
    from app.services.pipeline import execute_full_analysis_pipeline

    await execute_full_analysis_pipeline(analysis.id, db)

    # Reload fresh state
    res_updated = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis.id))
    analysis = res_updated.scalar_one()

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        parent_analysis_id=analysis.parent_analysis_id,
        replay_mode=analysis.replay_mode,
        provenance_metadata=analysis.provenance_metadata,
        created_at=analysis.created_at,
    )


@router.get(
    "",
    response_model=list[AnalysisListItemDTO],
    summary="List all historical and active analysis runs",
)
async def list_analyses(
    db: AsyncSession = Depends(get_db_session),
) -> list[AnalysisListItemDTO]:
    """Retrieve history of all analysis runs with capture metadata and security indicators."""
    stmt = (
        select(AnalysisRun)
        .options(selectinload(AnalysisRun.capture))
        .order_by(AnalysisRun.created_at.desc())
    )
    res = await db.execute(stmt)
    runs = res.scalars().all()
    if not runs:
        return []

    run_ids = [r.id for r in runs]

    # Batch fetch scores
    stmt_scores = select(ScoreAssessmentModel).where(ScoreAssessmentModel.analysis_id.in_(run_ids))
    score_rows = (await db.execute(stmt_scores)).scalars().all()
    score_map = {s.analysis_id: s.overall_score for s in score_rows}

    # Batch fetch findings counts
    stmt_finds = select(SecurityFindingModel).where(SecurityFindingModel.analysis_id.in_(run_ids))
    find_rows = (await db.execute(stmt_finds)).scalars().all()
    crit_map: dict[uuid.UUID, int] = {}
    high_map: dict[uuid.UUID, int] = {}
    for f in find_rows:
        if f.severity == "CRITICAL":
            crit_map[f.analysis_id] = crit_map.get(f.analysis_id, 0) + 1
        elif f.severity == "HIGH":
            high_map[f.analysis_id] = high_map.get(f.analysis_id, 0) + 1

    return [
        AnalysisListItemDTO(
            analysis_id=r.id,
            capture_id=r.capture_id,
            capture_filename=(r.capture.original_filename or "unknown.pcap") if r.capture else "unknown.pcap",
            capture_sha256=(r.capture.sha256_hash or "unknown") if r.capture else "unknown",
            status=r.status,
            current_stage=r.current_stage,
            created_at=r.created_at,
            completed_at=r.completed_at,
            security_score=score_map.get(r.id),
            critical_findings=crit_map.get(r.id, 0),
            high_findings=high_map.get(r.id, 0),
            parent_analysis_id=r.parent_analysis_id,
            replay_mode=r.replay_mode,
        )
        for r in runs
    ]


@router.get(
    "/{analysis_id}",
    response_model=AnalysisRunResponseDTO,
    summary="Retrieve analysis execution status and counters",
)
async def get_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Retrieve operational state and parser version of an analysis run."""
    res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        parent_analysis_id=analysis.parent_analysis_id,
        replay_mode=analysis.replay_mode,
        provenance_metadata=analysis.provenance_metadata,
        created_at=analysis.created_at,
    )


@router.get(
    "/{analysis_id}/protocol",
    response_model=ProtocolSummaryDTO,
    summary="Retrieve normalized IPsec protocol observations summary",
)
async def get_protocol_summary(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ProtocolSummaryDTO:
    """Retrieve verified protocol facts, observed transforms, SPIs, and exchange types."""
    service = ProtocolForensicsService(db)
    return await service.get_protocol_summary(analysis_id)


# Stage 8: Direct /analyses/{analysis_id}/... security endpoints
router.add_api_route(
    "/{analysis_id}/compliance",
    get_compliance_summary,
    methods=["GET"],
    response_model=ComplianceSummaryDTO,
    summary="Retrieve itemized rule compliance evaluations",
)
router.add_api_route(
    "/{analysis_id}/findings",
    get_security_findings,
    methods=["GET"],
    response_model=list[SecurityFindingDTO],
    summary="Retrieve structured security findings",
)
router.add_api_route(
    "/{analysis_id}/security-score",
    get_security_score,
    methods=["GET"],
    response_model=SecurityScoreDTO,
    summary="Retrieve transparent Security Posture Score",
)
router.add_api_route(
    "/{analysis_id}/risk",
    get_risk_assessment,
    methods=["GET"],
    response_model=RiskAssessmentDTO,
    summary="Retrieve deterministic risk evaluation",
)
router.add_api_route(
    "/{analysis_id}/threat-matrix",
    get_threat_matrix,
    methods=["GET"],
    response_model=list[ThreatInstanceDTO],
    summary="Retrieve threat matrix instances",
)
router.add_api_route(
    "/{analysis_id}/metadata-fingerprintability",
    get_metadata_fingerprintability,
    methods=["GET"],
    response_model=FingerprintabilityDTO,
    summary="Retrieve behavioral metadata fingerprintability",
)
router.add_api_route(
    "/{analysis_id}/evidence-graph",
    get_evidence_graph,
    methods=["GET"],
    response_model=EvidenceGraphDTO,
    summary="Retrieve forensic provenance graph",
)


@router.get(
    "/{analysis_id}/overview",
    response_model=AnalysisOverviewDTO,
    summary="Consolidated Command Center overview for an analysis run",
)
async def get_analysis_overview(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisOverviewDTO:
    """Retrieve consolidated overview data without N+1 client round-trips."""
    builder = AnalysisSnapshotBuilder(db)
    try:
        snap = await builder.build_snapshot(analysis_id)
    except ValueError as exc:
        raise AnalysisNotFoundError(str(analysis_id)) from exc

    return AnalysisOverviewDTO(
        analysis_id=analysis_id,
        capture=snap["capture"],
        analysis=snap["analysis"],
        security_posture={
            "score": snap["score"]["score"],
            "evidence_coverage": snap["score"]["evidence_coverage"],
            "aggregate_risk_tier": snap["risk"]["aggregate_risk_tier"],
            "itemized_deductions": snap["score"]["itemized_deductions"],
            "methodology_version": snap["score"]["methodology_version"],
        },
        compliance_counts={
            "pass": snap["compliance"]["pass_count"],
            "fail": snap["compliance"]["fail_count"],
            "unknown": snap["compliance"]["unknown_count"],
            "not_applicable": snap["compliance"]["not_applicable_count"],
        },
        findings_summary={
            "total": snap["findings"]["total_findings"],
            "critical": snap["findings"]["critical_count"],
            "high": snap["findings"]["high_count"],
            "medium": snap["findings"]["medium_count"],
            "low": snap["findings"]["low_count"],
            "top_findings": snap["findings"]["findings"][:5],
        },
        traffic_summary=snap["traffic"],
        fingerprintability=snap["metadata_fingerprintability"],
        protocol_summary=snap["protocol"],
    )


@router.get(
    "/{analysis_id}/traffic",
    response_model=TrafficSummaryResponseDTO,
    summary="Retrieve encrypted flows with Stage 7 predictions and explainability",
)
async def get_analysis_traffic(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> TrafficSummaryResponseDTO:
    """Retrieve encrypted ESP flows enriched with calibrated classification, entropy, and SHAP attributions."""
    stmt_flows = select(ESPFlow).where(ESPFlow.analysis_id == analysis_id).order_by(ESPFlow.start_time)
    flows = (await db.execute(stmt_flows)).scalars().all()

    # Query current MLInferenceRun deterministically
    from app.db.models.ml import MLInferenceRun
    stmt_run = select(MLInferenceRun).where(
        MLInferenceRun.analysis_id == analysis_id,
        MLInferenceRun.is_current.is_(True),
    )
    current_run = (await db.execute(stmt_run)).scalars().first()

    flow_ids = [f.id for f in flows]
    if current_run and flow_ids:
        stmt_ml = select(FlowClassification).where(
            FlowClassification.run_id == current_run.id,
            FlowClassification.flow_id.in_(flow_ids),
        )
        ml_records = (await db.execute(stmt_ml)).scalars().all()
    elif flow_ids:
        stmt_ml = select(FlowClassification).where(FlowClassification.flow_id.in_(flow_ids))
        ml_records = (await db.execute(stmt_ml)).scalars().all()
    else:
        ml_records = []

    ml_map = {m.flow_id: m for m in ml_records}

    flow_items = []
    classes_detected: set[str] = set()
    ood_count = 0
    anomaly_count = 0

    for f in flows:
        ml = ml_map.get(f.id)
        input_status = ml.input_status if ml else None
        known_class = ml.known_class if ml else None
        final_class = ml.final_class if ml else None
        supervised_hyp = ml.supervised_hypothesis if ml else None
        accepted_pred = ml.accepted_prediction if ml else None
        calib_conf = ml.calibrated_confidence if ml else None
        calib_status = ml.calibration_status if ml else None
        norm_entropy = ml.normalized_entropy if ml else None
        ood_status = ml.ood_status if ml else None
        anomaly_status = ml.behavioral_anomaly_status if ml else None
        anomaly_score = ml.anomaly_score if ml else None
        is_deg = ml.is_degraded if ml else None
        deg_reason = ml.degraded_reason if ml else None

        if final_class and final_class not in ("UNAVAILABLE", "UNKNOWN_UNSEEN", "OUT_OF_DISTRIBUTION"):
            classes_detected.add(final_class)
        if ood_status and ood_status not in ("KNOWN_ACCEPTED", "UNAVAILABLE"):
            ood_count += 1
        if anomaly_status in ("STATISTICAL_BEHAVIORAL_ANOMALY", "ANOMALOUS_BEHAVIOR"):
            anomaly_count += 1

        top_shap = None
        if ml and ml.transparency_data and "shap_values" in ml.transparency_data:
            shap_dict = ml.transparency_data["shap_values"]
            if isinstance(shap_dict, dict):
                top_shap = sorted(
                    [{"feature": k, "importance": float(v)} for k, v in shap_dict.items()],
                    key=lambda x: abs(x["importance"]),
                    reverse=True,
                )[:6]

        flow_items.append(
            TrafficFlowItemDTO(
                flow_id=f.id,
                spi=f.spi,
                reverse_spi=f.reverse_spi,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                duration_seconds=f.duration_seconds,
                packet_count=f.packet_count,
                byte_count=f.byte_count,
                association_state=f.association_state,
                input_status=input_status,
                supervised_hypothesis=supervised_hyp,
                known_class=known_class,
                final_class=final_class,
                accepted_prediction=accepted_pred,
                calibrated_confidence=calib_conf,
                calibration_status=calib_status,
                normalized_entropy=norm_entropy,
                ood_status=ood_status,
                behavioral_anomaly_status=anomaly_status,
                anomaly_score=anomaly_score,
                is_degraded=is_deg,
                degraded_reason=deg_reason,
                top_shap_features=top_shap,
            )
        )

    ml_run_status = current_run.status if current_run else ("NO_FLOWS" if not flows else "NOT_CONFIGURED")

    return TrafficSummaryResponseDTO(
        analysis_id=analysis_id,
        total_flows=len(flows),
        classified_flows=current_run.classified_count if current_run else len(ml_records),
        classes_detected=sorted(classes_detected),
        ood_count=ood_count,
        anomaly_count=anomaly_count,
        ml_run_status=ml_run_status,
        model_version=current_run.bundle_version if current_run else None,
        model_bundle_id=current_run.bundle_id if current_run else None,
        flows=flow_items,
    )


@router.post(
    "/{analysis_id}/re-analyze",
    response_model=ReplayExecutionResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic forensic re-analysis over an immutable capture",
)
async def re_analyze(
    analysis_id: uuid.UUID,
    req: ForensicReanalysisRequestDTO | None = None,
    db: AsyncSession = Depends(get_db_session),
) -> ReplayExecutionResponseDTO:
    """Reruns forensic analysis on the exact same verified capture artifact, creating an immutable child run."""
    from fastapi import HTTPException
    from app.replay.models import CaptureIntegrityError
    from app.replay.service import ReplayService

    service = ReplayService(db)
    try:
        child, comparison = await service.execute_forensic_reanalysis(analysis_id, req)
    except CaptureIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    return ReplayExecutionResponseDTO(
        child_analysis_id=child.id,
        parent_analysis_id=child.parent_analysis_id or analysis_id,
        replay_mode=child.replay_mode or "FORENSIC_REANALYSIS",
        status=child.status,
        artifact_integrity=comparison.artifact_integrity,
        comparison_status=comparison.comparison_status,
        summary=comparison.summary,
        differences=comparison.differences,
        metrics=comparison.metrics,
        created_at=comparison.created_at,
    )


@router.get(
    "/{analysis_id}/replay-lineage",
    response_model=ReplayLineageDTO,
    summary="Retrieve replay provenance lineage and integrity status",
)
async def get_replay_lineage(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ReplayLineageDTO:
    """Retrieve full parent/child replay lineage, capture SHA-256 integrity, and version pins."""
    from app.replay.service import ReplayService

    service = ReplayService(db)
    return await service.get_replay_lineage(analysis_id)

