"""Service layer managing Greenbone vulnerability report upload, preview, idempotent import, and evidence retrieval."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.discovery import DiscoveredHost
from app.db.models.vulnerability import (
    VulnerabilityReport,
    VulnerabilityReportFinding,
)
from app.services.storage.base import StorageProvider
from app.vulnerabilities.correlator import (
    AssetLinkState,
    CorrelationStatus,
    VulnerabilityCorrelator,
)
from app.vulnerabilities.parser import (
    GreenboneParseError,
    ParsedGreenboneReport,
    parse_greenbone_xml,
)

logger = logging.getLogger(__name__)


class AuthorizationValidationError(PermissionError):
    """Raised when operator authorization attestation or scope is missing/invalid."""
    pass


class VulnerabilityReportNotFoundError(KeyError):
    """Raised when the specified vulnerability report is not found."""
    pass


class VulnerabilityFindingNotFoundError(KeyError):
    """Raised when the specified finding is not found."""
    pass


class VulnerabilityReportService:
    """Orchestrates secure parsing, conservative correlation, and immutable storage."""

    @classmethod
    async def preview_report(
        cls,
        raw_bytes: bytes,
        *,
        authorized_targets: list[str] | None = None,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Preflight/preview parsed report content and asset mapping before accepting import."""
        if not raw_bytes:
            raise GreenboneParseError("Upload payload is empty")

        parsed = parse_greenbone_xml(raw_bytes)

        # Query existing DiscoveredHosts for candidate mapping
        res = await db.execute(
            select(DiscoveredHost).where(DiscoveredHost.ip_address.in_(parsed.unique_hosts))
        )
        discovered_hosts: Sequence[DiscoveredHost] = res.scalars().all()

        host_map, correlated_findings = VulnerabilityCorrelator.correlate_report(
            parsed_report=parsed,
            authorized_scope_targets=authorized_targets or [],
            discovered_hosts=discovered_hosts,
        )

        # Compute summary metrics
        mapped_count = sum(1 for h in host_map.values() if h.asset_link_state == AssetLinkState.MAPPED_EXACT_IP)
        ambiguous_count = sum(1 for h in host_map.values() if h.asset_link_state == AssetLinkState.AMBIGUOUS_MULTIPLE_MATCHES)
        unlinked_count = sum(1 for h in host_map.values() if h.asset_link_state == AssetLinkState.UNLINKED_NO_DISCOVERY_RECORD)
        out_of_scope_count = sum(1 for h in host_map.values() if h.asset_link_state == AssetLinkState.OUT_OF_SCOPE)

        severity_breakdown: dict[str, int] = {}
        for f in parsed.findings:
            sev = f.source_severity
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        correlation_breakdown: dict[str, int] = {}
        for cf in correlated_findings:
            stat = cf.correlation_status
            correlation_breakdown[stat] = correlation_breakdown.get(stat, 0) + 1

        return {
            "report_id": parsed.metadata.report_id,
            "format_id": parsed.metadata.format_id,
            "format_version": parsed.metadata.format_version,
            "task_id": parsed.metadata.task_id,
            "task_name": parsed.metadata.task_name,
            "scan_config": parsed.metadata.scan_config,
            "scanner_name": parsed.metadata.scanner_name,
            "scanner_version": parsed.metadata.scanner_version,
            "feed_status": parsed.metadata.feed_status,
            "feed_type": parsed.metadata.feed_type,
            "scan_started_at": parsed.metadata.scan_started_at.isoformat() if parsed.metadata.scan_started_at else None,
            "scan_ended_at": parsed.metadata.scan_ended_at.isoformat() if parsed.metadata.scan_ended_at else None,
            "raw_sha256": parsed.raw_sha256,
            "raw_bytes_count": parsed.raw_bytes_count,
            "total_findings_count": parsed.findings_count,
            "unique_hosts_count": len(parsed.unique_hosts),
            "host_mapping_summary": {
                "mapped_exact_ip": mapped_count,
                "ambiguous_multiple_matches": ambiguous_count,
                "unlinked_no_discovery_record": unlinked_count,
                "out_of_scope": out_of_scope_count,
                "total_unique_hosts": len(parsed.unique_hosts),
            },
            "host_mapping_details": [
                {
                    "host_ip": h.host_ip,
                    "asset_link_state": h.asset_link_state,
                    "asset_link_rationale": h.asset_link_rationale,
                    "mapped_host_id": str(h.mapped_host_id) if h.mapped_host_id else None,
                }
                for h in host_map.values()
            ],
            "severity_breakdown": severity_breakdown,
            "correlation_breakdown": correlation_breakdown,
            "findings_sample": [
                {
                    "source_result_id": cf.finding.source_result_id,
                    "host_ip": cf.finding.host_ip,
                    "port": cf.finding.port,
                    "protocol": cf.finding.protocol,
                    "nvt_oid": cf.finding.nvt.oid,
                    "nvt_name": cf.finding.nvt.name,
                    "source_severity": cf.finding.source_severity,
                    "cvss_base_score": cf.finding.nvt.cvss_base,
                    "qod_value": cf.finding.qod_value,
                    "qod_type": cf.finding.qod_type,
                    "cves": cf.finding.nvt.cves,
                    "cpes": cf.finding.nvt.cpes,
                    "asset_link_state": cf.asset_link_state,
                    "correlation_status": cf.correlation_status,
                    "cve_applicability_state": cf.cve_applicability_state,
                    "correlation_rationale": cf.correlation_rationale,
                }
                for cf in correlated_findings[:15]
            ],
        }

    @classmethod
    async def import_report(
        cls,
        raw_bytes: bytes,
        *,
        operator_id: str,
        authorization_reference: str,
        operator_attestation: str,
        engagement_scope: str,
        authorized_targets: list[str] | None = None,
        db: AsyncSession,
        storage: StorageProvider,
    ) -> VulnerabilityReport:
        """Validate operator attestation, parse, persist raw bytes immutably, and record findings."""
        # 1. Attestation validation
        if not operator_id or not operator_id.strip():
            raise AuthorizationValidationError("operator_id is required")
        if not authorization_reference or not authorization_reference.strip():
            raise AuthorizationValidationError("authorization_reference is required")
        if not operator_attestation or len(operator_attestation.strip()) < 10:
            raise AuthorizationValidationError(
                "operator_attestation must be at least 10 characters confirming authorized testing scope"
            )
        if not engagement_scope or not engagement_scope.strip():
            raise AuthorizationValidationError("engagement_scope is required")

        # 2. Compute exact artifact digest
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # 3. Check Idempotency / Duplicate Report
        existing_report_res = await db.execute(
            select(VulnerabilityReport).where(
                VulnerabilityReport.raw_artifact_sha256 == raw_sha256,
                VulnerabilityReport.engagement_scope == engagement_scope.strip(),
            )
        )
        existing_report = existing_report_res.scalar_one_or_none()
        if existing_report is not None:
            logger.info(
                f"Duplicate vulnerability report detected (ID {existing_report.id}, SHA256 {raw_sha256}). "
                "Returning existing report without duplicate findings."
            )
            # Create a duplicate pointer record or return existing with status DUPLICATE
            return existing_report

        # 4. Parse XML defensively
        parsed = parse_greenbone_xml(raw_bytes)

        # 5. Persist raw bytes immutably in storage provider
        rel_storage_path = f"reports/greenbone/{raw_sha256}.xml"
        try:
            storage.save_file(rel_storage_path, raw_bytes)
        except Exception as e:
            logger.warning(f"Storage provider failed to persist report artifact: {e}")
            rel_storage_path = None

        # 6. Query DiscoveredHosts for candidate mapping
        discovered_hosts_res = await db.execute(
            select(DiscoveredHost).where(DiscoveredHost.ip_address.in_(parsed.unique_hosts))
        )
        discovered_hosts: Sequence[DiscoveredHost] = discovered_hosts_res.scalars().all()

        host_map, correlated_findings = VulnerabilityCorrelator.correlate_report(
            parsed_report=parsed,
            authorized_scope_targets=authorized_targets or [],
            discovered_hosts=discovered_hosts,
        )

        has_warnings = any(
            h.asset_link_state in (AssetLinkState.AMBIGUOUS_MULTIPLE_MATCHES, AssetLinkState.OUT_OF_SCOPE)
            for h in host_map.values()
        )
        final_status = "COMPLETED_WITH_WARNINGS" if has_warnings else "COMPLETED"

        # 7. Create VulnerabilityReport DB entity
        report_entity = VulnerabilityReport(
            id=uuid.uuid4(),
            report_source_id=parsed.metadata.report_id,
            source_system="GREENBONE_OPENVAS",
            report_format="GREENBONE_REPORT_XML",
            report_format_version=parsed.metadata.format_version,
            task_id=parsed.metadata.task_id,
            task_name=parsed.metadata.task_name,
            scan_config=parsed.metadata.scan_config,
            port_list=parsed.metadata.port_list,
            scanner_name=parsed.metadata.scanner_name,
            scanner_version=parsed.metadata.scanner_version,
            feed_type=parsed.metadata.feed_type,
            feed_version=parsed.metadata.feed_version,
            feed_status=parsed.metadata.feed_status,
            engagement_scope=engagement_scope.strip(),
            authorization_reference=authorization_reference.strip(),
            operator_id=operator_id.strip(),
            operator_attestation=operator_attestation.strip(),
            is_local_attestation=True,
            status=final_status,
            failure_reason=None,
            raw_artifact_sha256=raw_sha256,
            raw_artifact_bytes=parsed.raw_bytes_count,
            storage_path=rel_storage_path,
            duplicate_of_id=None,
            scan_started_at=parsed.metadata.scan_started_at,
            scan_ended_at=parsed.metadata.scan_ended_at,
            imported_at=datetime.now(timezone.utc),
            hosts_count=len(parsed.unique_hosts),
            results_count=parsed.findings_count,
        )
        db.add(report_entity)
        await db.flush()

        # 8. Create VulnerabilityReportFinding DB entities
        for cf in correlated_findings:
            f = cf.finding
            finding_entity = VulnerabilityReportFinding(
                id=uuid.uuid4(),
                report_id=report_entity.id,
                source_result_id=f.source_result_id,
                host_ip=f.host_ip,
                host_name=f.host_name,
                ip_version=f.ip_version,
                port=f.port,
                protocol=f.protocol,
                service_name=f.service_name,
                nvt_oid=f.nvt.oid,
                nvt_name=f.nvt.name,
                nvt_family=f.nvt.family,
                cvss_version=f.nvt.cvss_version,
                cvss_base_score=f.nvt.cvss_base,
                cvss_vector=f.nvt.cvss_vector,
                source_severity=f.source_severity,
                qod_value=f.qod_value,
                qod_type=f.qod_type,
                detection_method=f.detection_method,
                reported_cves=f.nvt.cves,
                reported_cpes=f.nvt.cpes,
                source_product_claim=f.source_product_claim,
                source_version_claim=f.source_version_claim,
                description=f.description,
                summary=f.summary,
                solution=f.solution,
                solution_type=f.solution_type,
                source_timestamp=f.source_timestamp,
                status="SCANNER_REPORTED",
                mapped_discovered_host_id=cf.mapped_host_id,
                asset_link_state=cf.asset_link_state,
                asset_link_rationale=cf.asset_link_rationale,
                correlation_status=cf.correlation_status,
                correlation_method=cf.correlation_method,
                cve_applicability_state=cf.cve_applicability_state,
                correlation_rationale=cf.correlation_rationale,
                created_at=datetime.now(timezone.utc),
            )
            db.add(finding_entity)

        await db.commit()
        await db.refresh(report_entity)
        return report_entity

    @classmethod
    async def list_reports(
        cls,
        db: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 50,
        status: str | None = None,
        operator_id: str | None = None,
    ) -> tuple[Sequence[VulnerabilityReport], int]:
        """List imported vulnerability reports with pagination and count."""
        stmt = select(VulnerabilityReport)
        if status:
            stmt = stmt.where(VulnerabilityReport.status == status)
        if operator_id:
            stmt = stmt.where(VulnerabilityReport.operator_id == operator_id)

        count_stmt = select(func.count(VulnerabilityReport.id))
        if status:
            count_stmt = count_stmt.where(VulnerabilityReport.status == status)
        if operator_id:
            count_stmt = count_stmt.where(VulnerabilityReport.operator_id == operator_id)

        total_res = await db.execute(count_stmt)
        total = total_res.scalar_one()

        stmt = stmt.order_by(desc(VulnerabilityReport.imported_at)).offset(skip).limit(limit)
        res = await db.execute(stmt)
        reports = res.scalars().all()
        return reports, total

    @classmethod
    async def get_report(
        cls,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> VulnerabilityReport:
        """Fetch report by ID or raise NotFoundError."""
        res = await db.execute(
            select(VulnerabilityReport)
            .where(VulnerabilityReport.id == report_id)
            .options(selectinload(VulnerabilityReport.findings))
        )
        report = res.scalar_one_or_none()
        if report is None:
            raise VulnerabilityReportNotFoundError(f"Report {report_id} not found")
        return report

    @classmethod
    async def list_findings(
        cls,
        db: AsyncSession,
        *,
        report_id: uuid.UUID | None = None,
        host_ip: str | None = None,
        severity: str | None = None,
        correlation_status: str | None = None,
        asset_link_state: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[VulnerabilityReportFinding], int]:
        """List findings across reports or for a specific report."""
        stmt = select(VulnerabilityReportFinding)
        if report_id:
            stmt = stmt.where(VulnerabilityReportFinding.report_id == report_id)
        if host_ip:
            stmt = stmt.where(VulnerabilityReportFinding.host_ip == host_ip)
        if severity:
            stmt = stmt.where(VulnerabilityReportFinding.source_severity == severity)
        if correlation_status:
            stmt = stmt.where(VulnerabilityReportFinding.correlation_status == correlation_status)
        if asset_link_state:
            stmt = stmt.where(VulnerabilityReportFinding.asset_link_state == asset_link_state)

        count_stmt = select(func.count(VulnerabilityReportFinding.id))
        if report_id:
            count_stmt = count_stmt.where(VulnerabilityReportFinding.report_id == report_id)
        if host_ip:
            count_stmt = count_stmt.where(VulnerabilityReportFinding.host_ip == host_ip)
        if severity:
            count_stmt = count_stmt.where(VulnerabilityReportFinding.source_severity == severity)
        if correlation_status:
            count_stmt = count_stmt.where(VulnerabilityReportFinding.correlation_status == correlation_status)
        if asset_link_state:
            count_stmt = count_stmt.where(VulnerabilityReportFinding.asset_link_state == asset_link_state)

        total_res = await db.execute(count_stmt)
        total = total_res.scalar_one()

        stmt = stmt.order_by(desc(VulnerabilityReportFinding.created_at)).offset(skip).limit(limit)
        res = await db.execute(stmt)
        findings = res.scalars().all()
        return findings, total

    @classmethod
    async def get_finding(
        cls,
        db: AsyncSession,
        finding_id: uuid.UUID,
    ) -> VulnerabilityReportFinding:
        """Fetch finding by ID or raise NotFoundError."""
        res = await db.execute(
            select(VulnerabilityReportFinding)
            .where(VulnerabilityReportFinding.id == finding_id)
            .options(selectinload(VulnerabilityReportFinding.report))
        )
        finding = res.scalar_one_or_none()
        if finding is None:
            raise VulnerabilityFindingNotFoundError(f"Finding {finding_id} not found")
        return finding
