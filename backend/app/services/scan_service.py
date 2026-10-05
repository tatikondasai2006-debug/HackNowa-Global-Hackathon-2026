"""Scan service for managing scan jobs and executing scans."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import logging

from app.core.exceptions import DomainValidationError, ScanNotFoundError
from app.models.scan import (
    ScanJob, ScanResult, Finding, Report, AuditLog,
    ScanStatus, Severity
)
from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.base import CheckStatus, ModuleResult
from app.scanner.scoring import ScoreBreakdown, get_risk_label
from app.services.domain_validation import domain_validator
from app.services.scoring_service import breakdown_to_dict, score_from_scan_results
from app.services.recommendation_service import RecommendationService

logger = logging.getLogger(__name__)

# Failure reasons safe to persist and return to the client. Anything not on this
# allowlist is replaced with a generic message so internal exception text, file
# paths, connection strings or library internals never reach the database.
_PUBLIC_SCAN_ERRORS = (DomainValidationError,)


def public_scan_error(exc: BaseException) -> str:
    """Map an exception to a client-safe failure reason for a scan job."""
    if isinstance(exc, _PUBLIC_SCAN_ERRORS):
        return str(getattr(exc, "detail", exc))
    return (
        "The scan could not be completed because of an internal error. "
        "The failure has been logged for investigation."
    )


class ScanService:
    """Business logic for scan operations."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.orchestrator = ScanOrchestrator()

    async def create_scan(
        self,
        user_id: int,
        target_domain: str,
        scan_options: Optional[Dict] = None,
        authorization_confirmed: bool = False,
    ) -> ScanJob:
        """Create a new scan job after domain validation.

        The caller is responsible for rejecting requests that lack a valid
        authorization attestation; this method records the attestation in the
        audit trail.
        """
        domain = domain_validator.validate(target_domain, resolve_dns=False)

        scan_job = ScanJob(
            user_id=user_id,
            target_domain=domain,
            target_url=f"https://{domain}",
            status=ScanStatus.PENDING.value,
            total_checks=self.orchestrator.get_total_checks(),
        )
        self.db.add(scan_job)
        await self.db.flush()
        await self.db.refresh(scan_job)

        # Audit log
        audit = AuditLog(
            user_id=user_id,
            action="scan.created",
            resource_type="scan_job",
            resource_id=scan_job.id,
            details={
                "target_domain": domain,
                "authorization_confirmed": bool(authorization_confirmed),
                "authorization_attested_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        self.db.add(audit)
        await self.db.flush()

        if authorization_confirmed:
            attestation = AuditLog(
                user_id=user_id,
                action="scan.authorization_attested",
                resource_type="scan_job",
                resource_id=scan_job.id,
                details={
                    "target_domain": domain,
                    "statement": (
                        "User confirmed they own this target or have explicit "
                        "written permission to assess it."
                    ),
                },
            )
            self.db.add(attestation)
            await self.db.flush()

        logger.info(f"Scan job created: id={scan_job.id}, domain={domain}")
        return scan_job

    async def execute_scan(
        self, scan_job_id: int, scan_options: Optional[Dict] = None
    ) -> ScanJob:
        """Execute the scan for a given job ID.

        This runs the actual scanning, saves results, calculates score,
        and generates findings.
        """
        # Get scan job
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        scan_job = result.scalar_one_or_none()
        if not scan_job:
            raise ValueError(f"Scan job {scan_job_id} not found")

        # Update status to running. Commit so the transition is durable and the
        # polling clients observe `running` instead of a job frozen at `pending`.
        scan_job.status = ScanStatus.RUNNING.value
        scan_job.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        try:
            # Resolve once, validate, and pin. The orchestrator is handed these
            # exact addresses so the outbound connections cannot be redirected
            # to a different (e.g. private) address between validation and
            # connect time (DNS rebinding).
            target_domain, pinned_ips = domain_validator.validate_and_resolve(
                scan_job.target_domain
            )
            completed = 0

            async def progress_callback(module_name: str, status: str):
                nonlocal completed
                scan_job.current_module = module_name
                if status in ("completed", "error"):
                    completed += 1
                    scan_job.completed_checks = completed
                # Commit progress so the frontend progress bar advances live.
                await self.db.commit()

            # Run the scan using the modules selected on the New Scan form
            module_results, score = await self.orchestrator.run_scan(
                target_domain,
                scan_options=scan_options,
                progress_callback=progress_callback,
                pinned_ips=pinned_ips,
            )

            # Save results to database
            await self._save_results(scan_job, module_results, score)

            # Update scan job status
            scan_job.status = ScanStatus.COMPLETED.value
            scan_job.completed_at = datetime.now(timezone.utc)
            scan_job.current_module = None
            scan_job.overall_score = score.percentage
            scan_job.risk_level = score.risk_level
            scan_job.score_breakdown = breakdown_to_dict(score)
            scan_job.total_checks = sum(
                len(mr.checks) for mr in module_results
            )
            scan_job.completed_checks = scan_job.total_checks

            # Count results
            all_checks = [c for mr in module_results for c in mr.checks]
            scan_job.passed_count = sum(
                1 for c in all_checks if c.status == CheckStatus.PASSED
            )
            scan_job.warning_count = sum(
                1 for c in all_checks if c.status == CheckStatus.WARNING
            )
            scan_job.failed_count = sum(
                1 for c in all_checks if c.status == CheckStatus.FAILED
            )
            failed_modules = sum(
                1 for mr in module_results if mr.error
            )
            scan_job.failed_checks = failed_modules

            await self.db.flush()
            await self.db.refresh(scan_job)

            try:
                findings = await self.get_scan_findings(scan_job.id)
                rec_service = RecommendationService(self.db)
                await rec_service.explain_scan_with_ai(scan_job, findings)
            except Exception:
                logger.warning(
                    "AI explanation skipped for scan_id=%s",
                    scan_job.id,
                    extra={"event": "gemini_skipped"},
                )

            logger.info(
                f"Scan completed: id={scan_job.id}, score={score.percentage}, "
                f"risk={score.risk_level}"
            )

        except Exception as e:
            scan_job.status = ScanStatus.FAILED.value
            scan_job.error_message = public_scan_error(e)
            scan_job.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            logger.error(f"Scan failed: id={scan_job.id}, error={e}", exc_info=True)
            raise

        return scan_job

    async def _save_results(
        self, scan_job: ScanJob, module_results: List[ModuleResult], score: ScoreBreakdown
    ):
        """Save scan results and findings to the database."""
        for module_result in module_results:
            for check in module_result.checks:
                scan_result = ScanResult(
                    scan_job_id=scan_job.id,
                    module_name=check.module_name,
                    check_name=check.check_name,
                    status=check.status.value,
                    severity=check.severity.value if check.severity else None,
                    title=check.title,
                    description=check.description,
                    evidence=check.evidence,
                    technical_details=check.technical_details,
                    score_impact=check.score_impact,
                    max_score=check.max_score,
                )
                self.db.add(scan_result)
                await self.db.flush()

                # Create finding for failed/warning checks
                if check.status in (CheckStatus.FAILED, CheckStatus.WARNING):
                    finding = Finding(
                        scan_job_id=scan_job.id,
                        scan_result_id=scan_result.id,
                        title=check.title,
                        description=check.description or f"Issue detected: {check.title}",
                        severity=check.severity.value if check.severity else "info",
                        category=module_result.display_name,
                        evidence=check.evidence,
                        technical_details=check.technical_details,
                        recommendation=check.recommendation,
                        remediation_steps=check.remediation_steps,
                        reference_urls=check.reference_urls,
                    )
                    self.db.add(finding)

        await self.db.flush()

    async def get_scan(self, scan_id: int, user_id: int) -> Optional[ScanJob]:
        """Get a scan job by ID, ensuring it belongs to the user."""
        result = await self.db.execute(
            select(ScanJob).where(
                ScanJob.id == scan_id,
                ScanJob.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    async def require_scan(self, scan_id: int, user_id: int) -> ScanJob:
        scan = await self.get_scan(scan_id, user_id)
        if not scan:
            raise ScanNotFoundError("Scan not found")
        return scan

    async def get_scan_results(self, scan_id: int) -> List[ScanResult]:
        """Get all scan results for a scan job."""
        result = await self.db.execute(
            select(ScanResult)
            .where(ScanResult.scan_job_id == scan_id)
            .order_by(ScanResult.id)
        )
        return list(result.scalars().all())

    async def get_scan_findings(self, scan_id: int) -> List[Finding]:
        """Get all findings for a scan job."""
        result = await self.db.execute(
            select(Finding)
            .where(Finding.scan_job_id == scan_id)
            .order_by(Finding.id)
        )
        return list(result.scalars().all())

    async def get_score_breakdown(
        self, scan: ScanJob, results: List[ScanResult]
    ) -> Dict[str, Any]:
        if scan.score_breakdown:
            return scan.score_breakdown
        if not results:
            return {}
        return breakdown_to_dict(score_from_scan_results(results))

    async def get_user_scans(
        self,
        user_id: int,
        page: int = 1,
        page_size: int = 20,
        domain: Optional[str] = None,
        status: Optional[str] = None,
    ) -> tuple:
        """Get paginated scan history, optionally filtered by domain and status."""
        filters = [ScanJob.user_id == user_id]
        if domain:
            filters.append(
                ScanJob.target_domain == domain_validator.sanitize(domain)
            )
        if status:
            filters.append(ScanJob.status == status)

        count_result = await self.db.execute(
            select(func.count(ScanJob.id)).where(*filters)
        )
        total = count_result.scalar() or 0

        offset = (page - 1) * page_size
        result = await self.db.execute(
            select(ScanJob)
            .where(*filters)
            .order_by(desc(ScanJob.created_at))
            .offset(offset)
            .limit(page_size)
        )
        scans = list(result.scalars().all())
        return scans, total

    async def get_domain_history(
        self, user_id: int, domain: str, limit: int = 20
    ) -> List[ScanJob]:
        """Return chronological scan history for one domain (posture trend)."""
        normalized = domain_validator.validate(domain, resolve_dns=False)
        result = await self.db.execute(
            select(ScanJob)
            .where(
                ScanJob.user_id == user_id,
                ScanJob.target_domain == normalized,
            )
            .order_by(desc(ScanJob.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def delete_scan(self, scan_id: int, user_id: int) -> bool:
        """Delete a scan job and all related data."""
        scan = await self.get_scan(scan_id, user_id)
        if not scan:
            return False

        # Delete findings
        findings = await self.db.execute(
            select(Finding).where(Finding.scan_job_id == scan_id)
        )
        for f in findings.scalars().all():
            await self.db.delete(f)

        # Delete results
        results = await self.db.execute(
            select(ScanResult).where(ScanResult.scan_job_id == scan_id)
        )
        for r in results.scalars().all():
            await self.db.delete(r)

        # Delete reports
        reports = await self.db.execute(
            select(Report).where(Report.scan_job_id == scan_id)
        )
        for rpt in reports.scalars().all():
            await self.db.delete(rpt)

        # Delete scan job
        await self.db.delete(scan)
        await self.db.flush()

        logger.info(f"Scan deleted: id={scan_id}")
        return True

    async def get_dashboard_stats(self, user_id: int) -> Dict[str, Any]:
        """Get dashboard statistics for a user."""
        # Total scans
        total_result = await self.db.execute(
            select(func.count(ScanJob.id)).where(ScanJob.user_id == user_id)
        )
        total_scans = total_result.scalar() or 0

        # Completed scans
        completed_result = await self.db.execute(
            select(func.count(ScanJob.id)).where(
                ScanJob.user_id == user_id,
                ScanJob.status == ScanStatus.COMPLETED.value,
            )
        )
        completed_scans = completed_result.scalar() or 0

        # Average score
        avg_result = await self.db.execute(
            select(func.avg(ScanJob.overall_score)).where(
                ScanJob.user_id == user_id,
                ScanJob.status == ScanStatus.COMPLETED.value,
                ScanJob.overall_score.isnot(None),
            )
        )
        average_score = avg_result.scalar()
        if average_score is not None:
            average_score = round(average_score, 1)

        # Unique domains
        domains_result = await self.db.execute(
            select(func.count(func.distinct(ScanJob.target_domain))).where(
                ScanJob.user_id == user_id
            )
        )
        domains_scanned = domains_result.scalar() or 0

        # Finding severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for severity in severity_counts:
            sev_result = await self.db.execute(
                select(func.count(Finding.id))
                .join(ScanJob, Finding.scan_job_id == ScanJob.id)
                .where(
                    ScanJob.user_id == user_id,
                    Finding.severity == severity,
                )
            )
            severity_counts[severity] = sev_result.scalar() or 0

        # Recent scans (last 5)
        recent_result = await self.db.execute(
            select(ScanJob)
            .where(ScanJob.user_id == user_id)
            .order_by(desc(ScanJob.created_at))
            .limit(5)
        )
        recent_scans = list(recent_result.scalars().all())

        # Score trend (last 10 completed scans)
        trend_result = await self.db.execute(
            select(ScanJob)
            .where(
                ScanJob.user_id == user_id,
                ScanJob.status == ScanStatus.COMPLETED.value,
                ScanJob.overall_score.isnot(None),
            )
            .order_by(desc(ScanJob.completed_at))
            .limit(10)
        )
        trend_scans = list(trend_result.scalars().all())
        score_trend = [
            {
                "date": s.completed_at.isoformat() if s.completed_at else None,
                "score": s.overall_score,
                "domain": s.target_domain,
            }
            for s in reversed(trend_scans)
        ]

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "average_score": average_score,
            "domains_scanned": domains_scanned,
            "critical_findings": severity_counts["critical"],
            "high_findings": severity_counts["high"],
            "medium_findings": severity_counts["medium"],
            "low_findings": severity_counts["low"],
            "recent_scans": recent_scans,
            "score_trend": score_trend,
        }
