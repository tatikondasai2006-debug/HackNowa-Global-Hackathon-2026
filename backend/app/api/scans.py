"""Scan Management and Execution API Endpoints."""

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.core.config import settings
from app.core.exceptions import AuthorizationNotConfirmedError
from app.db.session import get_db, async_session_factory
from app.models.scan import ScanJob, ScanStatus
from app.schemas.scan import (
    AIExplanationResponse,
    DomainValidateRequest,
    DomainValidateResponse,
    RecommendationItem,
    RecommendationResponse,
    ResourceId,
    ScanCompareResponse,
    ScanRequest,
    ScanJobResponse,
    ScanJobDetailResponse,
    ScanListResponse,
    ScanScoreSummary,
    ScanStatusResponse,
    ScanResultResponse,
    FindingResponse,
)
from app.services.scan_service import ScanService, public_scan_error
from app.services.scan_limits import enforce_scan_admission, scan_admission_guard
from app.services.recommendation_service import RecommendationService
from app.services.history_service import HistoryService
from app.services.domain_validation import domain_validator
from app.core.security import get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["Scans"])


async def _mark_scan_failed(scan_job_id: int, reason: str) -> None:
    """Best-effort transition of a scan job to FAILED using its own session.

    Used for failures that happen outside `ScanService.execute_scan` (timeouts,
    cancelled workers, unexpected errors) so the job can never be left stranded
    in `pending` or `running`.
    """
    async with async_session_factory() as session:
        try:
            result = await session.execute(
                select(ScanJob).where(ScanJob.id == scan_job_id)
            )
            scan_job = result.scalar_one_or_none()
            if scan_job is None:
                logger.warning(
                    "Cannot mark scan failed, job not found: id=%s", scan_job_id
                )
                return
            if scan_job.status in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value):
                return
            scan_job.status = ScanStatus.FAILED.value
            scan_job.error_message = reason
            scan_job.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.warning("Scan job marked FAILED: id=%s reason=%s", scan_job_id, reason)
        except Exception:
            await session.rollback()
            logger.exception(
                "Failed to persist FAILED status for scan_job_id=%s", scan_job_id
            )


async def _run_scan_background(scan_job_id: int, scan_options: Optional[dict] = None):
    """Background task worker that executes the scan with its own DB session.

    The scan job is bounded by `SCAN_TIMEOUT_SECONDS`. Every exit path other
    than success marks the job FAILED so it is never left pending/running.
    """
    timeout = settings.SCAN_TIMEOUT_SECONDS
    try:
        async with async_session_factory() as session:
            service = ScanService(session)
            try:
                await asyncio.wait_for(
                    service.execute_scan(scan_job_id, scan_options=scan_options),
                    timeout=timeout,
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    except asyncio.TimeoutError:
        logger.error(
            "Background scan timed out after %ss: scan_job_id=%s", timeout, scan_job_id
        )
        await _mark_scan_failed(
            scan_job_id,
            f"The scan exceeded the maximum allowed duration of {timeout} seconds "
            "and was stopped.",
        )
    except asyncio.CancelledError:
        logger.error("Background scan cancelled: scan_job_id=%s", scan_job_id)
        await _mark_scan_failed(
            scan_job_id, "The scan was cancelled before it could complete."
        )
        raise
    except Exception as exc:
        logger.exception("Background scan failed for scan_job_id=%s", scan_job_id)
        await _mark_scan_failed(scan_job_id, public_scan_error(exc))


@router.post("/validate", response_model=DomainValidateResponse)
async def validate_domain(
    data: DomainValidateRequest,
    user_id: int = Depends(get_current_user_id),
):
    """Validate and sanitize a domain before starting a scan."""
    logger.info(
        "Domain pre-validation by user_id=%s domain=%s resolve_dns=%s",
        user_id,
        data.target_domain,
        data.resolve_dns,
    )
    payload = domain_validator.preflight(
        data.target_domain, resolve_dns=data.resolve_dns
    )
    return DomainValidateResponse(**payload)


@router.post("/", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    data: ScanRequest,
    background_tasks: BackgroundTasks,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Initiate a real security scan for the authorized target domain.

    The user must explicitly attest that they are authorized to assess the
    target. The attestation is enforced here (not in the UI) and recorded in
    the audit log.
    """
    if not data.authorization_confirmed:
        logger.warning(
            "Rejected scan request without authorization attestation: "
            "user_id=%s domain=%s",
            user_id,
            data.target_domain,
        )
        raise AuthorizationNotConfirmedError(
            "You must confirm that you own this target or have explicit written "
            "permission to assess it before a scan can be started."
        )

    # Server-side admission control. These are enforced here, not in the UI, so
    # a client cannot bypass them by calling the API directly.
    #
    # The guard has to cover the insert as well as the check: releasing it in
    # between would leave the check-then-act window open, which let concurrent
    # requests each observe a free slot and all proceed.
    async with scan_admission_guard():
        await enforce_scan_admission(db, user_id)

        service = ScanService(db)
        scan_job = await service.create_scan(
            user_id=user_id,
            target_domain=data.target_domain,
            scan_options=data.scan_options,
            authorization_confirmed=True,
        )
        # The background worker opens its own session, so the new scan row and
        # its audit record must be durable before the task is scheduled. Without
        # this commit the worker cannot observe the row and the job stays
        # `pending`.
        await db.commit()
    background_tasks.add_task(_run_scan_background, scan_job.id, data.scan_options)
    return ScanJobResponse.model_validate(scan_job)


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    domain: Optional[str] = Query(None, description="Filter history by domain"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by scan status"
    ),
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get paginated scan history for the current user."""
    service = ScanService(db)
    scans, total = await service.get_user_scans(
        user_id,
        page=page,
        page_size=page_size,
        domain=domain,
        status=status_filter,
    )
    return ScanListResponse(
        scans=[ScanJobResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        domain=domain,
        status=status_filter,
    )


@router.get("/history/{domain}", response_model=ScanListResponse)
async def domain_scan_history(
    domain: str,
    page_size: int = Query(20, ge=1, le=100),
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Chronological scan history for a single domain."""
    service = ScanService(db)
    scans = await service.get_domain_history(user_id, domain, limit=page_size)
    return ScanListResponse(
        scans=[ScanJobResponse.model_validate(s) for s in scans],
        total=len(scans),
        page=1,
        page_size=page_size,
        domain=domain,
    )


@router.get("/compare/{scan_id_a}/{scan_id_b}", response_model=ScanCompareResponse)
async def compare_scans(
    scan_id_a: ResourceId,
    scan_id_b: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Compare two scan history records for the same user."""
    service = HistoryService(db)
    payload = await service.compare_scans(user_id, scan_id_a, scan_id_b)
    return ScanCompareResponse(
        scan_a=ScanJobResponse.model_validate(payload["scan_a"]),
        scan_b=ScanJobResponse.model_validate(payload["scan_b"]),
        score_delta=payload["score_delta"],
        findings_added=payload["findings_added"],
        findings_resolved=payload["findings_resolved"],
        check_deltas=payload["check_deltas"],
    )


@router.get("/{scan_id}", response_model=ScanJobDetailResponse)
async def get_scan_detail(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Get full scan details including module results and findings."""
    service = ScanService(db)
    scan = await service.require_scan(scan_id, user_id)
    results = await service.get_scan_results(scan_id)
    findings = await service.get_scan_findings(scan_id)

    response_data = ScanJobResponse.model_validate(scan).model_dump()
    response_data["results"] = [ScanResultResponse.model_validate(r) for r in results]
    response_data["findings"] = [FindingResponse.model_validate(f) for f in findings]
    response_data["score_breakdown"] = await service.get_score_breakdown(scan, results)
    response_data["scan"] = ScanScoreSummary(
        score=scan.overall_score,
        risk_level=scan.risk_level,
    )

    rec_service = RecommendationService(db)
    rec_payload = {"recommendations": []}
    ai_payload = {
        "available": False,
        "summary": "AI explanation is temporarily unavailable.",
        "details": [],
    }
    if scan.status == "completed":
        rec_payload = await rec_service.build_recommendations(scan_id, user_id)
        ai_payload = await rec_service.explain_scan_with_ai(
            scan,
            findings,
            recommendations=rec_payload.get("recommendations"),
        )
    response_data["recommendations"] = [
        RecommendationItem(**item) for item in rec_payload.get("recommendations", [])
    ]
    response_data["ai_explanation"] = AIExplanationResponse(**ai_payload)
    if ai_payload.get("available") and ai_payload.get("summary"):
        response_data["ai_summary"] = ai_payload["summary"]
    return ScanJobDetailResponse(**response_data)


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Lightweight endpoint for frontend polling of scan progress."""
    service = ScanService(db)
    scan = await service.require_scan(scan_id, user_id)
    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        completed_checks=scan.completed_checks,
        total_checks=scan.total_checks,
        failed_checks=scan.failed_checks,
        current_module=scan.current_module,
        overall_score=scan.overall_score,
        risk_level=scan.risk_level,
    )


@router.get("/{scan_id}/recommendations", response_model=RecommendationResponse)
async def get_scan_recommendations(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Prioritized remediation recommendations for a scan."""
    service = RecommendationService(db)
    payload = await service.build_recommendations(scan_id, user_id)
    return RecommendationResponse(**payload)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and all associated records."""
    service = ScanService(db)
    deleted = await service.delete_scan(scan_id, user_id)
    if not deleted:
        from app.core.exceptions import ScanNotFoundError

        raise ScanNotFoundError("Scan not found")
    return None
