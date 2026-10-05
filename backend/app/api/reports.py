"""Reports API Endpoints."""

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.scan import ReportListResponse, ReportResponse, ResourceId
from app.services.report_service import ReportService
from app.core.security import get_current_user_id

router = APIRouter(prefix="/reports", tags=["Reports"])

# Reports are generated HTML that embeds scan-derived text, so the browser is
# told not to sniff a different type out of the body and not to render it in a
# frame. These are response-level protections only: they add no CSP, because the
# frontend opens the report from a blob URL in a new tab and a policy applied to
# that document would also apply to the window that created it.
REPORT_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


@router.post("/generate/{scan_id}", response_model=ReportResponse)
async def generate_report(
    scan_id: ResourceId,
    fmt: str = Query("html", alias="format", pattern="^(html|pdf)$"),
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Generate a formal HTML or PDF security assessment report."""
    service = ReportService(db)
    report = await service.generate_report(scan_id, user_id, fmt=fmt)
    return ReportResponse.model_validate(report)


@router.get("/", response_model=ReportListResponse)
async def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """List generated reports for the current user."""
    service = ReportService(db)
    reports, total = await service.list_reports(user_id, page=page, page_size=page_size)
    return ReportListResponse(
        reports=[ReportResponse.model_validate(r) for r in reports],
        total=total,
    )


@router.get("/{report_id}/view", response_class=HTMLResponse)
async def view_report_html(
    report_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """View full rendered HTML report in the browser."""
    service = ReportService(db)
    report = await service.get_report(report_id, user_id)
    return HTMLResponse(content=report.content_html or "", headers=REPORT_SECURITY_HEADERS)


@router.get("/{report_id}/pdf")
async def download_report_pdf(
    report_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Download a stored or generated PDF for a persisted report."""
    service = ReportService(db)
    pdf_bytes = await service.pdf_bytes_for_report(report_id, user_id)
    filename = f"cybersentinel-report-{report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            **REPORT_SECURITY_HEADERS,
        },
    )


@router.get("/scan/{scan_id}/view", response_class=HTMLResponse)
async def view_scan_report_direct(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Directly generate and view HTML report for a scan on the fly."""
    service = ReportService(db)
    html_content = await service.html_for_scan(scan_id, user_id)
    return HTMLResponse(content=html_content, headers=REPORT_SECURITY_HEADERS)


@router.get("/scan/{scan_id}/pdf")
async def download_scan_pdf(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Download a PDF assessment report for a completed scan."""
    service = ReportService(db)
    pdf_bytes = await service.pdf_bytes_for_scan(scan_id, user_id)
    filename = f"cybersentinel-scan-{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            **REPORT_SECURITY_HEADERS,
        },
    )
