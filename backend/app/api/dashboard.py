"""Dashboard Statistics API Endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.scan import DashboardStats, ScanJobResponse
from app.services.scan_service import ScanService
from app.core.security import get_current_user_id

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve security dashboard summary, risk distribution, and historical score trend."""
    service = ScanService(db)
    stats = await service.get_dashboard_stats(user_id)
    return DashboardStats(
        total_scans=stats["total_scans"],
        completed_scans=stats["completed_scans"],
        average_score=stats["average_score"],
        domains_scanned=stats["domains_scanned"],
        critical_findings=stats["critical_findings"],
        high_findings=stats["high_findings"],
        medium_findings=stats["medium_findings"],
        low_findings=stats["low_findings"],
        recent_scans=[ScanJobResponse.model_validate(s) for s in stats["recent_scans"]],
        score_trend=stats["score_trend"],
    )
