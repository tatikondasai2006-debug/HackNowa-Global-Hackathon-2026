"""AI Analysis and RAG Q&A Endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import get_current_user_id
from app.db.session import get_db
from app.schemas.scan import (
    AIExplainResponse,
    AIExplanationDetail,
    RAGQueryRequest,
    RAGQueryResponse,
    ResourceId,
)
from app.services.recommendation_service import RecommendationService
from app.services.scan_service import ScanService
from app.ai.rag_service import rag_service

router = APIRouter(prefix="/ai", tags=["AI & RAG"])


@router.post("/explain-scan/{scan_id}", response_model=AIExplainResponse)
async def explain_scan(
    scan_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Generate AI executive summary from stored findings. Score is never changed."""
    service = ScanService(db)
    scan = await service.get_scan(scan_id, user_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    findings = await service.get_scan_findings(scan_id)
    rec_service = RecommendationService(db)
    rec_payload = await rec_service.build_recommendations(scan_id, user_id)
    explanation = await rec_service.explain_scan_with_ai(
        scan,
        findings,
        recommendations=rec_payload.get("recommendations"),
    )
    details = [AIExplanationDetail(**item) for item in explanation.get("details") or []]
    recs = [
        item.get("recommendation")
        for item in rec_payload.get("recommendations") or []
        if item.get("recommendation")
    ][:5]
    available = bool(explanation.get("available"))
    summary = explanation.get("summary") or ""
    return AIExplainResponse(
        explanation=summary,
        recommendations=recs,
        is_ai_generated=available,
        model_used=settings.GEMINI_MODEL if available else "rule-engine",
        available=available,
        summary=summary,
        details=details,
    )


@router.post("/explain-finding/{finding_id}", response_model=AIExplainResponse)
async def explain_single_finding(
    finding_id: ResourceId,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Explain one finding using the cached scan-level Gemini result or rule-based fallback."""
    service = ScanService(db)
    from app.models.scan import Finding, ScanJob
    from sqlalchemy import select

    # The finding is looked up together with its owner's scan, so a finding that
    # belongs to somebody else simply does not match. Authorising after an
    # unfiltered fetch answered 404 for "no such finding" and 403 for "not
    # yours", which let any authenticated user enumerate which finding IDs exist
    # in other tenants' scans. Every other resource here answers a flat 404.
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.scan_job_id.in_(
                select(ScanJob.id).where(ScanJob.user_id == user_id)
            ),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    # Ownership is established by the query above, so the parent scan is the
    # caller's own.
    scan_id = finding.scan_job_id
    findings = await service.get_scan_findings(scan_id)
    rec_service = RecommendationService(db)
    rec_payload = await rec_service.build_recommendations(scan_id, user_id)
    explanation = await rec_service.explain_scan_with_ai(
        scan,
        findings,
        recommendations=rec_payload.get("recommendations"),
    )
    match = next(
        (
            item
            for item in explanation.get("details") or []
            if str(item.get("title") or "").lower() == str(finding.title or "").lower()
        ),
        None,
    )
    if match:
        text = (
            f"{match.get('explanation', '')}\n\n"
            f"Why it matters: {match.get('why_it_matters', '')}\n"
            f"Impact: {match.get('impact', '')}"
        ).strip()
        recs = match.get("remediation") or []
        finding.ai_explanation = text
        await db.flush()
        return AIExplainResponse(
            explanation=text,
            recommendations=recs,
            is_ai_generated=bool(explanation.get("available")),
            model_used=settings.GEMINI_MODEL if explanation.get("available") else "rule-engine",
            available=bool(explanation.get("available")),
            summary=explanation.get("summary") or "",
            details=[AIExplanationDetail(**match)],
        )

    fallback_text = finding.recommendation or finding.description
    return AIExplainResponse(
        explanation=fallback_text,
        recommendations=[finding.recommendation] if finding.recommendation else [],
        is_ai_generated=False,
        model_used="rule-engine",
        available=False,
        summary="AI explanation is temporarily unavailable.",
        details=[],
    )


@router.post("/rag/ask", response_model=RAGQueryResponse)
async def ask_rag_assistant(
    data: RAGQueryRequest,
    user_id: int = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Ask cybersecurity questions with semantic RAG retrieval and source citations."""
    scan_context = None
    if data.scan_job_id:
        service = ScanService(db)
        scan = await service.get_scan(data.scan_job_id, user_id)
        if scan:
            findings = await service.get_scan_findings(scan.id)
            findings_summary = ", ".join([f.title for f in findings[:5]])
            scan_context = {
                "target_domain": scan.target_domain,
                "overall_score": scan.overall_score,
                "risk_level": scan.risk_level,
                "findings_summary": findings_summary,
            }

    result = await rag_service.answer_query(
        question=data.question,
        scan_context=scan_context,
    )

    return RAGQueryResponse(
        answer=result["answer"],
        sources=result["sources"],
        is_ai_generated=result["is_ai_generated"],
        scan_context_used=result["scan_context_used"],
    )
