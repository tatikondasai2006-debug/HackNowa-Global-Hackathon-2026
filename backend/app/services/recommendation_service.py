"""Prioritized remediation recommendations derived from scan findings."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ScanNotFoundError
from app.models.scan import Finding, ScanJob, ScanStatus
from app.scanner.scoring import get_score_description
from app.services.gemini_service import (
    UNAVAILABLE_SUMMARY,
    build_minimal_findings,
    gemini_service,
    sanitize_explanation,
)

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class RecommendationService:
    """Builds ordered, actionable recommendations from stored findings."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_scan_or_404(self, scan_id: int, user_id: int) -> ScanJob:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_id, ScanJob.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise ScanNotFoundError("Scan not found")
        return scan

    async def build_recommendations(
        self, scan_id: int, user_id: int
    ) -> Dict[str, Any]:
        scan = await self.get_scan_or_404(scan_id, user_id)
        result = await self.db.execute(
            select(Finding).where(Finding.scan_job_id == scan_id)
        )
        findings = list(result.scalars().all())
        findings.sort(
            key=lambda f: (SEVERITY_RANK.get(f.severity, 5), f.id or 0)
        )

        items: List[Dict[str, Any]] = []
        for finding in findings:
            if not finding.recommendation and not finding.remediation_steps:
                continue
            items.append(
                {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "category": finding.category,
                    "recommendation": finding.recommendation,
                    "remediation_steps": finding.remediation_steps or [],
                    "reference_urls": finding.reference_urls or [],
                }
            )

        score = scan.overall_score or 0.0
        summary = (
            scan.ai_recommendations
            or get_score_description(score)
        )
        logger.info(
            "Built %s recommendations for scan_id=%s domain=%s",
            len(items),
            scan_id,
            scan.target_domain,
        )
        return {
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "overall_score": scan.overall_score,
            "risk_level": scan.risk_level,
            "status": scan.status,
            "is_complete": scan.status == ScanStatus.COMPLETED.value,
            "summary": summary,
            "priority_count": len(items),
            "recommendations": items,
        }

    def rule_based_explanation(
        self,
        findings: List[Any],
        recommendations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Deterministic owner-friendly explanation used when Gemini is unavailable."""
        return build_rule_based_explanation(findings, recommendations)

    async def explain_scan_with_ai(
        self,
        scan: ScanJob,
        findings: List[Finding],
        recommendations: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Return a sanitized AI explanation, falling back to rule-based text.

        Gemini never writes the scan score. Results are cached on the scan row
        so completed scans do not repeatedly call the model.
        """
        rec_items = recommendations
        if rec_items is None:
            built = await self.build_recommendations(scan.id, scan.user_id)
            rec_items = built.get("recommendations") or []

        fallback = build_rule_based_explanation(findings, rec_items)
        stored = scan.ai_explanation_payload
        if isinstance(stored, dict) and stored.get("summary"):
            available = bool(stored.get("available"))
            if available:
                return sanitize_explanation(stored, available=True)
            merged = dict(fallback)
            merged["summary"] = UNAVAILABLE_SUMMARY
            return sanitize_explanation(merged, available=False)

        if scan.status != ScanStatus.COMPLETED.value:
            return fallback

        result = await gemini_service.explain_or_none(
            findings,
            context={
                "scan_id": scan.id,
                "risk_level": scan.risk_level,
            },
            cache_key=f"scan:{scan.id}:{scan.completed_at}",
        )
        if result.get("available"):
            if not result.get("details"):
                result["details"] = fallback.get("details") or []
            scan.ai_explanation_payload = result
            scan.ai_summary = result.get("summary")
            await self.db.flush()
            return result

        merged = dict(fallback)
        merged["available"] = False
        merged["summary"] = UNAVAILABLE_SUMMARY
        scan.ai_explanation_payload = merged
        await self.db.flush()
        return merged


def _severity_impact(severity: str) -> str:
    mapping = {
        "critical": "Attackers could take over accounts, steal data, or impersonate your business.",
        "high": "This gap can be used to intercept traffic, send fake email, or weaken login security.",
        "medium": "This makes it easier for attackers to probe your site or trick customers.",
        "low": "This is a hardening gap. Fixing it reduces risk and improves security posture.",
        "info": "This is informational. Review it so you understand your current setup.",
    }
    return mapping.get((severity or "").lower(), mapping["medium"])


def _why_it_matters(category: str) -> str:
    category_l = (category or "").lower()
    if "tls" in category_l or "https" in category_l:
        return "Customers expect the padlock. Weak HTTPS lets others spy on or alter traffic."
    if "header" in category_l:
        return "Browser security headers are simple controls that block common website attacks."
    if "dns" in category_l:
        return "DNS settings decide where visitors and email go. Weak DNS can be abused for hijacking."
    if "email" in category_l or "spf" in category_l or "dmarc" in category_l:
        return "Email authentication stops criminals from sending messages that look like they came from you."
    if "port" in category_l:
        return "Open services on the internet are doors. Unused doors should stay closed."
    return "Fixing public security configuration reduces the chance of a preventable incident."


def build_rule_based_explanation(
    findings: List[Any],
    recommendations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Owner-friendly fallback built only from scanner recommendations."""
    rec_by_title: Dict[str, Dict[str, Any]] = {}
    for item in recommendations or []:
        title = str(item.get("title") or "")
        if title:
            rec_by_title[title] = item

    details: List[Dict[str, Any]] = []
    for finding in build_minimal_findings(findings):
        title = finding["title"]
        rec = rec_by_title.get(title, {})
        steps = rec.get("remediation_steps") or []
        if not steps and rec.get("recommendation"):
            steps = [rec["recommendation"]]
        if not steps:
            steps = ["Ask your website or IT provider to apply the recommended security configuration."]
        details.append(
            {
                "title": title,
                "severity": finding.get("severity"),
                "explanation": finding.get("issue")
                or "The scanner found a configuration gap that should be reviewed.",
                "why_it_matters": _why_it_matters(finding.get("category") or ""),
                "impact": _severity_impact(finding.get("severity") or ""),
                "remediation": steps,
            }
        )

    payload = {
        "summary": UNAVAILABLE_SUMMARY,
        "details": details,
    }
    return sanitize_explanation(payload, available=False)
