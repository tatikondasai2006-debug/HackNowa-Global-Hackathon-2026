"""Rebuild a transparent score breakdown from persisted check results."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.models.scan import ScanResult
from app.scanner.base import CheckResult, CheckSeverity, CheckStatus, ModuleResult
from app.scanner.scoring import ScoreBreakdown, calculate_score

logger = logging.getLogger(__name__)


def breakdown_to_dict(score: ScoreBreakdown) -> Dict[str, Any]:
    return {
        "total_score": score.total_score,
        "max_possible_score": score.max_possible_score,
        "percentage": score.percentage,
        "risk_level": score.risk_level,
        "module_scores": score.module_scores,
        "scoring_factors": score.scoring_factors,
    }


def results_to_module_results(results: List[ScanResult]) -> List[ModuleResult]:
    grouped: Dict[str, ModuleResult] = {}
    for row in results:
        module = grouped.get(row.module_name)
        if module is None:
            module = ModuleResult(
                module_name=row.module_name,
                display_name=row.module_name.replace("_", " ").title(),
            )
            grouped[row.module_name] = module
        try:
            status = CheckStatus(row.status)
        except ValueError:
            status = CheckStatus.ERROR
        severity = None
        if row.severity:
            try:
                severity = CheckSeverity(row.severity)
            except ValueError:
                severity = None
        module.checks.append(
            CheckResult(
                module_name=row.module_name,
                check_name=row.check_name,
                title=row.title,
                status=status,
                severity=severity,
                description=row.description or "",
                evidence=row.evidence or "",
                technical_details=row.technical_details,
                score_impact=row.score_impact or 0.0,
                max_score=row.max_score or 0.0,
            )
        )
    return list(grouped.values())


def score_from_scan_results(results: List[ScanResult]) -> ScoreBreakdown:
    modules = results_to_module_results(results)
    score = calculate_score(modules)
    logger.debug(
        "Rebuilt score from %s stored checks: %s/100",
        len(results),
        score.percentage,
    )
    return score
