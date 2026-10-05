"""Security Scoring Engine.

Calculates a transparent, deterministic security score from scan results.
Every score factor is documented and traceable to a specific check result.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import logging

from app.scanner.base import CheckResult, CheckStatus, ModuleResult

logger = logging.getLogger(__name__)


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how the security score was calculated."""
    total_score: float
    max_possible_score: float
    percentage: float  # 0-100
    risk_level: str
    module_scores: Dict[str, Dict[str, float]] = field(default_factory=dict)
    scoring_factors: List[Dict] = field(default_factory=list)


# Module weights (relative importance)
MODULE_WEIGHTS = {
    "tls": {
        "display_name": "TLS/SSL Security",
        "weight": 0.25,
        "description": "SSL/TLS certificate and protocol security",
    },
    "https": {
        "display_name": "HTTPS Availability",
        "weight": 0.10,
        "description": "HTTPS reachability and HTTP upgrade",
    },
    "headers": {
        "display_name": "HTTP Security Headers",
        "weight": 0.20,
        "description": "HTTP security response headers",
    },
    "dns": {
        "display_name": "DNS Configuration",
        "weight": 0.15,
        "description": "DNS security and configuration",
    },
    "email_security": {
        "display_name": "Email Security",
        "weight": 0.15,
        "description": "SPF, DKIM, and DMARC email authentication",
    },
    "ports": {
        "display_name": "Port & Service Exposure",
        "weight": 0.15,
        "description": "Exposed services and port security",
    },
}

# Risk level thresholds
RISK_THRESHOLDS = [
    (90, "minimal", "Minimal Risk"),
    (70, "low", "Low Risk"),
    (50, "medium", "Medium Risk"),
    (25, "high", "High Risk"),
    (0, "critical", "Critical Risk"),
]


def calculate_score(module_results: List[ModuleResult]) -> ScoreBreakdown:
    """Calculate the overall security score from module results.

    The score is a weighted average of individual module scores, where each
    module score is the ratio of earned points to maximum possible points.

    Scoring is deterministic and transparent:
    - Each check contributes a defined score_impact and max_score
    - Module scores are weighted according to MODULE_WEIGHTS
    - The final score is normalized to 0-100
    - Risk level is determined by score thresholds

    Returns:
        ScoreBreakdown with full scoring details
    """
    module_scores: Dict[str, Dict[str, float]] = {}
    scoring_factors: List[Dict] = []
    weighted_total = 0.0
    total_weight = 0.0

    for module_result in module_results:
        module_name = module_result.module_name
        weight_config = MODULE_WEIGHTS.get(module_name)

        if not weight_config:
            logger.warning(f"No weight configuration for module: {module_name}")
            continue

        weight = weight_config["weight"]

        if module_result.error and not module_result.checks:
            # Module failed entirely — counts as 0
            module_scores[module_name] = {
                "display_name": weight_config["display_name"],
                "earned": 0.0,
                "max": 0.0,
                "percentage": 0.0,
                "weight": weight,
                "weighted_contribution": 0.0,
                "error": module_result.error,
            }
            scoring_factors.append({
                "module": module_name,
                "display_name": weight_config["display_name"],
                "check": "module_error",
                "status": "error",
                "impact": f"Module error: {module_result.error}",
                "score_earned": 0.0,
                "score_max": 0.0,
            })
            # Still count the weight
            total_weight += weight
            continue

        earned = sum(c.score_impact for c in module_result.checks)
        max_possible = sum(c.max_score for c in module_result.checks)

        if max_possible > 0:
            module_pct = (earned / max_possible) * 100
        else:
            module_pct = 100.0  # No checks = full score (no issues)

        weighted_contribution = module_pct * weight
        weighted_total += weighted_contribution
        total_weight += weight

        module_scores[module_name] = {
            "display_name": weight_config["display_name"],
            "earned": round(earned, 1),
            "max": round(max_possible, 1),
            "percentage": round(module_pct, 1),
            "weight": weight,
            "weighted_contribution": round(weighted_contribution, 1),
        }

        # Record individual scoring factors
        for check in module_result.checks:
            scoring_factors.append({
                "module": module_name,
                "display_name": weight_config["display_name"],
                "check": check.check_name,
                "title": check.title,
                "status": check.status.value,
                "score_earned": check.score_impact,
                "score_max": check.max_score,
                "severity": check.severity.value if check.severity else None,
            })

    # Calculate final percentage
    if total_weight > 0:
        final_percentage = weighted_total / total_weight
    else:
        final_percentage = 0.0

    # Determine risk level
    risk_level = "critical"
    for threshold, level, _ in RISK_THRESHOLDS:
        if final_percentage >= threshold:
            risk_level = level
            break

    return ScoreBreakdown(
        total_score=round(weighted_total, 1),
        max_possible_score=round(total_weight * 100, 1),
        percentage=round(final_percentage, 1),
        risk_level=risk_level,
        module_scores=module_scores,
        scoring_factors=scoring_factors,
    )


def get_risk_label(risk_level: str) -> str:
    """Get human-readable risk label."""
    labels = {
        "critical": "Critical Risk",
        "high": "High Risk",
        "medium": "Medium Risk",
        "low": "Low Risk",
        "minimal": "Minimal Risk",
    }
    return labels.get(risk_level, "Unknown")


def get_score_description(percentage: float) -> str:
    """Get a description of what the score means."""
    if percentage >= 90:
        return "Excellent security posture. The domain has strong security configurations."
    elif percentage >= 70:
        return "Good security posture with some areas for improvement."
    elif percentage >= 50:
        return "Moderate security posture. Several improvements are recommended."
    elif percentage >= 25:
        return "Poor security posture. Significant vulnerabilities need attention."
    else:
        return "Critical security issues detected. Immediate action is required."
