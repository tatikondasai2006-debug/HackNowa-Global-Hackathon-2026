"""Unit tests for the Security Scoring Engine."""

import pytest
from app.scanner.base import ModuleResult, CheckResult, CheckStatus, CheckSeverity
from app.scanner.scoring import calculate_score, get_risk_label, get_score_description


def test_perfect_score_calculation():
    """Test score when all checks pass."""
    results = [
        ModuleResult(
            module_name="tls",
            display_name="TLS/SSL Security",
            checks=[
                CheckResult(
                    module_name="tls",
                    check_name="cert_valid",
                    title="Cert Valid",
                    status=CheckStatus.PASSED,
                    score_impact=25.0,
                    max_score=25.0,
                )
            ]
        ),
        ModuleResult(
            module_name="headers",
            display_name="HTTP Security Headers",
            checks=[
                CheckResult(
                    module_name="headers",
                    check_name="hsts",
                    title="HSTS",
                    status=CheckStatus.PASSED,
                    score_impact=10.0,
                    max_score=10.0,
                )
            ]
        ),
    ]

    score = calculate_score(results)
    assert score.percentage == 100.0
    assert score.risk_level == "minimal"
    assert get_risk_label(score.risk_level) == "Minimal Risk"


def test_low_score_calculation():
    """Test score when critical checks fail."""
    results = [
        ModuleResult(
            module_name="tls",
            display_name="TLS/SSL Security",
            checks=[
                CheckResult(
                    module_name="tls",
                    check_name="cert_valid",
                    title="Cert Valid",
                    status=CheckStatus.FAILED,
                    severity=CheckSeverity.CRITICAL,
                    score_impact=0.0,
                    max_score=25.0,
                )
            ]
        ),
        ModuleResult(
            module_name="headers",
            display_name="HTTP Security Headers",
            checks=[
                CheckResult(
                    module_name="headers",
                    check_name="hsts",
                    title="HSTS",
                    status=CheckStatus.FAILED,
                    severity=CheckSeverity.HIGH,
                    score_impact=0.0,
                    max_score=10.0,
                )
            ]
        ),
    ]

    score = calculate_score(results)
    assert score.percentage == 0.0
    assert score.risk_level == "critical"
    assert "Critical security issues" in get_score_description(score.percentage)
