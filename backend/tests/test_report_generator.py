"""Report HTML generation must autoescape attacker-controlled scan fields."""

from datetime import datetime, timezone
from types import SimpleNamespace

from app.reports.report_generator import ReportGenerator


def test_report_html_escapes_evidence_and_titles():
    generator = ReportGenerator()
    scan = SimpleNamespace(
        id=7,
        target_domain="example.com",
        overall_score=42.0,
        risk_level="high",
        ai_summary=None,
        completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        passed_count=1,
        warning_count=0,
        failed_count=1,
    )
    findings = [
        SimpleNamespace(
            title="<script>alert('xss')</script>",
            severity="high",
            description="desc <b>bold</b>",
            evidence="<img src=x onerror=alert(1)>",
            recommendation="fix it",
        )
    ]
    results = [
        SimpleNamespace(
            module_name="tls",
            title="<script>alert(2)</script>",
            status="failed",
            score_impact=0,
            max_score=10,
        )
    ]
    html = generator.generate_html_report(scan, results, findings)
    assert "<script>alert('xss')</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<script>alert(2)</script>" not in html
