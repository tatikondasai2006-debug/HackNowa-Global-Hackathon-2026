"""Tests for the Gemini explanation service and fallbacks."""


from __future__ import annotations
import asyncio
import pytest
import json
from types import SimpleNamespace



from app.services.gemini_service import (
    UNAVAILABLE_SUMMARY,
    GeminiService,
    GeminiUnavailableError,
    build_minimal_findings,
    classify_gemini_error,
    sanitize_explanation,
)
from app.services.recommendation_service import build_rule_based_explanation
from app.core.config import settings

# Retired provider model names must not be reintroduced; the configured default
# is exercised directly in test_configured_default_model_is_supported below.
TEST_MODEL = "gemini-flash-latest"

RETIRED_MODELS = {"gemini-1.0-pro", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"}

FINDINGS = [
    SimpleNamespace(
        id=1,
        title="Missing HSTS header",
        severity="high",
        category="Headers",
        description="The site does not send Strict-Transport-Security.",
        evidence="SECRET-SHOULD-NOT-BE-SENT",
        technical_details={"raw": "cookie=abc"},
        recommendation="Enable HSTS with a one-year max-age.",
        remediation_steps=["Add the Strict-Transport-Security header."],
    ),
    SimpleNamespace(
        id=2,
        title="No DMARC record",
        severity="medium",
        category="Email",
        description="DMARC is not published.",
        evidence=None,
        technical_details=None,
        recommendation="Publish a DMARC policy of quarantine or reject.",
        remediation_steps=["Add a _dmarc TXT record."],
    ),
]


VALID_JSON = """
{
  "summary": "Your website has a few fixable security gaps.",
  "details": [
    {
      "title": "Missing HSTS header",
      "explanation": "Browsers are not told to always use HTTPS.",
      "why_it_matters": "Customers could be sent to an insecure copy of your site.",
      "impact": "Attackers could intercept logins on public Wi-Fi.",
      "remediation": ["Ask your host to enable HSTS."]
    }
  ],
  "score": 1
}
"""


@pytest.mark.asyncio
async def test_successful_gemini_response_ignores_model_score():
    async def fake_generate(_prompt: str) -> str:
        return VALID_JSON

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        timeout_seconds=5,
        generate_fn=fake_generate,
    )
    result = await service.generate_scan_explanation(
        FINDINGS,
        context={"scan_id": 9, "risk_level": "medium"},
        cache_key="success",
    )
    assert result["available"] is True
    assert "fixable security gaps" in result["summary"]
    assert result["details"][0]["title"] == "Missing HSTS header"
    assert "score" not in result
    prompt_findings = build_minimal_findings(FINDINGS)
    assert "SECRET-SHOULD-NOT-BE-SENT" not in str(prompt_findings)
    assert "cookie=abc" not in str(prompt_findings)


@pytest.mark.asyncio
async def test_missing_api_key_uses_unavailable_payload():
    service = GeminiService(api_key="", model=TEST_MODEL, generate_fn=lambda _: None)
    result = await service.explain_or_none(FINDINGS, cache_key="missing-key")
    assert result["available"] is False
    assert result["summary"] == UNAVAILABLE_SUMMARY


@pytest.mark.asyncio
async def test_timeout_is_classified_and_falls_back():
    async def slow(_prompt: str) -> str:
        await asyncio.sleep(0.2)
        return VALID_JSON

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        timeout_seconds=0.01,
        generate_fn=slow,
    )
    with pytest.raises(GeminiUnavailableError) as exc:
        await service.generate_scan_explanation(FINDINGS, cache_key="timeout")
    assert exc.value.reason == "timeout"
    result = await service.explain_or_none(FINDINGS, cache_key="timeout-2")
    assert result["available"] is False
    assert result["summary"] == UNAVAILABLE_SUMMARY


@pytest.mark.asyncio
async def test_rate_limit_failure():
    async def limited(_prompt: str) -> str:
        raise RuntimeError("429 Resource exhausted: rate limit")

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=limited,
    )
    with pytest.raises(GeminiUnavailableError) as exc:
        await service.generate_scan_explanation(FINDINGS, cache_key="rate")
    assert exc.value.reason == "rate_limit"
    assert classify_gemini_error(RuntimeError("429 quota exceeded")) == "rate_limit"


@pytest.mark.asyncio
async def test_api_failure():
    async def boom(_prompt: str) -> str:
        raise RuntimeError("500 internal from provider")

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=boom,
    )
    with pytest.raises(GeminiUnavailableError) as exc:
        await service.generate_scan_explanation(FINDINGS, cache_key="api")
    assert exc.value.reason == "api_error"
    result = await service.explain_or_none(FINDINGS, cache_key="api-2")
    assert result["available"] is False


@pytest.mark.asyncio
async def test_malformed_ai_response():
    async def bad(_prompt: str) -> str:
        return "sorry, I cannot help with that"

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=bad,
    )
    with pytest.raises(GeminiUnavailableError) as exc:
        await service.generate_scan_explanation(FINDINGS, cache_key="malformed")
    assert exc.value.reason == "malformed"


def test_fallback_recommendation_is_useful():
    recs = [
        {
            "title": "Missing HSTS header",
            "recommendation": "Enable HSTS with a one-year max-age.",
            "remediation_steps": ["Add the Strict-Transport-Security header."],
        }
    ]
    payload = build_rule_based_explanation(FINDINGS, recs)
    assert payload["available"] is False
    assert payload["summary"] == UNAVAILABLE_SUMMARY
    assert payload["details"]
    remediation = payload["details"][0]["remediation"]
    assert remediation
    # The fallback must surface actionable remediation for the HSTS finding.
    # Match on the header name in either the short or long spelling.
    assert any("hsts" in step.lower() or "strict-transport-security" in step.lower()
               for step in remediation)


def test_sanitize_strips_secrets_and_score_fields():
    raw = {
        "summary": "Looks ok. GEMINI_API_KEY=super-secret",
        "details": [
            {
                "title": "Issue",
                "explanation": "AQ.ThisIsAFakeTestTokenValueForSanitizationChecks",
                "why_it_matters": "x",
                "impact": "y",
                "remediation": ["patch"],
            }
        ],
        "score": 99,
    }
    cleaned = sanitize_explanation(raw, available=True)
    assert "super-secret" not in cleaned["summary"]
    assert "AQ." not in cleaned["details"][0]["explanation"]
    assert "score" not in cleaned


def test_configured_default_model_is_supported():
    """The shipped default model must not be a retired provider model."""
    assert settings.GEMINI_MODEL == "gemini-flash-latest"
    assert settings.GEMINI_MODEL not in RETIRED_MODELS


def test_service_defaults_to_configured_model(monkeypatch):
    """With no explicit model, the service must use settings.GEMINI_MODEL."""
    monkeypatch.setattr(settings, "GEMINI_MODEL", "gemini-flash-latest")
    service = GeminiService(api_key="test-key")
    assert service.model_name == "gemini-flash-latest"


@pytest.mark.asyncio
async def test_successful_response_is_parsed_and_model_forwarded():
    """End-to-end success path: the configured model is used and parsed."""
    seen = {}

    async def fake_generate(prompt: str) -> str:
        seen["prompt"] = prompt
        return VALID_JSON

    service = GeminiService(api_key="test-key", generate_fn=fake_generate)
    result = await service.generate_scan_explanation(
        FINDINGS, context={"scan_id": 9, "risk_level": "medium"}, cache_key="cfg"
    )
    assert service.model_name == settings.GEMINI_MODEL
    assert service.model_name not in RETIRED_MODELS
    assert result["available"] is True
    assert result["summary"]
    assert result["details"]
    assert seen["prompt"]
    assert result["details"]


@pytest.mark.asyncio
async def test_multiple_findings_are_parsed():
    response = {
        "summary": "Two security findings need attention.",
        "details": [
            {
                "title": "Missing HSTS header",
                "explanation": "Browsers are not told to always use HTTPS.",
                "why_it_matters": "Customers could reach an insecure copy of the site.",
                "impact": "Logins could be intercepted.",
                "remediation": ["Enable HSTS."],
            },
            {
                "title": "No DMARC record",
                "explanation": "The domain has no DMARC policy.",
                "why_it_matters": "Email recipients have less protection from spoofing.",
                "impact": "Attackers could impersonate the domain.",
                "remediation": ["Publish a DMARC TXT record."],
            },
        ],
    }

    async def fake_generate(_prompt: str) -> str:
        import json
        return json.dumps(response)

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=fake_generate,
    )

    result = await service.generate_scan_explanation(
        FINDINGS,
        cache_key="multiple-findings",
    )

    assert result["available"] is True
    assert [detail["title"] for detail in result["details"]] == [
        "Missing HSTS header",
        "No DMARC record",
    ]
    assert result["details"][1]["remediation"] == [
        "Publish a DMARC TXT record."
    ]


@pytest.mark.asyncio
async def test_empty_findings_are_handled():
    assert build_minimal_findings([]) == []

    async def fake_generate(_prompt: str) -> str:
        return '{"summary": "No findings to explain.", "details": []}'

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=fake_generate,
    )

    result = await service.generate_scan_explanation(
        [],
        cache_key="empty-findings",
    )

    assert result["available"] is True
    assert result["summary"] == "No findings to explain."
    assert result["details"] == []


@pytest.mark.asyncio
async def test_valid_json_with_invalid_schema_is_malformed():
    async def fake_generate(_prompt: str) -> str:
        return '{"summary": "A summary.", "details": {}}'

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=fake_generate,
    )

    with pytest.raises(GeminiUnavailableError) as exc:
        await service.generate_scan_explanation(
            FINDINGS,
            cache_key="invalid-details-schema",
        )

    assert exc.value.reason == "malformed"


@pytest.mark.asyncio
async def test_task_cancellation_propagates():
    started = asyncio.Event()

    async def blocked_generate(_prompt: str) -> str:
        started.set()
        await asyncio.Event().wait()

    service = GeminiService(
        api_key="test-key",
        model=TEST_MODEL,
        generate_fn=blocked_generate,
    )

    task = asyncio.create_task(
        service.generate_scan_explanation(
            FINDINGS,
            cache_key="cancelled-request",
        )
    )

    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


def test_sanitizer_redacts_secrets_across_all_output_fields():
    fake_secret = "GEMINI_API_KEY=fake-test-credential-123"

    raw = {
        "summary": f"Summary {fake_secret}",
        "details": [
            {
                "title": "Test finding",
                "explanation": f"Explanation {fake_secret}",
                "why_it_matters": f"Why it matters {fake_secret}",
                "impact": f"Impact {fake_secret}",
                "remediation": [f"Recommendation {fake_secret}"],
            }
        ],
    }

    cleaned = sanitize_explanation(raw, available=True)

    assert fake_secret not in str(cleaned)
    assert "[redacted]" in cleaned["details"][0]["why_it_matters"]
    assert "[redacted]" in cleaned["details"][0]["impact"]
    assert "[redacted]" in cleaned["details"][0]["remediation"][0]