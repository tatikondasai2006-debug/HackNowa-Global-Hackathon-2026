"""Gemini-backed AI explanation layer for security scan findings.

This module is independent of the deterministic scanner. Scoring, checks,
evidence collection, and findings are never modified by Gemini. The provider
can be swapped by replacing this service; callers depend on the explanation
payload contract only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

GenerateFn = Callable[[str], Awaitable[str]]

UNAVAILABLE_SUMMARY = "AI explanation is temporarily unavailable."
MAX_FINDINGS_FOR_PROMPT = 8
MAX_SUMMARY_CHARS = 1800
MAX_DETAIL_CHARS = 800
MAX_REMEDIATION_STEPS = 6
MAX_DETAILS = 10
DEFAULT_TIMEOUT_SECONDS = 20

_SECRET_RE = re.compile(
    r"(GEMINI_API_KEY\s*=\s*\S+)|"
    r"(AIza[0-9A-Za-z_\-]{20,})|"
    r"(AQ\.[A-Za-z0-9_\-]{20,})|"
    r"(sk-[A-Za-z0-9_\-]{16,})",
    re.IGNORECASE,
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

USER_SAFE_REASONS = {
    "missing_api_key": "not_configured",
    "invalid_config": "invalid_configuration",
    "timeout": "timeout",
    "network": "network_failure",
    "rate_limit": "rate_limited",
    "api_error": "provider_error",
    "malformed": "malformed_response",
    "unexpected": "unavailable",
}

SYSTEM_PROMPT = """You are a cybersecurity advisor for small-business owners.
Explain the provided scan findings in beginner-friendly language.

Rules:
- Use ONLY the structured findings supplied. Do not invent extra issues, CVEs, breaches, or scores.
- Do NOT change, invent, or return a security score. Scoring is handled separately.
- Do not request or repeat secrets, API keys, passwords, raw certificates, or full HTTP dumps.
- Be concise, practical, and non-alarmist.

Return JSON only with this shape:
{
  "summary": "short overall explanation for a business owner",
  "details": [
    {
      "title": "finding title from input",
      "explanation": "what this finding means",
      "why_it_matters": "why a small business should care",
      "impact": "potential security impact if ignored",
      "remediation": ["practical step 1", "practical step 2"]
    }
  ]
}
"""


class GeminiUnavailableError(Exception):
    """Raised when Gemini cannot produce a usable explanation."""

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        super().__init__(message or reason)


def _safe_text(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    text = _CONTROL_RE.sub("", text)
    text = _SECRET_RE.sub("[redacted]", text)
    text = text.replace("\r\n", "\n").strip()
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def _truncate_list(values: Any, limit: int) -> List[str]:
    if not isinstance(values, list):
        if isinstance(values, str) and values.strip():
            return [_safe_text(values, MAX_DETAIL_CHARS)]
        return []
    cleaned: List[str] = []
    for item in values:
        text = _safe_text(item, MAX_DETAIL_CHARS)
        if text:
            cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def build_minimal_findings(findings: List[Any], limit: int = MAX_FINDINGS_FOR_PROMPT) -> List[Dict[str, Any]]:
    """Reduce stored findings to the minimum fields needed for an explanation."""
    ranked = sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(str(getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "")).lower(), 5),
            getattr(f, "id", None) or (f.get("id") if isinstance(f, dict) else 0) or 0,
        ),
    )
    payload: List[Dict[str, Any]] = []
    for finding in ranked[:limit]:
        if isinstance(finding, dict):
            payload.append(
                {
                    "title": _safe_text(finding.get("title"), 180),
                    "severity": _safe_text(finding.get("severity"), 20).lower(),
                    "category": _safe_text(finding.get("category"), 80),
                    "issue": _safe_text(finding.get("description") or finding.get("issue"), 280),
                }
            )
        else:
            payload.append(
                {
                    "title": _safe_text(getattr(finding, "title", ""), 180),
                    "severity": _safe_text(getattr(finding, "severity", ""), 20).lower(),
                    "category": _safe_text(getattr(finding, "category", ""), 80),
                    "issue": _safe_text(getattr(finding, "description", ""), 280),
                }
            )
    return [item for item in payload if item["title"]]


def sanitize_explanation(raw: Dict[str, Any], available: bool) -> Dict[str, Any]:
    """Validate and sanitize a model or fallback payload before API return."""
    summary = _safe_text(raw.get("summary") if isinstance(raw, dict) else "", MAX_SUMMARY_CHARS)
    if not summary:
        summary = UNAVAILABLE_SUMMARY if not available else "Security findings were reviewed for this scan."

    details_in = raw.get("details") if isinstance(raw, dict) else []
    if not isinstance(details_in, list):
        details_in = []

    details: List[Dict[str, Any]] = []
    for item in details_in[:MAX_DETAILS]:
        if not isinstance(item, dict):
            continue
        title = _safe_text(item.get("title"), 180)
        if not title:
            continue
        details.append(
            {
                "title": title,
                "severity": _safe_text(item.get("severity"), 20).lower() or None,
                "explanation": _safe_text(item.get("explanation"), MAX_DETAIL_CHARS),
                "why_it_matters": _safe_text(item.get("why_it_matters"), MAX_DETAIL_CHARS),
                "impact": _safe_text(item.get("impact"), MAX_DETAIL_CHARS),
                "remediation": _truncate_list(item.get("remediation"), MAX_REMEDIATION_STEPS),
            }
        )

    return {
        "available": bool(available),
        "summary": summary,
        "details": details,
    }


def _extract_json(text: str) -> Dict[str, Any]:
    if not text or not str(text).strip():
        raise GeminiUnavailableError("malformed", "empty_response")
    candidate = str(text).strip()
    fenced = _JSON_FENCE_RE.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            raise GeminiUnavailableError("malformed", "non_json_response")
        try:
            parsed = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as exc:
            raise GeminiUnavailableError("malformed", "invalid_json") from exc
    if not isinstance(parsed, dict):
        raise GeminiUnavailableError("malformed", "json_not_object")
    parsed.pop("score", None)
    parsed.pop("overall_score", None)
    parsed.pop("risk_level", None)
    if "summary" not in parsed or not str(parsed.get("summary") or "").strip():
        raise GeminiUnavailableError("malformed", "missing_summary")
    if "details" in parsed and not isinstance(parsed["details"], list):
        raise GeminiUnavailableError("malformed", "invalid_details")
    return parsed


def classify_gemini_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, GeminiUnavailableError):
        return exc.reason
    name = exc.__class__.__name__.lower()
    message = str(exc).lower()
    combined = f"{name} {message}"
    if any(token in combined for token in ("429", "resourceexhausted", "rate limit", "quota")):
        return "rate_limit"
    if any(token in combined for token in ("timeout", "deadline", "timed out")):
        return "timeout"
    if any(
        token in combined
        for token in ("connection", "network", "dns", "unreachable", "temporarily unavailable", "ssl")
    ):
        return "network"
    if any(token in combined for token in ("api key", "invalid x-goog-api-key", "permission", "401", "403", "unauthenticated")):
        return "invalid_config"
    return "api_error"


class GeminiService:
    """Thin, replaceable Gemini client used only for human-readable explanations."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        generate_fn: Optional[GenerateFn] = None,
    ):
        self.api_key = (api_key if api_key is not None else settings.gemini_api_key) or ""
        self.model_name = (model if model is not None else getattr(settings, "GEMINI_MODEL", "")) or ""
        timeout = timeout_seconds if timeout_seconds is not None else getattr(
            settings, "GEMINI_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS
        )
        try:
            self.timeout_seconds = float(timeout)
        except (TypeError, ValueError):
            self.timeout_seconds = float(DEFAULT_TIMEOUT_SECONDS)
        if self.timeout_seconds <= 0:
            self.timeout_seconds = float(DEFAULT_TIMEOUT_SECONDS)
        self._generate_fn = generate_fn
        self._model = None
        self._configured_client = False
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._last_request_at: Dict[str, float] = {}

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key.strip()) and bool(self.model_name.strip())

    def _ensure_lock(self, cache_key: str) -> asyncio.Lock:
        lock = self._locks.get(cache_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[cache_key] = lock
        return lock

    def _validate_configuration(self) -> None:
        if not self.api_key.strip():
            raise GeminiUnavailableError("missing_api_key")
        if not self.model_name.strip():
            raise GeminiUnavailableError("invalid_config")

    def _build_prompt(self, findings: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
        facts = {
            "risk_level": context.get("risk_level") or "unknown",
            "finding_count": len(findings),
            "findings": findings,
        }
        return (
            f"{SYSTEM_PROMPT}\n\n"
            "Structured security findings (do not alter scores; score is computed separately):\n"
            f"{json.dumps(facts, ensure_ascii=True)}"
        )

    async def _call_model(self, prompt: str) -> str:
        if self._generate_fn is not None:
            return await self._generate_fn(prompt)
        try:
            import google.generativeai as genai
        except Exception as exc:  # pragma: no cover - import environment
            raise GeminiUnavailableError("invalid_config") from exc

        if not self._configured_client:
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel(self.model_name)
            self._configured_client = True

        generation_config = {"response_mime_type": "application/json", "temperature": 0.2}
        response = await self._model.generate_content_async(
            prompt,
            generation_config=generation_config,
        )
        text = getattr(response, "text", None)
        if not text and getattr(response, "candidates", None):
            try:
                text = response.candidates[0].content.parts[0].text
            except Exception as exc:
                raise GeminiUnavailableError("malformed", "empty_candidates") from exc
        return text or ""

    async def generate_scan_explanation(
        self,
        findings: List[Any],
        context: Optional[Dict[str, Any]] = None,
        cache_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ask Gemini to explain findings. Never returns a mutated security score."""
        context = context or {}
        minimal = build_minimal_findings(findings)
        key = cache_key or json.dumps(minimal, sort_keys=True)
        cached = self._cache.get(key)
        if cached:
            logger.info(
                "gemini.cache_hit scan_id=%s finding_count=%s",
                context.get("scan_id"),
                len(minimal),
            )
            return cached

        lock = self._ensure_lock(key)
        async with lock:
            cached = self._cache.get(key)
            if cached:
                return cached

            last = self._last_request_at.get(key)
            if last and (time.monotonic() - last) < 2:
                raise GeminiUnavailableError("rate_limit", "duplicate_suppressed")
            self._last_request_at[key] = time.monotonic()

            self._validate_configuration()
            prompt = self._build_prompt(minimal, context)
            logger.info(
                "gemini.request scan_id=%s model=%s finding_count=%s timeout_s=%s",
                context.get("scan_id"),
                self.model_name,
                len(minimal),
                self.timeout_seconds,
            )
            try:
                raw_text = await asyncio.wait_for(
                    self._call_model(prompt),
                    timeout=self.timeout_seconds,
                )
            except GeminiUnavailableError:
                raise
            except asyncio.TimeoutError as exc:
                logger.warning(
                    "gemini.timeout scan_id=%s model=%s",
                    context.get("scan_id"),
                    self.model_name,
                )
                raise GeminiUnavailableError("timeout") from exc
            except Exception as exc:
                reason = classify_gemini_error(exc)
                logger.warning(
                    "gemini.failure scan_id=%s reason=%s error_type=%s",
                    context.get("scan_id"),
                    reason,
                    exc.__class__.__name__,
                )
                raise GeminiUnavailableError(reason) from exc

            parsed = _extract_json(raw_text)
            sanitized = sanitize_explanation(parsed, available=True)
            self._cache[key] = sanitized
            logger.info(
                "gemini.success scan_id=%s detail_count=%s",
                context.get("scan_id"),
                len(sanitized["details"]),
            )
            return sanitized

    async def explain_or_none(
        self,
        findings: List[Any],
        context: Optional[Dict[str, Any]] = None,
        cache_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            return await self.generate_scan_explanation(findings, context=context, cache_key=cache_key)
        except GeminiUnavailableError as exc:
            logger.info(
                "gemini.unavailable scan_id=%s reason=%s public=%s",
                (context or {}).get("scan_id"),
                exc.reason,
                USER_SAFE_REASONS.get(exc.reason, "unavailable"),
            )
            return sanitize_explanation({"summary": UNAVAILABLE_SUMMARY, "details": []}, available=False)
        except Exception:
            logger.exception(
                "gemini.unexpected scan_id=%s",
                (context or {}).get("scan_id"),
            )
            return sanitize_explanation({"summary": UNAVAILABLE_SUMMARY, "details": []}, available=False)


gemini_service = GeminiService()
