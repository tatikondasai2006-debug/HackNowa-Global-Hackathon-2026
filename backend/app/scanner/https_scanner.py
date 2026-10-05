"""HTTPS availability and HTTP→HTTPS redirect checks."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import httpx

from app.scanner.base import (
    BaseScanner,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    ModuleResult,
)
from app.scanner.pinned_connect import pinned_http_get

logger = logging.getLogger(__name__)


class HTTPSScanner(BaseScanner):
    """Confirms HTTPS is reachable and HTTP is upgraded."""

    module_name = "https"
    display_name = "HTTPS Availability"
    timeout = 15

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )
        result.checks.append(await self._check_https_reachable(domain, pinned_ips))
        result.checks.append(await self._check_https_redirect(domain, pinned_ips))
        result.checks.append(await self._check_http_status(domain, pinned_ips))
        return result

    async def _check_https_reachable(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> CheckResult:
        try:
            response = await pinned_http_get(
                domain,
                pinned_ips=pinned_ips,
                scheme="https",
                follow_redirects=True,
                verify=True,
                timeout=10,
            )
            return CheckResult(
                module_name=self.module_name,
                check_name="https_reachable",
                title="HTTPS Reachable",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="The site answers over HTTPS.",
                evidence=f"GET https://{domain} → {response.status_code}",
                technical_details={
                    "status_code": response.status_code,
                    "final_url": str(response.url),
                },
                score_impact=10.0,
                max_score=10.0,
            )
        except httpx.ConnectError:
            return CheckResult(
                module_name=self.module_name,
                check_name="https_reachable",
                title="HTTPS Reachable",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.CRITICAL,
                description="Could not establish an HTTPS connection.",
                evidence=f"Connection failed to https://{domain}",
                score_impact=0.0,
                max_score=10.0,
                recommendation="Enable HTTPS on port 443 with a valid certificate.",
                remediation_steps=[
                    "Install a TLS certificate (Let's Encrypt is free)",
                    "Listen on TCP 443 and serve the site over HTTPS",
                ],
                reference_urls=["https://letsencrypt.org/getting-started/"],
            )
        except Exception as exc:
            logger.debug("HTTPS reachability check failed for %s: %s", domain, exc)
            return CheckResult(
                module_name=self.module_name,
                check_name="https_reachable",
                title="HTTPS Reachable",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.HIGH,
                description="HTTPS is present but the handshake or certificate failed validation.",
                evidence=str(exc),
                score_impact=3.0,
                max_score=10.0,
                recommendation="Fix TLS certificate validation errors so browsers trust the site.",
            )

    async def _check_https_redirect(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> CheckResult:
        try:
            response = await pinned_http_get(
                domain,
                pinned_ips=pinned_ips,
                scheme="http",
                follow_redirects=False,
                verify=False,
                timeout=10,
            )
            location = response.headers.get("location", "")
            if response.status_code in (301, 302, 307, 308) and location.lower().startswith(
                "https://"
            ):
                return CheckResult(
                    module_name=self.module_name,
                    check_name="http_to_https_redirect",
                    title="HTTP to HTTPS Redirect",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description="HTTP requests are redirected to HTTPS.",
                    evidence=f"HTTP {response.status_code} → {location}",
                    score_impact=8.0,
                    max_score=8.0,
                )
            return CheckResult(
                module_name=self.module_name,
                check_name="http_to_https_redirect",
                title="HTTP to HTTPS Redirect",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.MEDIUM,
                description="HTTP does not redirect to HTTPS.",
                evidence=f"HTTP response status {response.status_code}",
                score_impact=0.0,
                max_score=8.0,
                recommendation="Redirect all HTTP traffic to HTTPS with a 301 response.",
                remediation_steps=[
                    "Configure the web server to issue a 301 to https://",
                    "Keep HSTS enabled after the redirect is in place",
                ],
            )
        except Exception as exc:
            logger.debug("HTTP redirect check failed for %s: %s", domain, exc)
            return CheckResult(
                module_name=self.module_name,
                check_name="http_to_https_redirect",
                title="HTTP to HTTPS Redirect",
                status=CheckStatus.INFO,
                severity=CheckSeverity.LOW,
                description="Could not test HTTP to HTTPS redirect (HTTP may be closed).",
                evidence=str(exc),
                score_impact=4.0,
                max_score=8.0,
            )

    async def _check_http_status(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> CheckResult:
        try:
            response = await pinned_http_get(
                domain,
                pinned_ips=pinned_ips,
                scheme="https",
                follow_redirects=True,
                verify=False,
                timeout=10,
            )
            if 200 <= response.status_code < 400:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="https_status",
                    title="HTTPS Response Status",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description="HTTPS returned a successful response after redirects.",
                    evidence=f"Final status {response.status_code}",
                    score_impact=2.0,
                    max_score=2.0,
                )
            return CheckResult(
                module_name=self.module_name,
                check_name="https_status",
                title="HTTPS Response Status",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.LOW,
                description="HTTPS responded with an error status code.",
                evidence=f"Status {response.status_code}",
                score_impact=1.0,
                max_score=2.0,
                recommendation="Investigate the HTTPS origin so it returns 2xx for the site homepage.",
            )
        except Exception as exc:
            return CheckResult(
                module_name=self.module_name,
                check_name="https_status",
                title="HTTPS Response Status",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not read HTTPS status: {exc}",
                score_impact=0.0,
                max_score=2.0,
            )
