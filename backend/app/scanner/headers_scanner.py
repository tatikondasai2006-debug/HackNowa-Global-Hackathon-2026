"""HTTP Security Headers Scanner Module.

Checks for the presence and correct configuration of security-related HTTP headers.
All checks are passive — just sending a normal HTTP request.
"""

import logging
from typing import Dict, Optional, Sequence

from app.scanner.base import (
    BaseScanner, ModuleResult, CheckResult, CheckStatus, CheckSeverity
)
from app.scanner.pinned_connect import pinned_http_get

logger = logging.getLogger(__name__)

# Security headers to check and their configurations
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "display": "HTTP Strict Transport Security (HSTS)",
        "severity": CheckSeverity.HIGH,
        "max_score": 10.0,
        "description_present": "HSTS is enabled, forcing browsers to use HTTPS.",
        "description_missing": "HSTS header is missing. Browsers may connect over insecure HTTP.",
        "recommendation": "Add the Strict-Transport-Security header with a max-age of at least 31536000 (1 year).",
        "remediation_steps": [
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Consider adding the preload directive for HSTS preload list inclusion",
            "Test with https://hstspreload.org/"
        ],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "Content-Security-Policy": {
        "display": "Content Security Policy (CSP)",
        "severity": CheckSeverity.HIGH,
        "max_score": 10.0,
        "description_present": "CSP is configured, providing XSS and injection protection.",
        "description_missing": "No Content Security Policy header. Site is more vulnerable to XSS attacks.",
        "recommendation": "Implement a Content Security Policy to control which resources can load.",
        "remediation_steps": [
            "Start with: Content-Security-Policy: default-src 'self'",
            "Add specific directives for scripts, styles, and images",
            "Use report-uri or report-to for violation monitoring",
            "Test in report-only mode first"
        ],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    "X-Content-Type-Options": {
        "display": "X-Content-Type-Options",
        "severity": CheckSeverity.MEDIUM,
        "max_score": 5.0,
        "description_present": "X-Content-Type-Options is set, preventing MIME type sniffing.",
        "description_missing": "X-Content-Type-Options header is missing. Browser may sniff MIME types.",
        "recommendation": "Add X-Content-Type-Options: nosniff header.",
        "remediation_steps": ["Add header: X-Content-Type-Options: nosniff"],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "X-Frame-Options": {
        "display": "X-Frame-Options",
        "severity": CheckSeverity.MEDIUM,
        "max_score": 5.0,
        "description_present": "X-Frame-Options is set, providing clickjacking protection.",
        "description_missing": "X-Frame-Options header is missing. Site may be vulnerable to clickjacking.",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN header.",
        "remediation_steps": [
            "Add header: X-Frame-Options: DENY (if no framing needed)",
            "Or: X-Frame-Options: SAMEORIGIN (if same-origin framing needed)",
            "Also consider using CSP frame-ancestors directive"
        ],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "Referrer-Policy": {
        "display": "Referrer Policy",
        "severity": CheckSeverity.LOW,
        "max_score": 3.0,
        "description_present": "Referrer-Policy is configured, controlling referrer information leakage.",
        "description_missing": "Referrer-Policy header is missing. Browser uses default referrer behavior.",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
        "remediation_steps": ["Add header: Referrer-Policy: strict-origin-when-cross-origin"],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "Permissions-Policy": {
        "display": "Permissions Policy",
        "severity": CheckSeverity.LOW,
        "max_score": 3.0,
        "description_present": "Permissions-Policy restricts browser feature access.",
        "description_missing": "Permissions-Policy is missing. Browser features are unrestricted.",
        "recommendation": "Add Permissions-Policy to restrict access to sensitive browser features.",
        "remediation_steps": [
            "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "Restrict features you don't need to the minimum scope"
        ],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
    "X-XSS-Protection": {
        "display": "X-XSS-Protection",
        "severity": CheckSeverity.LOW,
        "max_score": 2.0,
        "description_present": "X-XSS-Protection is set (legacy XSS filter).",
        "description_missing": "X-XSS-Protection header is missing (low impact with CSP present).",
        "recommendation": "Add X-XSS-Protection: 0 (or rely on CSP instead).",
        "remediation_steps": ["Add header: X-XSS-Protection: 0 (modern best practice with CSP)"],
        "reference_urls": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
    },
}

# Dangerous headers that should not be exposed
DANGEROUS_HEADERS = {
    "Server": {
        "display": "Server Header Information Disclosure",
        "severity": CheckSeverity.LOW,
        "max_score": 3.0,
        "description_present": "Server header exposes web server software details.",
        "recommendation": "Remove or minimize the Server header to prevent information disclosure.",
    },
    "X-Powered-By": {
        "display": "X-Powered-By Information Disclosure",
        "severity": CheckSeverity.LOW,
        "max_score": 3.0,
        "description_present": "X-Powered-By header exposes technology stack details.",
        "recommendation": "Remove the X-Powered-By header to prevent information disclosure.",
    },
}


class HeadersScanner(BaseScanner):
    """Scans HTTP security headers."""

    module_name = "headers"
    display_name = "HTTP Security Headers"
    timeout = 15

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )

        # Fetch headers
        headers = await self._fetch_headers(domain, pinned_ips)
        if headers is None:
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="http_connection",
                title="HTTP Connection",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.HIGH,
                description=f"Could not connect to {domain} via HTTP/HTTPS.",
                evidence=f"Connection to https://{domain} and http://{domain} failed",
                score_impact=0.0,
                max_score=44.0,
                recommendation="Ensure the website is accessible and responds to HTTP requests.",
            ))
            return result

        # Check HTTPS redirect
        result.checks.append(await self._check_https_redirect(domain, pinned_ips))

        # Check each security header
        for header_name, config in SECURITY_HEADERS.items():
            result.checks.append(
                self._check_security_header(headers, header_name, config)
            )

        # Check for dangerous information-disclosure headers
        for header_name, config in DANGEROUS_HEADERS.items():
            result.checks.append(
                self._check_dangerous_header(headers, header_name, config)
            )

        return result

    async def _fetch_headers(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> Optional[Dict[str, str]]:
        """Fetch HTTP response headers from the domain."""
        for scheme in ("https", "http"):
            try:
                response = await pinned_http_get(
                    domain,
                    pinned_ips=pinned_ips,
                    scheme=scheme,
                    follow_redirects=True,
                    verify=False,
                    timeout=10,
                )
                return dict(response.headers)
            except Exception as e:
                logger.debug("Failed to fetch headers from %s://%s: %s", scheme, domain, e)
                continue
        return None

    async def _check_https_redirect(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> CheckResult:
        """Check if HTTP redirects to HTTPS."""
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
            if response.status_code in (301, 302, 307, 308) and "https://" in location.lower():
                return CheckResult(
                    module_name=self.module_name,
                    check_name="https_redirect",
                    title="HTTPS Redirect",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description="HTTP requests are redirected to HTTPS.",
                    evidence=f"HTTP → {location} (Status {response.status_code})",
                    score_impact=5.0,
                    max_score=5.0,
                )
            return CheckResult(
                module_name=self.module_name,
                check_name="https_redirect",
                title="HTTPS Redirect",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.MEDIUM,
                description="HTTP does not redirect to HTTPS.",
                evidence=f"HTTP response: Status {response.status_code}",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Configure HTTP to HTTPS redirect (301 redirect).",
                remediation_steps=[
                    "Configure your web server to redirect all HTTP traffic to HTTPS",
                    "Use a 301 (permanent) redirect",
                    "Example (Nginx): return 301 https://$server_name$request_uri;"
                ],
            )
        except Exception:
            return CheckResult(
                module_name=self.module_name,
                check_name="https_redirect",
                title="HTTPS Redirect",
                status=CheckStatus.INFO,
                severity=CheckSeverity.LOW,
                description="Could not test HTTP to HTTPS redirect (HTTP port may be closed).",
                score_impact=3.0,
                max_score=5.0,
            )

    def _check_security_header(
        self, headers: Dict[str, str], header_name: str, config: Dict
    ) -> CheckResult:
        """Check if a security header is present."""
        # Case-insensitive header lookup
        value = None
        for k, v in headers.items():
            if k.lower() == header_name.lower():
                value = v
                break

        if value:
            quality = self._header_quality_issues(header_name, value)
            if quality:
                return CheckResult(
                    module_name=self.module_name,
                    check_name=f"header_{header_name.lower().replace('-', '_')}",
                    title=config["display"],
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="Header is present but not configured to recommended strength.",
                    evidence=f"{header_name}: {value}. Issues: {'; '.join(quality)}",
                    score_impact=round(config["max_score"] * 0.5, 1),
                    max_score=config["max_score"],
                    recommendation=config["recommendation"],
                    remediation_steps=config.get("remediation_steps"),
                    reference_urls=config.get("reference_urls"),
                )
            return CheckResult(
                module_name=self.module_name,
                check_name=f"header_{header_name.lower().replace('-', '_')}",
                title=config["display"],
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description=config["description_present"],
                evidence=f"{header_name}: {value}",
                score_impact=config["max_score"],
                max_score=config["max_score"],
            )
        else:
            return CheckResult(
                module_name=self.module_name,
                check_name=f"header_{header_name.lower().replace('-', '_')}",
                title=config["display"],
                status=CheckStatus.FAILED,
                severity=config["severity"],
                description=config["description_missing"],
                evidence=f"Header '{header_name}' not found in response",
                score_impact=0.0,
                max_score=config["max_score"],
                recommendation=config["recommendation"],
                remediation_steps=config.get("remediation_steps"),
                reference_urls=config.get("reference_urls"),
            )

    @staticmethod
    def _header_quality_issues(header_name: str, value: str) -> list:
        lower_name = header_name.lower()
        lower_value = value.lower()
        issues = []
        if lower_name == "strict-transport-security":
            import re

            match = re.search(r"max-age\s*=\s*(\d+)", lower_value)
            if not match:
                issues.append("HSTS is missing max-age")
            elif int(match.group(1)) < 31536000:
                issues.append("HSTS max-age is below the recommended 31536000 seconds")
        if lower_name == "x-content-type-options" and "nosniff" not in lower_value:
            issues.append("X-Content-Type-Options should be nosniff")
        if lower_name == "x-frame-options" and lower_value not in {"deny", "sameorigin"}:
            issues.append("X-Frame-Options should be DENY or SAMEORIGIN")
        return issues

    def _check_dangerous_header(
        self, headers: Dict[str, str], header_name: str, config: Dict
    ) -> CheckResult:
        """Check if a dangerous information-disclosure header is present."""
        value = None
        for k, v in headers.items():
            if k.lower() == header_name.lower():
                value = v
                break

        if value:
            return CheckResult(
                module_name=self.module_name,
                check_name=f"disclosure_{header_name.lower().replace('-', '_')}",
                title=config["display"],
                status=CheckStatus.WARNING,
                severity=config["severity"],
                description=config["description_present"],
                evidence=f"{header_name}: {value}",
                score_impact=config["max_score"] * 0.5,
                max_score=config["max_score"],
                recommendation=config["recommendation"],
            )
        else:
            return CheckResult(
                module_name=self.module_name,
                check_name=f"disclosure_{header_name.lower().replace('-', '_')}",
                title=config["display"],
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description=f"{header_name} header is not exposed.",
                score_impact=config["max_score"],
                max_score=config["max_score"],
            )
