"""Scan Orchestrator.

Coordinates all scanner modules, collects results, calculates scores,
and generates findings. This is the main entry point for executing a scan.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Sequence, Tuple

from app.scanner.base import ModuleResult, CheckResult, CheckStatus, CheckSeverity
from app.scanner.tls_scanner import TLSScanner
from app.scanner.https_scanner import HTTPSScanner
from app.scanner.headers_scanner import HeadersScanner
from app.scanner.dns_scanner import DNSScanner
from app.scanner.email_scanner import EmailSecurityScanner
from app.scanner.port_scanner import PortScanner
from app.scanner.scoring import calculate_score, ScoreBreakdown

logger = logging.getLogger(__name__)

# Default scanner modules
DEFAULT_SCANNERS = [
    TLSScanner(),
    HTTPSScanner(),
    HeadersScanner(),
    DNSScanner(),
    EmailSecurityScanner(),
    PortScanner(),
]


class ScanOrchestrator:
    """Orchestrates the entire scanning workflow.

    1. Validates target domain
    2. Runs all scanner modules
    3. Collects and aggregates results
    4. Calculates security score
    5. Generates findings with recommendations
    """

    def __init__(self, scanners=None):
        self.scanners = scanners or DEFAULT_SCANNERS

    async def run_scan(
        self,
        domain: str,
        scan_options: Optional[Dict[str, bool]] = None,
        progress_callback=None,
        pinned_ips: Optional[Sequence[str]] = None,
    ) -> Tuple[List[ModuleResult], ScoreBreakdown]:
        """Execute a full security scan.

        Args:
            domain: Validated target domain
            scan_options: Optional dict to enable/disable specific modules
            progress_callback: Optional async callback(module_name, status) for progress updates
            pinned_ips: Pre-validated public IPs to connect to (SSRF pin)

        Returns:
            Tuple of (list of ModuleResults, ScoreBreakdown)
        """
        logger.info(f"Starting scan for domain: {domain}")

        # Filter scanners based on options
        active_scanners = self.scanners
        if scan_options:
            active_scanners = [
                s for s in self.scanners
                if scan_options.get(s.module_name, True)
            ]

        # Run all scanner modules
        module_results: List[ModuleResult] = []

        for scanner in active_scanners:
            logger.info(f"Running scanner module: {scanner.module_name}")

            if progress_callback:
                await progress_callback(scanner.module_name, "running")

            result = await scanner.safe_scan(domain, pinned_ips=pinned_ips)
            module_results.append(result)

            if progress_callback:
                status = "completed" if not result.error else "error"
                await progress_callback(scanner.module_name, status)

            logger.info(
                f"Module '{scanner.module_name}' completed: "
                f"{result.passed_count} passed, {result.failed_count} failed, "
                f"{result.warning_count} warnings"
            )

        # Calculate security score
        score = calculate_score(module_results)
        logger.info(
            f"Scan complete for {domain}: "
            f"Score {score.percentage}/100, Risk: {score.risk_level}"
        )

        return module_results, score

    @staticmethod
    def extract_findings(
        module_results: List[ModuleResult],
    ) -> List[Dict]:
        """Extract security findings from scan results.

        Generates structured finding records for failed and warning checks.
        """
        findings = []

        for module_result in module_results:
            for check in module_result.checks:
                if check.status in (CheckStatus.FAILED, CheckStatus.WARNING):
                    finding = {
                        "title": check.title,
                        "description": check.description,
                        "severity": check.severity.value if check.severity else "info",
                        "category": module_result.display_name,
                        "evidence": check.evidence,
                        "technical_details": check.technical_details,
                        "recommendation": check.recommendation,
                        "remediation_steps": check.remediation_steps,
                        "reference_urls": check.reference_urls,
                    }
                    findings.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

        return findings

    @staticmethod
    def get_total_checks(scanners=None) -> int:
        """Get the expected number of checks across all modules."""
        # This is approximate — actual count depends on scan results
        return len((scanners or DEFAULT_SCANNERS)) * 5  # Average ~5 checks per module
