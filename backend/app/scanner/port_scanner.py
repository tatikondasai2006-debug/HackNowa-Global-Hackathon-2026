"""Port Scanner Module.

Performs safe, limited port scanning of commonly exposed service ports.
Only checks a predefined set of well-known ports — no full port sweeps.
This is a defensive assessment, not penetration testing.
"""

import socket
import asyncio
import logging
from typing import List, Optional, Sequence, Tuple

from app.scanner.base import (
    BaseScanner, ModuleResult, CheckResult, CheckStatus, CheckSeverity
)
from app.scanner.pinned_connect import tcp_connect_open

logger = logging.getLogger(__name__)

# Only check common, well-known ports for defensive assessment
# We deliberately limit the scope to avoid aggressive scanning behavior
SAFE_PORTS = [
    (21, "FTP", CheckSeverity.HIGH, "File Transfer Protocol — often insecure"),
    (22, "SSH", CheckSeverity.INFO, "Secure Shell — expected on servers"),
    (23, "Telnet", CheckSeverity.CRITICAL, "Telnet — unencrypted remote access"),
    (25, "SMTP", CheckSeverity.MEDIUM, "Simple Mail Transfer Protocol"),
    (53, "DNS", CheckSeverity.INFO, "Domain Name System"),
    (80, "HTTP", CheckSeverity.INFO, "HTTP web server"),
    (110, "POP3", CheckSeverity.MEDIUM, "Post Office Protocol v3 — may be unencrypted"),
    (143, "IMAP", CheckSeverity.MEDIUM, "IMAP email access — may be unencrypted"),
    (443, "HTTPS", CheckSeverity.INFO, "HTTPS secure web server"),
    (445, "SMB", CheckSeverity.CRITICAL, "Server Message Block — high-risk if exposed"),
    (993, "IMAPS", CheckSeverity.INFO, "IMAP over SSL"),
    (995, "POP3S", CheckSeverity.INFO, "POP3 over SSL"),
    (3306, "MySQL", CheckSeverity.CRITICAL, "MySQL database — should not be exposed"),
    (3389, "RDP", CheckSeverity.HIGH, "Remote Desktop Protocol"),
    (5432, "PostgreSQL", CheckSeverity.CRITICAL, "PostgreSQL database — should not be exposed"),
    (8080, "HTTP-Alt", CheckSeverity.MEDIUM, "Alternative HTTP port"),
    (8443, "HTTPS-Alt", CheckSeverity.LOW, "Alternative HTTPS port"),
    (27017, "MongoDB", CheckSeverity.CRITICAL, "MongoDB — should not be exposed"),
]

# Ports that are expected/acceptable to be open
EXPECTED_OPEN = {80, 443, 22, 53, 25, 993, 995}

# Ports that are dangerous if publicly exposed
DANGEROUS_PORTS = {21, 23, 445, 3306, 3389, 5432, 27017}


class PortScanner(BaseScanner):
    """Scans common ports for exposed services."""

    module_name = "ports"
    display_name = "Port & Service Exposure"
    timeout = 30

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )

        # Scan ports concurrently with semaphore to limit parallelism
        open_ports = []
        closed_ports = []
        
        semaphore = asyncio.Semaphore(10)  # Limit concurrent connections

        async def check_port(port_info: Tuple[int, str, CheckSeverity, str]):
            async with semaphore:
                port, service, severity, desc = port_info
                is_open = await self._check_port(domain, port, pinned_ips)
                return (port, service, severity, desc, is_open)

        tasks = [check_port(p) for p in SAFE_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for item in results:
            if isinstance(item, Exception):
                continue
            port, service, severity, desc, is_open = item
            if is_open:
                open_ports.append((port, service, severity, desc))
            else:
                closed_ports.append((port, service))

        # Generate results for dangerous open ports
        dangerous_open = [p for p in open_ports if p[0] in DANGEROUS_PORTS]
        expected_open = [p for p in open_ports if p[0] in EXPECTED_OPEN]
        other_open = [p for p in open_ports if p[0] not in DANGEROUS_PORTS and p[0] not in EXPECTED_OPEN]

        # Overall port exposure summary
        if dangerous_open:
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="dangerous_ports",
                title="Dangerous Ports Exposed",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.CRITICAL,
                description=f"{len(dangerous_open)} potentially dangerous port(s) are publicly accessible.",
                evidence="Open dangerous ports: " + ", ".join(
                    f"{p[0]}/{p[1]}" for p in dangerous_open
                ),
                technical_details={"dangerous_ports": [
                    {"port": p[0], "service": p[1], "description": p[3]}
                    for p in dangerous_open
                ]},
                score_impact=0.0,
                max_score=15.0,
                recommendation="Close or firewall all unnecessary ports, especially database and remote access ports.",
                remediation_steps=[
                    "Review each open port and determine if it needs to be publicly accessible",
                    "Use a firewall to restrict access to necessary ports only",
                    "Move database ports behind a VPN or private network",
                    "Disable unused services",
                ],
            ))
        else:
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="dangerous_ports",
                title="No Dangerous Ports Exposed",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="No commonly dangerous ports are publicly accessible.",
                evidence="Checked ports: " + ", ".join(
                    str(p) for p in sorted(DANGEROUS_PORTS)
                ) + " — all closed",
                score_impact=15.0,
                max_score=15.0,
            ))

        # Report on service exposure
        if open_ports:
            open_summary = ", ".join(f"{p[0]}/{p[1]}" for p in open_ports)
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="open_ports_summary",
                title="Open Ports Summary",
                status=CheckStatus.INFO if not other_open else CheckStatus.WARNING,
                severity=CheckSeverity.INFO if not other_open else CheckSeverity.LOW,
                description=f"{len(open_ports)} port(s) are open: {open_summary}",
                evidence=f"Open ports: {open_summary}",
                technical_details={"open_ports": [
                    {"port": p[0], "service": p[1]} for p in open_ports
                ]},
                score_impact=5.0 if not other_open else 3.0,
                max_score=5.0,
            ))
        else:
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="open_ports_summary",
                title="Open Ports Summary",
                status=CheckStatus.INFO,
                severity=CheckSeverity.INFO,
                description="No common ports appear to be open (host may be filtered/firewalled).",
                score_impact=5.0,
                max_score=5.0,
            ))

        return result

    async def _check_port(
        self, domain: str, port: int, pinned_ips: Optional[Sequence[str]] = None
    ) -> bool:
        """Check if a specific port is open using TCP connect."""
        try:
            loop = asyncio.get_event_loop()
            # Use a short timeout for port checks
            future = loop.run_in_executor(
                None, tcp_connect_open, domain, port, pinned_ips, 2
            )
            return await asyncio.wait_for(future, timeout=3)
        except (asyncio.TimeoutError, Exception):
            return False
