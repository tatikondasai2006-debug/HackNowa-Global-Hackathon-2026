"""TLS/SSL Scanner Module.

Checks SSL certificate validity, protocol versions, and TLS configuration.
All checks are passive — connecting as a normal HTTPS client.
"""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Sequence
import logging

from app.scanner.pinned_connect import connect_socket
from app.scanner.base import BaseScanner, ModuleResult, CheckResult, CheckStatus, CheckSeverity

logger = logging.getLogger(__name__)


class TLSScanner(BaseScanner):
    """Scans TLS/SSL configuration of a domain."""

    module_name = "tls"
    display_name = "TLS/SSL Security"
    timeout = 15

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )

        # Run SSL checks in thread pool to avoid blocking
        cert_info = await asyncio.get_event_loop().run_in_executor(
            None, self._get_cert_info, domain, pinned_ips
        )

        if cert_info is None:
            result.checks.append(CheckResult(
                module_name=self.module_name,
                check_name="ssl_connection",
                title="SSL/TLS Connection",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.CRITICAL,
                description="Could not establish an SSL/TLS connection to the server.",
                evidence=f"Failed to connect to {domain}:443 using SSL/TLS",
                score_impact=0.0,
                max_score=25.0,
                recommendation="Ensure your server supports HTTPS with a valid SSL/TLS certificate.",
                remediation_steps=[
                    "Obtain an SSL certificate (Let's Encrypt provides free certificates)",
                    "Install the certificate on your web server",
                    "Configure your server to accept HTTPS connections on port 443",
                    "Set up HTTP to HTTPS redirect"
                ],
                reference_urls=[
                    "https://letsencrypt.org/getting-started/",
                    "https://www.ssllabs.com/ssltest/"
                ]
            ))
            return result

        # Check 1: Certificate validity
        result.checks.append(self._check_cert_validity(cert_info))

        # Check 2: Certificate expiration
        result.checks.append(self._check_cert_expiration(cert_info))

        # Check 3: Certificate chain / issuer
        result.checks.append(self._check_cert_issuer(cert_info))

        # Check 4: Hostname match
        result.checks.append(self._check_hostname_match(cert_info, domain))

        # Check 5: Protocol version
        result.checks.append(self._check_protocol_version(cert_info))

        # Check 6: Negotiated cipher
        result.checks.append(self._check_cipher(cert_info))

        # Check 7: Subject Alternative Names
        result.checks.append(self._check_san(cert_info, domain))

        return result

    def _get_cert_info(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieve SSL certificate information from the server."""
        try:
            context = ssl.create_default_context()
            with connect_socket(domain, 443, pinned_ips, timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "cert": cert,
                        "protocol_version": protocol_version,
                        "cipher": cipher,
                        "valid": True,
                    }
        except ssl.SSLCertVerificationError as e:
            # Certificate exists but has issues
            try:
                context_no_verify = ssl.create_default_context()
                context_no_verify.check_hostname = False
                context_no_verify.verify_mode = ssl.CERT_NONE
                with connect_socket(domain, 443, pinned_ips, timeout=10) as sock:
                    with context_no_verify.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        protocol_version = ssock.version()
                        return {
                            "cert": None,
                            "protocol_version": protocol_version,
                            "cipher": ssock.cipher(),
                            "valid": False,
                            "error": str(e),
                        }
            except Exception:
                return None
        except Exception as e:
            logger.debug(f"TLS connection failed for {domain}: {e}")
            return None

    def _check_cert_validity(self, cert_info: Dict[str, Any]) -> CheckResult:
        """Check if the SSL certificate is valid."""
        if cert_info.get("valid") and cert_info.get("cert"):
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_valid",
                title="SSL Certificate Valid",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="The SSL certificate is valid and trusted.",
                evidence="Certificate validated successfully by system trust store",
                score_impact=25.0,
                max_score=25.0,
            )
        else:
            error_msg = cert_info.get("error", "Unknown certificate error")
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_valid",
                title="SSL Certificate Valid",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.CRITICAL,
                description="The SSL certificate could not be validated.",
                evidence=f"Validation error: {error_msg}",
                score_impact=0.0,
                max_score=25.0,
                recommendation="Obtain and install a valid SSL certificate from a trusted Certificate Authority.",
                remediation_steps=[
                    "Check if your certificate has expired",
                    "Ensure the certificate is issued by a trusted CA",
                    "Verify the certificate chain is complete",
                    "Consider using Let's Encrypt for free, trusted certificates"
                ],
                reference_urls=["https://letsencrypt.org/"]
            )

    def _check_cert_expiration(self, cert_info: Dict[str, Any]) -> CheckResult:
        """Check certificate expiration date."""
        cert = cert_info.get("cert")
        if not cert or "notAfter" not in cert:
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_expiration",
                title="Certificate Expiration",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.MEDIUM,
                description="Could not determine certificate expiration date.",
                score_impact=0.0,
                max_score=10.0,
            )

        try:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            expiry_date = datetime.fromtimestamp(not_after, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (expiry_date - now).days

            if days_remaining < 0:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="cert_expiration",
                    title="Certificate Expiration",
                    status=CheckStatus.FAILED,
                    severity=CheckSeverity.CRITICAL,
                    description="The SSL certificate has expired.",
                    evidence=f"Certificate expired on {expiry_date.strftime('%Y-%m-%d')} ({abs(days_remaining)} days ago)",
                    score_impact=0.0,
                    max_score=10.0,
                    recommendation="Renew your SSL certificate immediately.",
                    remediation_steps=["Renew the certificate through your CA or Let's Encrypt"],
                )
            elif days_remaining < 30:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="cert_expiration",
                    title="Certificate Expiration",
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="The SSL certificate expires soon.",
                    evidence=f"Certificate expires on {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days remaining)",
                    score_impact=5.0,
                    max_score=10.0,
                    recommendation="Renew your SSL certificate before it expires.",
                )
            else:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="cert_expiration",
                    title="Certificate Expiration",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description="The SSL certificate is not expiring soon.",
                    evidence=f"Certificate valid until {expiry_date.strftime('%Y-%m-%d')} ({days_remaining} days remaining)",
                    score_impact=10.0,
                    max_score=10.0,
                )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_expiration",
                title="Certificate Expiration",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not parse certificate expiration: {e}",
                score_impact=0.0,
                max_score=10.0,
            )

    def _check_cert_issuer(self, cert_info: Dict[str, Any]) -> CheckResult:
        """Check the certificate issuer/CA."""
        cert = cert_info.get("cert")
        if not cert or "issuer" not in cert:
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_issuer",
                title="Certificate Issuer",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.LOW,
                description="Could not determine certificate issuer.",
                score_impact=0.0,
                max_score=5.0,
            )

        issuer_parts = dict(x[0] for x in cert["issuer"])
        issuer_org = issuer_parts.get("organizationName", "Unknown")
        issuer_cn = issuer_parts.get("commonName", "Unknown")

        # Check for self-signed
        subject_parts = dict(x[0] for x in cert.get("subject", []))
        subject_org = subject_parts.get("organizationName", "")

        if issuer_org == subject_org and issuer_cn == subject_parts.get("commonName", ""):
            return CheckResult(
                module_name=self.module_name,
                check_name="cert_issuer",
                title="Certificate Issuer",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.MEDIUM,
                description="Certificate appears to be self-signed.",
                evidence=f"Issuer: {issuer_org} / {issuer_cn}",
                score_impact=2.0,
                max_score=5.0,
                recommendation="Use a certificate from a trusted Certificate Authority.",
            )

        return CheckResult(
            module_name=self.module_name,
            check_name="cert_issuer",
            title="Certificate Issuer",
            status=CheckStatus.PASSED,
            severity=CheckSeverity.INFO,
            description="Certificate is issued by a recognized Certificate Authority.",
            evidence=f"Issuer: {issuer_org} / {issuer_cn}",
            score_impact=5.0,
            max_score=5.0,
        )

    def _check_hostname_match(self, cert_info: Dict[str, Any], domain: str) -> CheckResult:
        """Check if the certificate matches the target domain."""
        cert = cert_info.get("cert")
        if not cert:
            return CheckResult(
                module_name=self.module_name,
                check_name="hostname_match",
                title="Hostname Match",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.HIGH,
                description="Could not verify hostname match.",
                score_impact=0.0,
                max_score=10.0,
            )

        # If connection succeeded with hostname verification, it matches
        if cert_info.get("valid"):
            return CheckResult(
                module_name=self.module_name,
                check_name="hostname_match",
                title="Hostname Match",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="The certificate hostname matches the target domain.",
                evidence=f"Domain '{domain}' matches certificate",
                score_impact=10.0,
                max_score=10.0,
            )

        return CheckResult(
            module_name=self.module_name,
            check_name="hostname_match",
            title="Hostname Match",
            status=CheckStatus.FAILED,
            severity=CheckSeverity.HIGH,
            description="The certificate hostname does not match the target domain.",
            evidence=f"Domain '{domain}' does not match certificate",
            score_impact=0.0,
            max_score=10.0,
            recommendation="Ensure the SSL certificate covers your domain name.",
        )

    def _check_protocol_version(self, cert_info: Dict[str, Any]) -> CheckResult:
        """Check the TLS protocol version."""
        protocol = cert_info.get("protocol_version", "")

        if protocol in ("TLSv1.3",):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_version",
                title="TLS Protocol Version",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="Server supports TLS 1.3, the latest and most secure version.",
                evidence=f"Protocol: {protocol}",
                score_impact=10.0,
                max_score=10.0,
            )
        elif protocol in ("TLSv1.2",):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_version",
                title="TLS Protocol Version",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="Server supports TLS 1.2, which is considered secure.",
                evidence=f"Protocol: {protocol}",
                score_impact=8.0,
                max_score=10.0,
            )
        elif protocol in ("TLSv1.1", "TLSv1"):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_version",
                title="TLS Protocol Version",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.HIGH,
                description=f"Server is using outdated {protocol} which has known vulnerabilities.",
                evidence=f"Protocol: {protocol}",
                score_impact=0.0,
                max_score=10.0,
                recommendation="Upgrade to TLS 1.2 or TLS 1.3.",
                remediation_steps=[
                    "Disable TLS 1.0 and TLS 1.1 in your server configuration",
                    "Enable TLS 1.2 and TLS 1.3",
                    "Test with SSLLabs after making changes"
                ],
            )
        else:
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_version",
                title="TLS Protocol Version",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.MEDIUM,
                description=f"Unknown or legacy protocol version: {protocol}",
                evidence=f"Protocol: {protocol or 'unknown'}",
                score_impact=3.0,
                max_score=10.0,
            )

    def _check_cipher(self, cert_info: Dict[str, Any]) -> CheckResult:
        """Evaluate the negotiated cipher suite (passive handshake only)."""
        cipher = cert_info.get("cipher")
        if not cipher:
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_cipher",
                title="TLS Cipher Suite",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.LOW,
                description="Could not determine the negotiated cipher suite.",
                score_impact=2.0,
                max_score=5.0,
            )

        name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
        bits = cipher[2] if isinstance(cipher, (list, tuple)) and len(cipher) > 2 else None
        lower = str(name).upper()
        weak_tokens = ("RC4", "MD5", "NULL", "EXPORT", "DES", "3DES", "CBC")
        weak_hits = [token for token in weak_tokens if token in lower]

        if weak_hits or (isinstance(bits, int) and bits < 128):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_cipher",
                title="TLS Cipher Suite",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.HIGH,
                description="The negotiated cipher uses weak or legacy cryptography.",
                evidence=f"Cipher: {name}" + (f" ({bits} bits)" if bits else ""),
                technical_details={"cipher": list(cipher) if isinstance(cipher, tuple) else cipher},
                score_impact=0.0,
                max_score=5.0,
                recommendation="Prefer TLS 1.3 AEAD ciphers (AES-GCM or ChaCha20-Poly1305).",
            )

        return CheckResult(
            module_name=self.module_name,
            check_name="tls_cipher",
            title="TLS Cipher Suite",
            status=CheckStatus.PASSED,
            severity=CheckSeverity.INFO,
            description="The handshake negotiated a modern cipher suite.",
            evidence=f"Cipher: {name}" + (f" ({bits} bits)" if bits else ""),
            technical_details={"cipher": list(cipher) if isinstance(cipher, tuple) else cipher},
            score_impact=5.0,
            max_score=5.0,
        )

    def _check_san(self, cert_info: Dict[str, Any], domain: str) -> CheckResult:
        """List certificate SAN entries and confirm the target host is covered."""
        cert = cert_info.get("cert") or {}
        sans = []
        for item in cert.get("subjectAltName", ()) or ():
            if len(item) >= 2:
                sans.append(f"{item[0]}:{item[1]}")

        if not sans and cert_info.get("valid"):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_san",
                title="Certificate SAN",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="Hostname matched during handshake; SAN list was not present in the parsed certificate.",
                evidence=f"Domain '{domain}' verified by TLS hostname check",
                score_impact=5.0,
                max_score=5.0,
            )

        covered = any(
            entry.lower().endswith(f":{domain.lower()}")
            or entry.lower().endswith(f":*.{'.'.join(domain.lower().split('.')[1:])}")
            for entry in sans
        )
        if covered or cert_info.get("valid"):
            return CheckResult(
                module_name=self.module_name,
                check_name="tls_san",
                title="Certificate SAN",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="Certificate subject alternative names cover the target host.",
                evidence="; ".join(sans) if sans else f"Hostname verified for {domain}",
                technical_details={"san": sans},
                score_impact=5.0,
                max_score=5.0,
            )

        return CheckResult(
            module_name=self.module_name,
            check_name="tls_san",
            title="Certificate SAN",
            status=CheckStatus.WARNING,
            severity=CheckSeverity.MEDIUM,
            description="Could not confirm SAN coverage for the target hostname.",
            evidence="; ".join(sans) if sans else "No SAN entries parsed",
            technical_details={"san": sans},
            score_impact=2.0,
            max_score=5.0,
            recommendation="Issue a certificate whose SAN list includes the scanned hostname.",
        )
