"""DNS Security Scanner Module.

Checks DNS configuration including DNSSEC, CAA records, and basic DNS health.
All checks are passive DNS lookups.
"""

import dns.resolver
import dns.rdatatype
import asyncio
import logging
from typing import List, Optional, Sequence

from app.scanner.base import (
    BaseScanner, ModuleResult, CheckResult, CheckStatus, CheckSeverity
)

logger = logging.getLogger(__name__)


class DNSScanner(BaseScanner):
    """Scans DNS configuration of a domain."""

    module_name = "dns"
    display_name = "DNS Configuration"
    timeout = 20

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )

        loop = asyncio.get_event_loop()

        # Check 1: DNS resolution
        dns_result = await loop.run_in_executor(None, self._check_dns_resolution, domain)
        result.checks.append(dns_result)

        if dns_result.status == CheckStatus.FAILED:
            return result  # Can't continue if DNS doesn't resolve

        # Check 2: DNSSEC
        result.checks.append(
            await loop.run_in_executor(None, self._check_dnssec, domain)
        )

        # Check 3: CAA records
        result.checks.append(
            await loop.run_in_executor(None, self._check_caa, domain)
        )

        # Check 4: Multiple nameservers
        result.checks.append(
            await loop.run_in_executor(None, self._check_nameservers, domain)
        )

        # Check 5: MX records exist
        result.checks.append(
            await loop.run_in_executor(None, self._check_mx, domain)
        )

        return result

    def _check_dns_resolution(self, domain: str) -> CheckResult:
        """Check if the domain resolves via DNS (A or AAAA)."""
        from app.scanner.dns_utils import make_resolver
        import dns.resolver

        resolver = make_resolver()
        a_records = []
        aaaa_records = []
        nxdomain = False

        try:
            answers = resolver.resolve(domain, "A")
            a_records = [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="dns_resolution",
                title="DNS Resolution",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.MEDIUM,
                description=f"DNS resolution check failed: {str(e)}",
                score_impact=0.0,
                max_score=5.0,
            )

        if not nxdomain:
            try:
                answers = resolver.resolve(domain, "AAAA")
                aaaa_records = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        else:
            return CheckResult(
                module_name=self.module_name,
                check_name="dns_resolution",
                title="DNS Resolution",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.CRITICAL,
                description="Domain does not exist (NXDOMAIN).",
                evidence=f"DNS lookup for '{domain}' returned NXDOMAIN",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Verify the domain name is correct and DNS is configured.",
            )

        if a_records or aaaa_records:
            evidence_parts = []
            if a_records:
                evidence_parts.append(f"A: {', '.join(a_records)}")
            if aaaa_records:
                evidence_parts.append(f"AAAA: {', '.join(aaaa_records)}")
            return CheckResult(
                module_name=self.module_name,
                check_name="dns_resolution",
                title="DNS Resolution",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="Domain resolves successfully via DNS.",
                evidence="; ".join(evidence_parts),
                technical_details={"a_records": a_records, "aaaa_records": aaaa_records},
                score_impact=5.0,
                max_score=5.0,
            )

        return CheckResult(
            module_name=self.module_name,
            check_name="dns_resolution",
            title="DNS Resolution",
            status=CheckStatus.WARNING,
            severity=CheckSeverity.HIGH,
            description="DNS server responded but no A or AAAA records were found.",
            evidence=f"No address records for '{domain}'",
            score_impact=2.0,
            max_score=5.0,
            recommendation="Publish A and/or AAAA records so the hostname is reachable.",
        )

    def _check_dnssec(self, domain: str) -> CheckResult:
        """Check if DNSSEC is enabled for the domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            # Try to get DNSKEY records
            try:
                resolver.resolve(domain, "DNSKEY")
                return CheckResult(
                    module_name=self.module_name,
                    check_name="dnssec",
                    title="DNSSEC",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description="DNSSEC is enabled, protecting against DNS spoofing.",
                    evidence="DNSKEY records found",
                    score_impact=5.0,
                    max_score=5.0,
                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return CheckResult(
                    module_name=self.module_name,
                    check_name="dnssec",
                    title="DNSSEC",
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="DNSSEC is not enabled. DNS responses are not cryptographically signed.",
                    evidence="No DNSKEY records found",
                    score_impact=0.0,
                    max_score=5.0,
                    recommendation="Enable DNSSEC through your DNS provider to protect against DNS spoofing.",
                    remediation_steps=[
                        "Contact your DNS provider to enable DNSSEC",
                        "Generate DNSSEC keys (ZSK and KSK)",
                        "Publish DS records at your domain registrar",
                        "Verify with: dig +dnssec yourdomain.com"
                    ],
                    reference_urls=["https://www.icann.org/resources/pages/dnssec-what-is-it-why-is-it-important-2019-03-05-en"],
                )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="dnssec",
                title="DNSSEC",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check DNSSEC: {str(e)}",
                score_impact=0.0,
                max_score=5.0,
            )

    def _check_caa(self, domain: str) -> CheckResult:
        """Check for CAA (Certificate Authority Authorization) records."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = resolver.resolve(domain, "CAA")
            records = [str(rdata) for rdata in answers]
            return CheckResult(
                module_name=self.module_name,
                check_name="caa_records",
                title="CAA Records",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="CAA records restrict which CAs can issue certificates for this domain.",
                evidence=f"CAA records: {'; '.join(records)}",
                score_impact=3.0,
                max_score=3.0,
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return CheckResult(
                module_name=self.module_name,
                check_name="caa_records",
                title="CAA Records",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.LOW,
                description="No CAA records found. Any CA can issue certificates for this domain.",
                evidence="No CAA records in DNS",
                score_impact=0.0,
                max_score=3.0,
                recommendation="Add CAA DNS records to restrict which Certificate Authorities can issue certificates.",
                remediation_steps=[
                    "Add a CAA record: yourdomain.com. IN CAA 0 issue \"letsencrypt.org\"",
                    "Add an iodef record for violation reporting"
                ],
            )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="caa_records",
                title="CAA Records",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check CAA records: {str(e)}",
                score_impact=0.0,
                max_score=3.0,
            )

    def _check_nameservers(self, domain: str) -> CheckResult:
        """Check for multiple nameservers (redundancy)."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = resolver.resolve(domain, "NS")
            nameservers = [str(rdata).rstrip(".") for rdata in answers]

            if len(nameservers) >= 2:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="nameservers",
                    title="Nameserver Redundancy",
                    status=CheckStatus.PASSED,
                    severity=CheckSeverity.INFO,
                    description=f"Domain has {len(nameservers)} nameservers providing redundancy.",
                    evidence=f"Nameservers: {', '.join(nameservers)}",
                    score_impact=2.0,
                    max_score=2.0,
                )
            else:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="nameservers",
                    title="Nameserver Redundancy",
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="Domain has only one nameserver. No DNS redundancy.",
                    evidence=f"Nameservers: {', '.join(nameservers)}",
                    score_impact=0.0,
                    max_score=2.0,
                    recommendation="Add at least 2 nameservers for DNS redundancy.",
                )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="nameservers",
                title="Nameserver Redundancy",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check nameservers: {str(e)}",
                score_impact=0.0,
                max_score=2.0,
            )

    def _check_mx(self, domain: str) -> CheckResult:
        """Check MX records exist and their hosts can be resolved."""
        from app.scanner.dns_utils import make_resolver
        import dns.resolver

        try:
            resolver = make_resolver()
            answers = resolver.resolve(domain, "MX")
            mx_records = sorted(
                [
                    {
                        "preference": int(rdata.preference),
                        "exchange": str(rdata.exchange).rstrip("."),
                    }
                    for rdata in answers
                ],
                key=lambda item: item["preference"],
            )
            if not mx_records:
                raise dns.resolver.NoAnswer()

            # RFC 7505 null MX
            if len(mx_records) == 1 and mx_records[0]["exchange"] in {"", "."}:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="mx_records",
                    title="MX Records",
                    status=CheckStatus.INFO,
                    severity=CheckSeverity.INFO,
                    description="Null MX is published; this domain is not intended to receive email.",
                    evidence="MX 0 .",
                    technical_details={"mx_records": mx_records, "null_mx": True},
                    score_impact=2.0,
                    max_score=2.0,
                )

            unresolved = []
            for record in mx_records:
                host = record["exchange"]
                try:
                    resolver.resolve(host, "A")
                except Exception:
                    try:
                        resolver.resolve(host, "AAAA")
                    except Exception:
                        unresolved.append(host)

            evidence = "; ".join(
                f"{item['preference']} {item['exchange']}" for item in mx_records
            )
            if unresolved:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="mx_records",
                    title="MX Records",
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="MX records exist but one or more mail hosts do not resolve.",
                    evidence=evidence,
                    technical_details={"mx_records": mx_records, "unresolved": unresolved},
                    score_impact=1.0,
                    max_score=2.0,
                    recommendation="Ensure every MX hostname has valid A or AAAA records.",
                )

            status = CheckStatus.PASSED
            description = "MX records are configured and mail hosts resolve."
            if len(mx_records) == 1:
                status = CheckStatus.WARNING
                description = "Only one MX host is published; add a backup MX for redundancy."

            return CheckResult(
                module_name=self.module_name,
                check_name="mx_records",
                title="MX Records",
                status=status,
                severity=CheckSeverity.INFO if status == CheckStatus.PASSED else CheckSeverity.LOW,
                description=description,
                evidence=evidence,
                technical_details={"mx_records": mx_records},
                score_impact=2.0 if status == CheckStatus.PASSED else 1.0,
                max_score=2.0,
                recommendation=(
                    "Publish at least two MX hosts with different preferences."
                    if status == CheckStatus.WARNING
                    else ""
                ),
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return CheckResult(
                module_name=self.module_name,
                check_name="mx_records",
                title="MX Records",
                status=CheckStatus.INFO,
                severity=CheckSeverity.INFO,
                description="No MX records found. Domain may not handle email.",
                evidence="No MX records in DNS",
                score_impact=2.0,
                max_score=2.0,
            )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="mx_records",
                title="MX Records",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check MX records: {str(e)}",
                score_impact=0.0,
                max_score=2.0,
            )
