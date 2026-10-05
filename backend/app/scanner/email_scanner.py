"""Email Security Scanner Module.

Checks SPF, DKIM, and DMARC DNS records for email security configuration.
All checks are passive DNS lookups.
"""

import dns.resolver
import asyncio
import logging
import re
from typing import Optional, Sequence

from app.scanner.base import (
    BaseScanner, ModuleResult, CheckResult, CheckStatus, CheckSeverity
)

logger = logging.getLogger(__name__)


class EmailSecurityScanner(BaseScanner):
    """Scans email security configuration (SPF, DKIM, DMARC)."""

    module_name = "email_security"
    display_name = "Email Security (SPF/DKIM/DMARC)"
    timeout = 15

    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        result = ModuleResult(
            module_name=self.module_name,
            display_name=self.display_name,
        )

        loop = asyncio.get_event_loop()

        # Check 1: SPF record
        result.checks.append(
            await loop.run_in_executor(None, self._check_spf, domain)
        )

        # Check 2: DMARC record
        result.checks.append(
            await loop.run_in_executor(None, self._check_dmarc, domain)
        )

        # Check 3: DKIM (common selectors)
        result.checks.append(
            await loop.run_in_executor(None, self._check_dkim, domain)
        )

        return result

    def _check_spf(self, domain: str) -> CheckResult:
        """Check SPF (Sender Policy Framework) record."""
        from app.scanner.dns_utils import make_resolver, txt_to_string
        import dns.resolver

        try:
            resolver = make_resolver()
            answers = resolver.resolve(domain, "TXT")
            spf_records = []
            for rdata in answers:
                txt = txt_to_string(rdata).strip()
                if txt.lower().startswith("v=spf1"):
                    spf_records.append(txt)

            if len(spf_records) > 1:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="spf",
                    title="SPF Record",
                    status=CheckStatus.FAILED,
                    severity=CheckSeverity.HIGH,
                    description="Multiple SPF records exist. Receivers may treat SPF as invalid.",
                    evidence="; ".join(spf_records),
                    technical_details={"spf_records": spf_records},
                    score_impact=0.0,
                    max_score=5.0,
                    recommendation="Publish exactly one SPF TXT record that starts with v=spf1.",
                )

            if not spf_records:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="spf",
                    title="SPF Record",
                    status=CheckStatus.FAILED,
                    severity=CheckSeverity.HIGH,
                    description="No SPF record found. Email spoofing is not prevented.",
                    evidence="No TXT record starting with 'v=spf1' found",
                    score_impact=0.0,
                    max_score=5.0,
                    recommendation="Add an SPF TXT record to your DNS to prevent email spoofing.",
                    remediation_steps=[
                        "Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider)",
                        "Use '-all' for strict SPF (hard fail) or '~all' for soft fail",
                        "Keep DNS lookups under the RFC 7208 limit of 10",
                    ],
                    reference_urls=["https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"],
                )

            spf_text = spf_records[0]
            issues = []
            lookup_terms = re.findall(
                r"\b(?:include|a|mx|ptr|exists|redirect)=?", spf_text, flags=re.I
            )
            if "+all" in spf_text.lower() or spf_text.lower().endswith(" all") and "-all" not in spf_text.lower() and "~all" not in spf_text.lower() and "?all" not in spf_text.lower():
                if re.search(r"(?:\+|\s)all\b", spf_text.lower()) and not re.search(r"[-~?]all\b", spf_text.lower()):
                    issues.append("Uses '+all' or bare 'all' which allows any server to send mail")
            if "+all" in spf_text:
                issues.append("Uses '+all' which allows any server to send email")
            if len(lookup_terms) > 10:
                issues.append("Too many mechanisms that cause DNS lookups (RFC 7208 limit is 10)")
            if "ptr:" in spf_text.lower() or " ptr " in f" {spf_text.lower()} ":
                issues.append("Uses deprecated ptr mechanism")

            if issues:
                return CheckResult(
                    module_name=self.module_name,
                    check_name="spf",
                    title="SPF Record",
                    status=CheckStatus.WARNING,
                    severity=CheckSeverity.MEDIUM,
                    description="SPF record exists but has configuration issues.",
                    evidence=f"SPF: {spf_text}\nIssues: {'; '.join(issues)}",
                    technical_details={"spf": spf_text, "issues": issues},
                    score_impact=3.0,
                    max_score=5.0,
                    recommendation="Fix SPF record issues for better email security.",
                )

            all_policy = "none"
            match = re.search(r"([+\-~?]?)all\b", spf_text.lower())
            if match:
                qualifier = match.group(1) or "+"
                all_policy = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}.get(
                    qualifier, "pass"
                )

            score = 5.0 if all_policy in {"fail", "softfail"} else 4.0
            return CheckResult(
                module_name=self.module_name,
                check_name="spf",
                title="SPF Record",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="SPF record is configured, helping prevent email spoofing.",
                evidence=f"SPF: {spf_text}",
                technical_details={"spf": spf_text, "all_policy": all_policy},
                score_impact=score,
                max_score=5.0,
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return CheckResult(
                module_name=self.module_name,
                check_name="spf",
                title="SPF Record",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.HIGH,
                description="No SPF record found.",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Add an SPF record to prevent email spoofing.",
            )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="spf",
                title="SPF Record",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check SPF: {str(e)}",
                score_impact=0.0,
                max_score=5.0,
            )

    def _check_dmarc(self, domain: str) -> CheckResult:
        """Check DMARC record."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")

            dmarc_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_records.append(txt)

            if dmarc_records:
                if len(dmarc_records) > 1:
                    return CheckResult(
                        module_name=self.module_name,
                        check_name="dmarc",
                        title="DMARC Record",
                        status=CheckStatus.FAILED,
                        severity=CheckSeverity.HIGH,
                        description="Multiple DMARC records exist. Receivers may ignore DMARC.",
                        evidence="; ".join(dmarc_records),
                        technical_details={"dmarc_records": dmarc_records},
                        score_impact=0.0,
                        max_score=5.0,
                        recommendation="Publish exactly one TXT record at _dmarc.yourdomain.com.",
                    )
                dmarc_text = dmarc_records[0]
                # Check policy
                policy_match = re.search(r"p=(\w+)", dmarc_text)
                policy = policy_match.group(1) if policy_match else "none"
                has_rua = "rua=" in dmarc_text.lower()

                if policy == "none":
                    return CheckResult(
                        module_name=self.module_name,
                        check_name="dmarc",
                        title="DMARC Record",
                        status=CheckStatus.WARNING,
                        severity=CheckSeverity.MEDIUM,
                        description="DMARC record exists but policy is set to 'none' (monitoring only).",
                        evidence=f"DMARC: {dmarc_text}",
                        technical_details={"dmarc": dmarc_text, "policy": policy, "rua": has_rua},
                        score_impact=3.0,
                        max_score=5.0,
                        recommendation="Change DMARC policy to 'quarantine' or 'reject' for enforcement.",
                    )
                elif policy in ("quarantine", "reject"):
                    score = 5.0 if has_rua else 4.0
                    return CheckResult(
                        module_name=self.module_name,
                        check_name="dmarc",
                        title="DMARC Record",
                        status=CheckStatus.PASSED if has_rua else CheckStatus.WARNING,
                        severity=CheckSeverity.INFO if has_rua else CheckSeverity.LOW,
                        description=f"DMARC is configured with '{policy}' policy for email authentication.",
                        evidence=f"DMARC: {dmarc_text}",
                        technical_details={"dmarc": dmarc_text, "policy": policy, "rua": has_rua},
                        score_impact=score,
                        max_score=5.0,
                        recommendation=(
                            None if has_rua else "Add rua= so you receive aggregate DMARC reports."
                        ),
                    )

            return CheckResult(
                module_name=self.module_name,
                check_name="dmarc",
                title="DMARC Record",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.HIGH,
                description="No DMARC record found. Email authentication is not enforced.",
                evidence=f"No DMARC record at _dmarc.{domain}",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Add a DMARC record to enforce email authentication.",
                remediation_steps=[
                    "Add TXT record at _dmarc.yourdomain.com",
                    "Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                    "Monitor reports, then upgrade to p=quarantine or p=reject",
                ],
                reference_urls=["https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/"],
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return CheckResult(
                module_name=self.module_name,
                check_name="dmarc",
                title="DMARC Record",
                status=CheckStatus.FAILED,
                severity=CheckSeverity.HIGH,
                description="No DMARC record found.",
                evidence=f"No DNS record at _dmarc.{domain}",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Add a DMARC DNS record for email authentication.",
            )
        except Exception as e:
            return CheckResult(
                module_name=self.module_name,
                check_name="dmarc",
                title="DMARC Record",
                status=CheckStatus.ERROR,
                severity=CheckSeverity.LOW,
                description=f"Could not check DMARC: {str(e)}",
                score_impact=0.0,
                max_score=5.0,
            )

    def _check_dkim(self, domain: str) -> CheckResult:
        """Check DKIM by trying common selector names."""
        common_selectors = [
            "default", "google", "selector1", "selector2",
            "k1", "mail", "dkim", "s1", "s2", "email"
        ]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        found_selectors = []

        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "p=" in txt:
                        found_selectors.append(selector)
                        break
            except Exception:
                continue

        if found_selectors:
            return CheckResult(
                module_name=self.module_name,
                check_name="dkim",
                title="DKIM Record",
                status=CheckStatus.PASSED,
                severity=CheckSeverity.INFO,
                description="DKIM records found, enabling email signature verification.",
                evidence=f"DKIM selectors found: {', '.join(found_selectors)}",
                score_impact=5.0,
                max_score=5.0,
            )
        else:
            return CheckResult(
                module_name=self.module_name,
                check_name="dkim",
                title="DKIM Record",
                status=CheckStatus.WARNING,
                severity=CheckSeverity.MEDIUM,
                description="No DKIM records found with common selectors. DKIM may use custom selectors.",
                evidence=f"Checked selectors: {', '.join(common_selectors)} - none found",
                score_impact=0.0,
                max_score=5.0,
                recommendation="Configure DKIM for email signing. If already configured, your selector may be custom.",
                remediation_steps=[
                    "Generate DKIM keys through your email provider",
                    "Add the DKIM public key as a TXT record",
                    "Configure your mail server to sign outgoing emails",
                ],
                reference_urls=["https://www.cloudflare.com/learning/dns/dns-records/dns-dkim-record/"],
            )
