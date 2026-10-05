"""Domain sanitization, format validation, and SSRF defenses.

Used by ScanService — not from route handlers — before any scan starts.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import List, Optional

from app.core.exceptions import DomainValidationError

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

# Suffix / special-name checks. Numeric addresses are enforced after DNS
# resolution via is_public_ip / ensure_public_ip.
BLOCKED_HOST_PATTERNS = [
    r"^localhost$",
    r"\.localhost$",  # RFC 6761: *.localhost is loopback
    r"^::1$",
    r"^\[::1\]$",
    r"\.local$",
    r"\.internal$",
    r"\.corp$",
    r"\.lan$",
    r"\.home\.arpa$",
    r"\.in-addr\.arpa$",
    r"\.ip6\.arpa$",
]

# Explicitly blocked IPv4 ranges. `ipaddress.is_private` alone is not enough:
# 100.64.0.0/10 (CGNAT / RFC6598, used by Tailscale and some cloud fabrics)
# reports is_private == False while still being non-routable internal space.
BLOCKED_IPV4_NETWORKS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC1918 private
        "100.64.0.0/10",  # CGNAT / shared address space
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local incl. 169.254.169.254 metadata
        "172.16.0.0/12",  # RFC1918 private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # 6to4 relay anycast
        "192.168.0.0/16",  # RFC1918 private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes 255.255.255.255
    )
)

# Explicitly blocked IPv6 ranges, including the transition mechanisms that can
# embed an arbitrary IPv4 address inside an apparently public IPv6 literal.
BLOCKED_IPV6_NETWORKS = tuple(
    ipaddress.IPv6Network(cidr)
    for cidr in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "64:ff9b::/96",  # NAT64 well-known prefix (embeds IPv4)
        "100::/64",  # discard-only
        "2001::/32",  # Teredo (embeds IPv4)
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4 (embeds IPv4)
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address tunneled inside an IPv6 address, if any.

    Without this, ``::ffff:169.254.169.254`` style literals and NAT64/6to4
    forms can be used to smuggle a blocked IPv4 target past the checks.
    """
    for attr in ("ipv4_mapped", "sixtofour"):
        embedded = getattr(addr, attr, None)
        if embedded is not None:
            return embedded
    teredo = getattr(addr, "teredo", None)
    if teredo is not None:
        return teredo[1]
    if addr in ipaddress.IPv6Network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


class DomainValidator:
    """Normalize a user-supplied host and reject private/internal targets."""

    def sanitize(self, raw: str) -> str:
        if raw is None:
            raise DomainValidationError("Domain is required")

        domain = raw.strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0]
        domain = domain.split("?")[0]
        domain = domain.split("#")[0]
        domain = domain.split(":")[0]
        domain = domain.strip(".")

        if domain.startswith("[") and domain.endswith("]"):
            domain = domain[1:-1]

        if not domain:
            raise DomainValidationError("Domain is required")

        logger.debug("Sanitized domain input %r -> %r", raw, domain)
        return domain

    def is_blocked_hostname(self, domain: str) -> bool:
        for pattern in BLOCKED_HOST_PATTERNS:
            if re.search(pattern, domain):
                return True
        return False

    def is_public_ip(self, ip_str: str) -> bool:
        """Return True only for globally routable, non-reserved addresses.

        This is an allowlist: anything that is not demonstrably public is
        refused. Blocked ranges are checked explicitly (they cover cases the
        stdlib flags miss, such as 100.64.0.0/10) and IPv4-in-IPv6 forms are
        unwrapped so they cannot be used to reach an internal address.
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if isinstance(addr, ipaddress.IPv6Address):
            embedded = _embedded_ipv4(addr)
            if embedded is not None and not self.is_public_ip(str(embedded)):
                return False
            if any(addr in net for net in BLOCKED_IPV6_NETWORKS):
                return False
        else:
            if any(addr in net for net in BLOCKED_IPV4_NETWORKS):
                return False

        return bool(addr.is_global)

    def is_private_ip(self, ip_str: str) -> bool:
        """Inverse of is_public_ip: True for anything not safe to connect to."""
        return not self.is_public_ip(ip_str)

    def validate_format(self, domain: str) -> None:
        try:
            ipaddress.ip_address(domain)
            raise DomainValidationError(
                "Scanning raw IP addresses is not permitted. Enter a public domain."
            )
        except ValueError:
            pass

        if self.is_blocked_hostname(domain):
            raise DomainValidationError(
                "Scanning private/internal domains is not permitted"
            )

        if not DOMAIN_REGEX.match(domain):
            raise DomainValidationError(
                "Invalid domain format. Please enter a valid domain (e.g., example.com)"
            )

    def resolve_public_addresses(self, domain: str) -> List[str]:
        """Resolve A/AAAA records and reject if any address is non-public."""
        # Defensive: this method is also called for redirect targets, so it must
        # refuse bare IP literals (e.g. a Location header pointing at 127.0.0.1)
        # rather than trusting the caller's format validation.
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            logger.warning("SSRF block: refusing literal address target %r", domain)
            raise DomainValidationError(
                "Scanning private/internal domains is not permitted"
            )

        addresses: List[str] = []
        errors: List[str] = []
        for family, label in (
            (socket.AF_INET, "A"),
            (socket.AF_INET6, "AAAA"),
        ):
            try:
                infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for info in infos:
                    ip = info[4][0]
                    if ip not in addresses:
                        addresses.append(ip)
            except socket.gaierror as exc:
                errors.append(f"{label}: {exc}")

        if not addresses:
            logger.warning("DNS resolution failed for %s: %s", domain, errors)
            raise DomainValidationError(
                f"Domain '{domain}' could not be resolved via public DNS"
            )

        private_hits = [ip for ip in addresses if self.is_private_ip(ip)]
        if private_hits:
            logger.warning(
                "SSRF block: %s resolved to non-public addresses %s", domain, private_hits
            )
            raise DomainValidationError(
                "Scanning private/internal domains is not permitted"
            )

        return addresses

    def ensure_public_ip(self, ip_str: str) -> str:
        """Re-validate an address immediately before opening a socket."""
        if self.is_private_ip(ip_str):
            logger.warning("SSRF block: refusing connect to non-public IP %s", ip_str)
            raise DomainValidationError(
                "Scanning private/internal domains is not permitted"
            )
        return ip_str

    def validate(self, raw: str, resolve_dns: bool = False) -> str:
        """Sanitize and validate a domain.

        Args:
            raw: User-supplied host or URL.
            resolve_dns: When True, also resolve DNS and block private IPs.
                         Use at scan execution time, not only on request parse,
                         so validation works offline in unit tests.
        """
        domain = self.sanitize(raw)
        self.validate_format(domain)
        if resolve_dns:
            self.resolve_public_addresses(domain)
        logger.info("Domain validated: %s (resolve_dns=%s)", domain, resolve_dns)
        return domain

    def validate_and_resolve(self, raw: str) -> tuple:
        """Validate a domain and return ``(domain, pinned_addresses)``.

        The returned addresses are the only addresses the scanner may connect
        to. Passing them downstream as ``pinned_ips`` closes the DNS-rebinding
        window between validation and connection.
        """
        domain = self.sanitize(raw)
        self.validate_format(domain)
        addresses = self.resolve_public_addresses(domain)
        logger.info(
            "Domain validated and pinned: %s -> %s", domain, addresses
        )
        return domain, addresses

    def preflight(self, raw: str, resolve_dns: bool = False) -> dict:
        """Return a structured validation result for the API (no scan started)."""
        domain = self.validate(raw, resolve_dns=False)
        payload = {
            "domain": domain,
            "valid": True,
            "message": "Domain is valid and eligible for scanning",
            "addresses": [],
            "dns_resolved": False,
        }
        if resolve_dns:
            addresses = self.resolve_public_addresses(domain)
            payload["addresses"] = addresses
            payload["dns_resolved"] = True
            payload["message"] = (
                f"Domain '{domain}' resolved to public address(es): {', '.join(addresses)}"
            )
            logger.info("Domain preflight resolved %s -> %s", domain, addresses)
        return payload


domain_validator = DomainValidator()
