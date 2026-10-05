"""Connect to previously validated public IPs (SSRF / DNS-rebinding defense).

Scanners must not re-resolve the user-supplied hostname at connect time.
Use the IPs from DomainValidator.resolve_public_addresses, re-check that they
are still public, then connect to the IP with SNI/Host set to the original
hostname.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List, Optional, Sequence
from urllib.parse import urljoin, urlparse

import httpx

from app.core.exceptions import DomainValidationError
from app.services.domain_validation import domain_validator

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("http", "https")


def pick_connect_ip(pinned_ips: Sequence[str]) -> str:
    """Choose a validated public IP, preferring IPv4.

    Raises DomainValidationError if no usable public address remains, so a
    caller can never silently fall through to a prohibited target.
    """
    if not pinned_ips:
        raise DomainValidationError(
            "No validated public addresses available for this scan"
        )
    for ip in pinned_ips:
        try:
            if ipaddress.ip_address(ip).version == 4:
                domain_validator.ensure_public_ip(ip)
                return ip
        except ValueError:
            continue
    ip = pinned_ips[0]
    domain_validator.ensure_public_ip(ip)
    return ip


def resolve_pinned_ips(
    host: str, pinned_ips: Optional[Sequence[str]] = None
) -> List[str]:
    """Return validated public addresses for a connection attempt.

    When the caller already resolved and validated the target (the normal scan
    path), those pinned addresses are reused. Otherwise the hostname is
    resolved *here*, immediately before connecting, and validated. Either way
    the socket is opened against an IP address, never a hostname, so the
    address that was validated is the address that gets connected to and a
    DNS-rebinding answer cannot be swapped in afterwards.
    """
    if pinned_ips:
        for ip in pinned_ips:
            domain_validator.ensure_public_ip(ip)
        return list(pinned_ips)
    return domain_validator.resolve_public_addresses(host)


def format_ip_for_url(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return f"[{ip}]"
    return ip


def connect_socket(
    domain: str,
    port: int,
    pinned_ips: Optional[Sequence[str]],
    timeout: float = 10,
):
    """TCP connect to a pre-validated public IP (never to a bare hostname)."""
    ips = resolve_pinned_ips(domain, pinned_ips)
    ip = pick_connect_ip(ips)
    return socket.create_connection((ip, port), timeout=timeout)


def tcp_connect_open(
    host: str, port: int, pinned_ips: Optional[Sequence[str]] = None, timeout: float = 2
) -> bool:
    target = pick_connect_ip(resolve_pinned_ips(host, pinned_ips))
    domain_validator.ensure_public_ip(target)
    family = socket.AF_INET6 if ":" in target and "." not in target else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex((target, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


async def pinned_http_get(
    domain: str,
    *,
    pinned_ips: Optional[Sequence[str]] = None,
    scheme: str = "https",
    path: str = "/",
    follow_redirects: bool = False,
    verify: bool = True,
    timeout: float = 10,
    max_redirects: int = 5,
) -> httpx.Response:
    """HTTP GET that connects to a validated public IP.

    Redirects are followed manually so every hop is re-validated. A redirect
    to a non-http(s) scheme, to a literal address, or to a host that resolves
    to a non-public address is refused rather than followed.
    """
    current_host = domain
    current_ips: Optional[List[str]] = resolve_pinned_ips(domain, pinned_ips)
    current_scheme = scheme
    current_path = path or "/"
    last: Optional[httpx.Response] = None

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, verify=verify) as client:
        for _ in range(max_redirects + 1):
            if current_ips:
                ip = pick_connect_ip(current_ips)
                url = f"{current_scheme}://{format_ip_for_url(ip)}{current_path}"
                headers = {"Host": current_host}
                extensions = {"sni_hostname": current_host} if current_scheme == "https" else {}
            else:
                url = f"{current_scheme}://{current_host}{current_path}"
                headers = {}
                extensions = {}

            last = await client.get(url, headers=headers, extensions=extensions)
            if not follow_redirects or last.status_code not in (301, 302, 303, 307, 308):
                return last

            location = last.headers.get("location")
            if not location:
                return last

            resolved = urlparse(urljoin(f"{current_scheme}://{current_host}{current_path}", location))
            if not resolved.hostname:
                return last

            next_scheme = (resolved.scheme or current_scheme).lower()
            if next_scheme not in ALLOWED_SCHEMES:
                logger.warning(
                    "SSRF block: refusing redirect from %s to non-http scheme %r",
                    current_host,
                    next_scheme,
                )
                return last

            next_host = resolved.hostname.lower()
            current_scheme = next_scheme
            current_path = resolved.path or "/"
            if resolved.query:
                current_path = f"{current_path}?{resolved.query}"

            if next_host != current_host:
                current_host = next_host
                # Re-validate the new hop: literal addresses and hosts that
                # resolve to non-public space are refused by
                # resolve_public_addresses.
                current_ips = domain_validator.resolve_public_addresses(current_host)

        return last
