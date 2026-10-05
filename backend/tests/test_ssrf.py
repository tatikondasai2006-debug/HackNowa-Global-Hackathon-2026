"""SSRF regression tests.

Covers the outbound-request hardening:
  * loopback / private / link-local / CGNAT / reserved IPv4 and IPv6 rejection
  * IPv4-in-IPv6 smuggling (mapped, 6to4, Teredo, NAT64)
  * hostnames and bare literals that point at internal space
  * DNS that resolves to a private address
  * redirects that try to escape to a prohibited target
  * the scan path actually pinning the validated IPs (DNS-rebinding defence)
  * legitimate public targets still working

The address policy is an allowlist: only globally routable addresses pass.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import httpx
import pytest

from app.core.exceptions import DomainValidationError
from app.scanner.pinned_connect import (
    connect_socket,
    pick_connect_ip,
    pinned_http_get,
    resolve_pinned_ips,
    tcp_connect_open,
)
from app.services.domain_validation import domain_validator


# --------------------------------------------------------------------------
# Address policy: everything non-public must be refused
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "address",
    [
        # loopback
        "127.0.0.1",
        "127.1.2.3",
        # RFC1918 private
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.1.1",
        # link-local, including the cloud metadata endpoint
        "169.254.0.1",
        "169.254.169.254",
        # CGNAT / shared address space (is_private == False in the stdlib)
        "100.64.0.1",
        "100.127.255.254",
        # IETF / documentation / benchmarking / reserved
        "0.0.0.0",
        "0.1.2.3",
        "192.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "192.88.99.1",
        # multicast / reserved / broadcast
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
    ],
)
def test_private_ipv4_is_blocked(address):
    assert domain_validator.is_private_ip(address) is True
    assert domain_validator.is_public_ip(address) is False


@pytest.mark.parametrize(
    "address",
    [
        "::1",
        "::",
        "fc00::1",  # unique local
        "fd00::1",
        "fdff::1",
        "fe80::1",  # link-local
        "fe80::a00:27ff:fe4e:66a1",
        "ff02::1",  # multicast
        "ff05::1",
        "2001:db8::1",  # documentation
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "::ffff:169.254.169.254",  # IPv4-mapped metadata
        "64:ff9b::7f00:1",  # NAT64 wrapping 127.0.0.1
        "64:ff9b::0a00:1",  # NAT64 wrapping 10.0.0.1
        "2002:7f00:0001::1",  # 6to4 wrapping 127.0.0.1
        "2001:0000:4136:e378::1",  # Teredo
    ],
)
def test_private_ipv6_is_blocked(address):
    assert domain_validator.is_private_ip(address) is True
    assert domain_validator.is_public_ip(address) is False


@pytest.mark.parametrize(
    "address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]
)
def test_public_addresses_are_allowed(address):
    """The allowlist must not block legitimate public targets."""
    assert domain_validator.is_public_ip(address) is True
    assert domain_validator.is_private_ip(address) is False


def test_unparseable_address_is_not_public():
    assert domain_validator.is_public_ip("not-an-ip") is False


def test_ensure_public_ip_rejects_private():
    with pytest.raises(DomainValidationError):
        domain_validator.ensure_public_ip("127.0.0.1")


def test_ensure_public_ip_returns_public():
    assert domain_validator.ensure_public_ip("8.8.8.8") == "8.8.8.8"


# --------------------------------------------------------------------------
# Hostname and literal rejection
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "sub.localhost",
        "foo.local",
        "foo.internal",
        "foo.corp",
        "foo.lan",
        "foo.home.arpa",
        "foo.in-addr.arpa",
        "foo.ip6.arpa",
    ],
)
def test_internal_hostnames_are_blocked(host):
    with pytest.raises(DomainValidationError, match="private/internal"):
        domain_validator.validate_format(domain_validator.sanitize(host))


@pytest.mark.parametrize(
    "literal",
    ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "100.64.0.1", "1.1.1.1"],
)
def test_raw_ip_literals_are_blocked(literal):
    """Bare literals are refused regardless of how the value was smuggled in."""
    with pytest.raises(DomainValidationError, match="raw IP addresses"):
        domain_validator.validate_format(domain_validator.sanitize(literal))


@pytest.mark.parametrize(
    "smuggled",
    [
        "http://127.0.0.1/admin",
        "https://169.254.169.254/latest/meta-data/",
        "http://user:pass@10.0.0.5/",
        "http://[::1]:8080/",
        "2130706433",  # decimal-encoded 127.0.0.1
        "0x7f000001",  # hex-encoded 127.0.0.1
    ],
)
def test_ssrf_smuggling_via_url_syntax_is_blocked(smuggled):
    with pytest.raises(DomainValidationError):
        domain_validator.validate_format(domain_validator.sanitize(smuggled))


def test_sanitize_preserves_legitimate_input():
    assert domain_validator.sanitize("https://Example.COM/path?q=1#f") == "example.com"
    assert domain_validator.sanitize("  example.com.  ") == "example.com"


# --------------------------------------------------------------------------
# DNS resolution
# --------------------------------------------------------------------------

def test_dns_resolving_to_private_ipv4_is_blocked():
    """A public-looking hostname that resolves internally must be refused."""
    with patch.object(
        domain_validator,
        "resolve_public_addresses",
        wraps=domain_validator.resolve_public_addresses,
    ):
        original = socket.getaddrinfo

        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "rebind.test":
                return original("169.254.169.254", port, *args, **kwargs)
            if host == "cgnat.test":
                return original("100.64.0.1", port, *args, **kwargs)
            if host == "v6.test":
                return original("::ffff:10.0.0.1", port, *args, **kwargs)
            return original(host, port, *args, **kwargs)

        with patch("app.services.domain_validation.socket.getaddrinfo", fake_getaddrinfo):
            for host in ("rebind.test", "cgnat.test", "v6.test"):
                with pytest.raises(DomainValidationError, match="private/internal"):
                    domain_validator.resolve_public_addresses(host)


def test_literal_target_is_refused_by_resolver():
    """A redirect to a literal address must not bypass validation."""
    for literal in ("127.0.0.1", "169.254.169.254", "10.0.0.1"):
        with pytest.raises(DomainValidationError, match="private/internal"):
            domain_validator.resolve_public_addresses(literal)


def test_unresolvable_domain_is_rejected():
    with patch(
        "app.services.domain_validation.socket.getaddrinfo",
        side_effect=socket.gaierror("nope"),
    ):
        with pytest.raises(DomainValidationError, match="could not be resolved"):
            domain_validator.resolve_public_addresses("does-not-exist.invalid")


def test_public_domain_resolves_to_public_addresses():
    """Sanity check that the allowlist permits ordinary public DNS."""
    addresses = domain_validator.resolve_public_addresses("example.com")
    assert addresses
    assert all(domain_validator.is_public_ip(ip) for ip in addresses)


def test_validate_and_resolve_returns_pinned_addresses():
    domain, pinned = domain_validator.validate_and_resolve("example.com")
    assert domain == "example.com"
    assert pinned
    assert all(domain_validator.is_public_ip(ip) for ip in pinned)


# --------------------------------------------------------------------------
# Connection layer: never connect to a bare hostname
# --------------------------------------------------------------------------

def test_pick_connect_ip_requires_addresses():
    with pytest.raises(DomainValidationError):
        pick_connect_ip([])


def test_pick_connect_ip_refuses_private_pinned_address():
    with pytest.raises(DomainValidationError):
        pick_connect_ip(["127.0.0.1"])


def test_pick_connect_ip_prefers_ipv4():
    assert pick_connect_ip(["2606:4700::1111", "93.184.216.34"]) == "93.184.216.34"


def test_resolve_pinned_ips_revalidates_pins():
    with pytest.raises(DomainValidationError):
        resolve_pinned_ips("example.com", ["169.254.169.254"])


def test_resolve_pinned_ips_validates_when_no_pins_supplied():
    """Without pins the hostname is resolved and validated before connecting."""
    with patch(
        "app.services.domain_validation.socket.getaddrinfo",
        side_effect=socket.gaierror("nope"),
    ):
        with pytest.raises(DomainValidationError, match="could not be resolved"):
            resolve_pinned_ips("example.com", None)


def test_connect_socket_refuses_private_pin_without_dialling():
    with patch("app.scanner.pinned_connect.socket.create_connection") as create:
        with pytest.raises(DomainValidationError):
            connect_socket("example.com", 443, ["10.0.0.1"])
    create.assert_not_called()


def test_connect_socket_dials_the_pinned_ip_not_the_hostname():
    with patch(
        "app.scanner.pinned_connect.socket.create_connection",
        return_value="sock",
    ) as create:
        connect_socket("example.com", 443, ["93.184.216.34"])
    create.assert_called_once()
    assert create.call_args[0][0][0] == "93.184.216.34"


def test_tcp_connect_open_refuses_private_pin():
    """A blocked pin must abort before any socket is created.

    The port scanner treats the raised DomainValidationError as "not open",
    which is correct: the probe is refused rather than reported.
    """
    with patch("app.scanner.pinned_connect.socket.socket") as sock:
        with pytest.raises(DomainValidationError, match="private/internal"):
            tcp_connect_open("example.com", 443, ["127.0.0.1"])
    sock.assert_not_called()


def test_tcp_connect_open_dials_pinned_ip():
    with patch("app.scanner.pinned_connect.socket.socket") as sock:
        sock.return_value.connect_ex.return_value = 0
        assert tcp_connect_open("example.com", 443, ["93.184.216.34"]) is True
    assert sock.return_value.connect_ex.call_args[0][0][0] == "93.184.216.34"


# --------------------------------------------------------------------------
# Redirects
# --------------------------------------------------------------------------

def _redirect_response(status, location=None):
    headers = {"location": location} if location else {}
    return httpx.Response(status, headers=headers, request=httpx.Request("GET", "https://x/"))


def _mock_get(*responses):
    calls = []

    async def fake_get(self, url, **kwargs):
        calls.append((url, kwargs.get("headers", {}).get("Host"), kwargs))
        return responses[min(len(calls) - 1, len(responses) - 1)]

    return fake_get, calls


@pytest.mark.asyncio
async def test_redirect_to_non_http_scheme_is_refused():
    """file://, gopher:// and friends must not be followed."""
    fake_get, calls = _mock_get(_redirect_response(302, "file:///etc/passwd"))
    with patch.object(httpx.AsyncClient, "get", fake_get):
        response = await pinned_http_get(
            "example.com", pinned_ips=["93.184.216.34"], follow_redirects=True
        )
    assert response.status_code == 302
    assert len(calls) == 1, "redirect was followed"


@pytest.mark.asyncio
async def test_redirect_to_private_literal_is_refused():
    """A Location header pointing at the metadata IP must not be followed."""
    fake_get, calls = _mock_get(
        _redirect_response(302, "http://169.254.169.254/latest/meta-data/")
    )
    with patch.object(httpx.AsyncClient, "get", fake_get):
        with pytest.raises(DomainValidationError, match="private/internal"):
            await pinned_http_get(
                "example.com", pinned_ips=["93.184.216.34"], follow_redirects=True
            )
    assert len(calls) == 1, "redirect was followed"


@pytest.mark.asyncio
async def test_redirect_to_host_resolving_private_is_refused():
    """A redirect to a hostname that resolves internally must be refused."""
    original = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "internal.test":
            return original("10.0.0.7", port, *args, **kwargs)
        return original(host, port, *args, **kwargs)

    fake_get, _ = _mock_get(_redirect_response(301, "https://internal.test/secret"))
    with patch.object(httpx.AsyncClient, "get", fake_get):
        with patch(
            "app.services.domain_validation.socket.getaddrinfo", fake_getaddrinfo
        ):
            with pytest.raises(DomainValidationError, match="private/internal"):
                await pinned_http_get(
                    "example.com", pinned_ips=["93.184.216.34"], follow_redirects=True
                )


@pytest.mark.asyncio
async def test_legitimate_redirect_to_public_host_is_followed():
    """Normal redirects must keep working."""
    original = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "www.example.com":
            return original("93.184.216.34", port, *args, **kwargs)
        return original(host, port, *args, **kwargs)

    fake_get, calls = _mock_get(
        _redirect_response(301, "https://www.example.com/home"),
        httpx.Response(200, request=httpx.Request("GET", "https://www.example.com/home")),
    )
    with patch.object(httpx.AsyncClient, "get", fake_get):
        with patch(
            "app.services.domain_validation.socket.getaddrinfo", fake_getaddrinfo
        ):
            response = await pinned_http_get(
                "example.com", pinned_ips=["93.184.216.34"], follow_redirects=True
            )
    assert response.status_code == 200
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_pinned_request_sends_original_host_header_and_sni():
    """Pinning the IP must not break Host/SNI for virtual-hosted sites."""
    fake_get, calls = _mock_get(httpx.Response(200, request=httpx.Request("GET", "https://x/")))
    with patch.object(httpx.AsyncClient, "get", fake_get):
        await pinned_http_get("example.com", pinned_ips=["93.184.216.34"])
    url, host_header, kwargs = calls[0]
    assert url.startswith("https://93.184.216.34")
    assert host_header == "example.com"
    assert kwargs["extensions"]["sni_hostname"] == "example.com"


# --------------------------------------------------------------------------
# The scan path must actually use the pins
# --------------------------------------------------------------------------

def test_orchestrator_forwards_pinned_ips_to_every_scanner():
    """Regression guard: the validated IPs must reach the scanner modules."""
    import asyncio

    from app.scanner.base import ModuleResult
    from app.scanner.orchestrator import ScanOrchestrator

    seen = {}

    class Recorder:
        module_name = "recorder"
        display_name = "Recorder"
        timeout = 5

        async def scan(self, domain, pinned_ips=None):
            seen[domain] = pinned_ips
            return ModuleResult(module_name="recorder", display_name="Recorder")

        async def safe_scan(self, domain, pinned_ips=None):
            return await self.scan(domain, pinned_ips=pinned_ips)

    orchestrator = ScanOrchestrator(scanners=[Recorder()])
    asyncio.run(
        orchestrator.run_scan("example.com", pinned_ips=["93.184.216.34"])
    )
    assert seen["example.com"] == ["93.184.216.34"]
