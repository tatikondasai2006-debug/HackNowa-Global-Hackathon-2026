"""Unit tests for scanner modules and orchestrator."""

import pytest
from app.schemas.scan import ScanRequest
from app.scanner.orchestrator import DEFAULT_SCANNERS, ScanOrchestrator


def test_domain_validation_valid():
    """Test valid domain input validation."""
    req = ScanRequest(target_domain="example.com")
    assert req.target_domain == "example.com"

    req2 = ScanRequest(target_domain="https://security.example.org/path")
    assert req2.target_domain == "security.example.org"


def test_domain_validation_blocked_private_domains():
    """Test SSRF protection blocks localhost and private IPs.

    Raw IP literals are now rejected up-front by `validate_format`, so the
    rejection message differs from the private-range message used for hostnames.
    Either way the request must be refused.
    """
    with pytest.raises(ValueError, match="Scanning private/internal domains is not permitted"):
        ScanRequest(target_domain="localhost")

    # Raw IPv4 literals are rejected as such before the private-range check runs.
    with pytest.raises(ValueError, match="Scanning raw IP addresses is not permitted"):
        ScanRequest(target_domain="127.0.0.1")

    with pytest.raises(ValueError, match="Scanning raw IP addresses is not permitted"):
        ScanRequest(target_domain="192.168.1.1")

    # A private address disguised behind a hostname must still be refused.
    with pytest.raises(ValueError):
        ScanRequest(target_domain="internal.corp")


def test_scan_orchestrator_initialization():
    """Verify orchestrator setup."""
    orchestrator = ScanOrchestrator()
    # DEFAULT_SCANNERS covers tls, https, headers, dns, email_security, ports.
    assert len(orchestrator.scanners) == len(DEFAULT_SCANNERS) == 6
    assert {s.module_name for s in orchestrator.scanners} == {
        "tls",
        "https",
        "headers",
        "dns",
        "email_security",
        "ports",
    }
    assert orchestrator.get_total_checks() >= 20
