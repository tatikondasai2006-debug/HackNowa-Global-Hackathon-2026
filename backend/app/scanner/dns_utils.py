"""Shared DNS lookup helpers used by scanner modules."""

from typing import List, Optional

import dns.resolver


def make_resolver(timeout: float = 5.0, lifetime: float = 10.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def txt_to_string(rdata) -> str:
    """Join possibly-split TXT character-strings into one record."""
    if hasattr(rdata, "strings"):
        parts = []
        for part in rdata.strings:
            if isinstance(part, bytes):
                parts.append(part.decode("utf-8", errors="replace"))
            else:
                parts.append(str(part))
        return "".join(parts)
    return str(rdata).strip('"').replace('" "', "")


def resolve_records(domain: str, rdtype: str, timeout: float = 5.0) -> List:
    resolver = make_resolver(timeout=timeout, lifetime=timeout * 2)
    return list(resolver.resolve(domain, rdtype))


def try_resolve(domain: str, rdtype: str, timeout: float = 5.0) -> Optional[List]:
    try:
        return resolve_records(domain, rdtype, timeout=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None
