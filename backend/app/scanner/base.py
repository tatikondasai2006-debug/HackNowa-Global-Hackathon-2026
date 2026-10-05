"""Base scanner module with common interface and utilities."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Sequence
from enum import Enum
import logging
import asyncio
import time

logger = logging.getLogger(__name__)


class CheckStatus(str, Enum):
    """Status of an individual security check."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    ERROR = "error"
    INFO = "info"


class CheckSeverity(str, Enum):
    """Severity level for a security finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CheckResult:
    """Result of a single security check."""
    module_name: str
    check_name: str
    title: str
    status: CheckStatus
    severity: Optional[CheckSeverity] = None
    description: str = ""
    evidence: str = ""
    technical_details: Optional[Dict[str, Any]] = None
    score_impact: float = 0.0
    max_score: float = 0.0
    recommendation: str = ""
    remediation_steps: Optional[List[str]] = None
    reference_urls: Optional[List[str]] = None


@dataclass
class ModuleResult:
    """Result from an entire scanner module."""
    module_name: str
    display_name: str
    checks: List[CheckResult] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: float = 0.0

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASSED)

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAILED)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARNING)

    @property
    def total_score(self) -> float:
        return sum(c.score_impact for c in self.checks)

    @property
    def max_possible_score(self) -> float:
        return sum(c.max_score for c in self.checks)


class BaseScanner(ABC):
    """Abstract base class for all scanner modules.

    Each scanner module must:
    1. Define a unique module_name
    2. Implement the scan() method
    3. Return structured CheckResults
    4. Handle all errors gracefully (never crash the scan)
    5. Respect timeout constraints
    """

    module_name: str = "base"
    display_name: str = "Base Scanner"
    timeout: int = 30

    @abstractmethod
    async def scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        """Perform security checks on the target domain.

        Args:
            domain: The validated domain to scan (e.g., "example.com")
            pinned_ips: Public IPs already validated for SSRF; connect to these
                instead of re-resolving the hostname.

        Returns:
            ModuleResult containing all check results
        """
        raise NotImplementedError

    async def safe_scan(
        self, domain: str, pinned_ips: Optional[Sequence[str]] = None
    ) -> ModuleResult:
        """Execute scan with timeout protection and error handling.

        Wraps the scan() method to ensure it never crashes the overall scan.
        """
        start_time = time.time()
        try:
            result = await asyncio.wait_for(
                self.scan(domain, pinned_ips=pinned_ips), timeout=self.timeout
            )
            result.duration_ms = (time.time() - start_time) * 1000
            return result
        except asyncio.TimeoutError:
            logger.warning(
                f"Scanner module '{self.module_name}' timed out after {self.timeout}s "
                f"for domain '{domain}'"
            )
            return ModuleResult(
                module_name=self.module_name,
                display_name=self.display_name,
                error=f"Module timed out after {self.timeout} seconds",
                duration_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            logger.error(
                f"Scanner module '{self.module_name}' failed for domain '{domain}': {e}",
                exc_info=True,
            )
            return ModuleResult(
                module_name=self.module_name,
                display_name=self.display_name,
                error=f"Module encountered an error: {str(e)}",
                duration_ms=(time.time() - start_time) * 1000,
            )
