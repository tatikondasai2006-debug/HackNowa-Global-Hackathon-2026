"""Scan-related Pydantic schemas for request/response validation."""

from datetime import datetime
from typing import Annotated, Optional, List, Dict, Any
from fastapi import Path
from pydantic import BaseModel, Field, field_validator, ConfigDict

from app.core.exceptions import DomainValidationError
from app.services.domain_validation import domain_validator


# Largest value a signed 64-bit `INTEGER` primary key can hold. An unbounded
# Python int arriving from a path segment (e.g. 400 digits) cannot be bound by
# the SQLite driver and raises OverflowError from inside the query, which
# nothing handled, so the request answered 500. Bounding the parameter rejects
# it during validation instead.
RESOURCE_ID_MAX = 2**63 - 1

#: Path-parameter type for any resource id that will be used in a query.
ResourceId = Annotated[int, Path(ge=1, le=RESOURCE_ID_MAX)]


class ScanRequest(BaseModel):
    """Schema for initiating a new scan."""
    target_domain: str = Field(..., min_length=3, max_length=255)
    scan_options: Optional[Dict[str, bool]] = Field(
        default=None,
        description="Optional scan module toggles (e.g., {'tls': true, 'headers': true})"
    )
    authorization_confirmed: bool = Field(
        default=False,
        description=(
            "Must be true. The submitting user confirms they own the target or "
            "otherwise have explicit written permission to assess it. Enforced "
            "server-side and recorded in the audit log."
        ),
    )

    @field_validator("target_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        try:
            return domain_validator.validate(v, resolve_dns=False)
        except DomainValidationError as exc:
            raise ValueError(str(exc)) from exc


class DomainValidateRequest(BaseModel):
    """Pre-flight domain validation without starting a scan."""
    target_domain: str = Field(..., min_length=3, max_length=255)
    resolve_dns: bool = Field(
        default=False,
        description="When true, resolve A/AAAA and reject private/internal targets",
    )

    @field_validator("target_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        try:
            return domain_validator.validate(v, resolve_dns=False)
        except DomainValidationError as exc:
            raise ValueError(str(exc)) from exc


class DomainValidateResponse(BaseModel):
    domain: str
    valid: bool = True
    message: str = "Domain is valid and eligible for scanning"
    addresses: List[str] = []
    dns_resolved: bool = False


class ScanResultResponse(BaseModel):
    """Schema for an individual scan check result."""
    id: int
    module_name: str
    check_name: str
    status: str
    severity: Optional[str] = None
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    technical_details: Optional[Dict[str, Any]] = None
    score_impact: float
    max_score: float
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    """Schema for a security finding."""
    id: int
    title: str
    description: str
    severity: str
    category: str
    evidence: Optional[str] = None
    technical_details: Optional[Dict[str, Any]] = None
    recommendation: Optional[str] = None
    remediation_steps: Optional[List[str]] = None
    reference_urls: Optional[List[str]] = None
    ai_explanation: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanScoreSummary(BaseModel):
    score: Optional[float] = None
    risk_level: Optional[str] = None


class AIExplanationDetail(BaseModel):
    title: str
    explanation: str = ""
    why_it_matters: str = ""
    impact: str = ""
    remediation: List[str] = []
    severity: Optional[str] = None


class AIExplanationResponse(BaseModel):
    available: bool = False
    summary: str
    details: List[AIExplanationDetail] = []


class RecommendationItem(BaseModel):
    finding_id: int
    title: str
    severity: str
    category: str
    recommendation: Optional[str] = None
    remediation_steps: List[str] = []
    reference_urls: List[str] = []


class ScanJobResponse(BaseModel):
    """Schema for scan job data in API responses."""
    id: int
    user_id: int
    target_domain: str
    target_url: Optional[str] = None
    status: str
    total_checks: int
    completed_checks: int
    failed_checks: int
    current_module: Optional[str] = None
    overall_score: Optional[float] = None
    risk_level: Optional[str] = None
    passed_count: int
    warning_count: int
    failed_count: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_recommendations: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanJobDetailResponse(ScanJobResponse):
    """Detailed scan job response including results, findings, and AI explanation."""
    results: List[ScanResultResponse] = []
    findings: List[FindingResponse] = []
    score_breakdown: Optional[Dict[str, Any]] = None
    scan: Optional[ScanScoreSummary] = None
    recommendations: List[RecommendationItem] = []
    ai_explanation: Optional[AIExplanationResponse] = None


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    scans: List[ScanJobResponse]
    total: int
    page: int
    page_size: int
    domain: Optional[str] = None
    status: Optional[str] = None


class RecommendationResponse(BaseModel):
    scan_id: int
    target_domain: str
    overall_score: Optional[float] = None
    risk_level: Optional[str] = None
    status: str
    is_complete: bool
    summary: str
    priority_count: int
    recommendations: List[RecommendationItem]


class ScanCompareRequest(BaseModel):
    scan_id_a: int = Field(..., ge=1)
    scan_id_b: int = Field(..., ge=1)


class ScanCompareDelta(BaseModel):
    check_name: str
    title: str
    module_name: str
    status_a: Optional[str] = None
    status_b: Optional[str] = None
    score_a: Optional[float] = None
    score_b: Optional[float] = None


class ScanCompareResponse(BaseModel):
    scan_a: ScanJobResponse
    scan_b: ScanJobResponse
    score_delta: Optional[float] = None
    findings_added: List[str] = []
    findings_resolved: List[str] = []
    check_deltas: List[ScanCompareDelta] = []


class ReportGenerateRequest(BaseModel):
    format: str = Field(default="html", pattern="^(html|pdf)$")


class ScanStatusResponse(BaseModel):
    """Lightweight scan status for polling."""
    id: int
    status: str
    completed_checks: int
    total_checks: int
    failed_checks: int
    current_module: Optional[str] = None
    overall_score: Optional[float] = None
    risk_level: Optional[str] = None


class ReportResponse(BaseModel):
    """Schema for report metadata."""
    id: int
    scan_job_id: int
    title: str
    format: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    """List of reports."""
    reports: List[ReportResponse]
    total: int


class DashboardStats(BaseModel):
    """Dashboard statistics for the user."""
    total_scans: int
    completed_scans: int
    average_score: Optional[float] = None
    domains_scanned: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    recent_scans: List[ScanJobResponse]
    score_trend: List[Dict[str, Any]] = []


class AIExplainRequest(BaseModel):
    """Request for AI explanation of findings."""
    scan_job_id: int
    finding_ids: Optional[List[int]] = None


class AIExplainResponse(BaseModel):
    """AI-generated explanation response."""
    explanation: str
    recommendations: List[str]
    is_ai_generated: bool = True
    model_used: Optional[str] = None
    available: bool = False
    summary: str = ""
    details: List[AIExplanationDetail] = []


class RAGQueryRequest(BaseModel):
    """Request for RAG-based cybersecurity Q&A."""
    question: str = Field(..., min_length=5, max_length=1000)
    scan_job_id: Optional[int] = None


class RAGQueryResponse(BaseModel):
    """RAG-based Q&A response."""
    answer: str
    sources: List[Dict[str, str]] = []
    is_ai_generated: bool = True
    scan_context_used: bool = False
