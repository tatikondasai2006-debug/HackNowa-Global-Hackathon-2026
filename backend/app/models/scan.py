"""Scan-related models: ScanJob, ScanResult, Finding, Recommendation."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, 
    ForeignKey, JSON, Enum as SQLEnum
)
import enum
from app.db.session import Base


class ScanStatus(str, enum.Enum):
    """Scan job lifecycle states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, enum.Enum):
    """Overall risk classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ScanJob(Base):
    """A security scan job targeting a specific domain."""

    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_domain = Column(String(255), nullable=False, index=True)
    target_url = Column(String(500), nullable=True)
    status = Column(
        String(20), default=ScanStatus.PENDING.value, nullable=False, index=True
    )
    
    # Progress tracking
    total_checks = Column(Integer, default=0, nullable=False)
    completed_checks = Column(Integer, default=0, nullable=False)
    failed_checks = Column(Integer, default=0, nullable=False)
    current_module = Column(String(100), nullable=True)
    
    # Results summary
    overall_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    score_breakdown = Column(JSON, nullable=True)
    passed_count = Column(Integer, default=0, nullable=False)
    warning_count = Column(Integer, default=0, nullable=False)
    failed_count = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Error information
    error_message = Column(Text, nullable=True)
    
    # AI-generated summary
    ai_summary = Column(Text, nullable=True)
    ai_recommendations = Column(Text, nullable=True)
    ai_explanation_payload = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ScanJob(id={self.id}, domain='{self.target_domain}', status='{self.status}')>"


class ScanResult(Base):
    """Individual scan check result (one per scanner module per scan)."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_job_id = Column(
        Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True
    )
    module_name = Column(String(100), nullable=False)  # e.g., "tls", "headers", "dns"
    check_name = Column(String(200), nullable=False)    # e.g., "SSL Certificate Valid"
    status = Column(String(20), nullable=False)         # "passed", "failed", "warning", "error", "info"
    severity = Column(String(20), nullable=True)
    
    # Result details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)              # Technical evidence
    technical_details = Column(JSON, nullable=True)     # Raw technical data
    
    # Scoring
    score_impact = Column(Float, default=0.0, nullable=False)
    max_score = Column(Float, default=0.0, nullable=False)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<ScanResult(id={self.id}, module='{self.module_name}', status='{self.status}')>"


class Finding(Base):
    """A security finding/issue discovered during scanning."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_job_id = Column(
        Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True
    )
    scan_result_id = Column(
        Integer, ForeignKey("scan_results.id"), nullable=True, index=True
    )
    
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    category = Column(String(100), nullable=False)      # e.g., "TLS", "Headers", "DNS"
    evidence = Column(Text, nullable=True)
    technical_details = Column(JSON, nullable=True)
    
    # Remediation
    recommendation = Column(Text, nullable=True)
    remediation_steps = Column(JSON, nullable=True)      # List of step strings
    reference_urls = Column(JSON, nullable=True)         # List of reference URLs
    
    # AI explanation
    ai_explanation = Column(Text, nullable=True)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<Finding(id={self.id}, title='{self.title[:50]}', severity='{self.severity}')>"


class Report(Base):
    """Generated security report for a scan."""

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_job_id = Column(
        Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    title = Column(String(500), nullable=False)
    format = Column(String(20), default="html", nullable=False)  # "html", "pdf"
    file_path = Column(String(500), nullable=True)
    
    # Report content stored as HTML
    content_html = Column(Text, nullable=True)
    
    # Executive summary
    executive_summary = Column(Text, nullable=True)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<Report(id={self.id}, scan_job_id={self.scan_job_id})>"


class AuditLog(Base):
    """Audit trail for security-relevant actions."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False)          # e.g., "scan.started", "report.generated"
    resource_type = Column(String(50), nullable=True)     # e.g., "scan_job", "report"
    resource_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}')>"
