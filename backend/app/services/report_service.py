"""Report persistence and HTML/PDF generation service."""

from __future__ import annotations

import io
import logging
import os
from typing import List, Optional, Tuple

from fpdf import FPDF
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    ReportGenerationError,
    ReportNotFoundError,
    ScanNotCompleteError,
    ScanNotFoundError,
)
from app.models.scan import Finding, Report, ScanJob, ScanResult, ScanStatus
from app.reports.report_generator import report_generator
from app.scanner.scoring import get_score_description

logger = logging.getLogger(__name__)


class _PdfReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(15, 23, 42)
        self.cell(0, 8, "CyberSentinel Security Assessment", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}  |  Defensive assessment only", align="C")

    def multi_cell(self, w, h, text="", *args, **kwargs):
        """Default `new_x` to the left margin.

        fpdf2 defaults `new_x` to XPos.RIGHT, which parks the cursor on the
        right margin after every full-width cell. A following full-width
        `multi_cell` then has zero horizontal space and raises
        "Not enough horizontal space to render a single character".
        """
        if kwargs.get("new_x") is None:
            kwargs["new_x"] = "LMARGIN"
        return super().multi_cell(w, h, text, *args, **kwargs)


def _safe(text: Optional[str]) -> str:
    if not text:
        return ""
    return (
        str(text)
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


class ReportService:
    """Creates and retrieves HTML/PDF reports without putting logic in routes."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _owned_scan(self, scan_id: int, user_id: int) -> ScanJob:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_id, ScanJob.user_id == user_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise ScanNotFoundError("Scan not found")
        return scan

    async def _results_and_findings(
        self, scan_id: int
    ) -> Tuple[List[ScanResult], List[Finding]]:
        results = list(
            (
                await self.db.execute(
                    select(ScanResult)
                    .where(ScanResult.scan_job_id == scan_id)
                    .order_by(ScanResult.id)
                )
            ).scalars().all()
        )
        findings = list(
            (
                await self.db.execute(
                    select(Finding)
                    .where(Finding.scan_job_id == scan_id)
                    .order_by(Finding.id)
                )
            ).scalars().all()
        )
        return results, findings

    def render_html(
        self, scan: ScanJob, results: List[ScanResult], findings: List[Finding]
    ) -> str:
        return report_generator.generate_html_report(scan, results, findings)

    def render_pdf(
        self, scan: ScanJob, results: List[ScanResult], findings: List[Finding]
    ) -> bytes:
        try:
            pdf = _PdfReport()
            pdf.alias_nb_pages()
            pdf.set_auto_page_break(auto=True, margin=18)
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.multi_cell(0, 8, _safe(f"Target: {scan.target_domain}"))
            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(
                0,
                6,
                _safe(
                    f"Score: {scan.overall_score or 0:.1f}/100    "
                    f"Risk: {scan.risk_level or 'n/a'}    "
                    f"Scan ID: #{scan.id}"
                ),
            )
            pdf.ln(2)
            pdf.multi_cell(
                0,
                6,
                _safe(get_score_description(scan.overall_score or 0.0)),
            )
            pdf.ln(2)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(
                0,
                6,
                _safe(
                    f"Passed {scan.passed_count}  |  Warnings {scan.warning_count}  |  "
                    f"Failed {scan.failed_count}"
                ),
            )

            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Priority Findings", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            if not findings:
                pdf.multi_cell(0, 6, "No failed or warning findings were recorded.")
            for finding in findings:
                pdf.set_font("Helvetica", "B", 11)
                pdf.multi_cell(0, 6, _safe(f"[{finding.severity.upper()}] {finding.title}"))
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 5, _safe(finding.description or ""))
                if finding.evidence:
                    pdf.set_text_color(14, 116, 144)
                    pdf.multi_cell(0, 5, _safe(f"Evidence: {finding.evidence}"))
                    pdf.set_text_color(0, 0, 0)
                if finding.recommendation:
                    pdf.multi_cell(0, 5, _safe(f"Fix: {finding.recommendation}"))
                pdf.ln(2)

            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Check Results", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for row in results:
                pdf.multi_cell(
                    0,
                    5,
                    _safe(
                        f"{row.module_name} | {row.title} | {row.status} | "
                        f"{row.score_impact}/{row.max_score}"
                    ),
                )

            pdf.ln(6)
            pdf.set_font("Helvetica", "I", 8)
            pdf.multi_cell(
                0,
                5,
                "Disclaimer: Passive, non-invasive observation of public services only. "
                "Not a penetration test or a guarantee of security.",
            )
            buffer = io.BytesIO()
            pdf.output(buffer)
            return buffer.getvalue()
        except Exception as exc:
            logger.exception("PDF generation failed for scan_id=%s", scan.id)
            raise ReportGenerationError("Failed to generate PDF report") from exc

    async def generate_report(
        self, scan_id: int, user_id: int, fmt: str = "html"
    ) -> Report:
        scan = await self._owned_scan(scan_id, user_id)
        if scan.status != ScanStatus.COMPLETED.value:
            raise ScanNotCompleteError("Cannot generate report for an incomplete scan")

        results, findings = await self._results_and_findings(scan_id)
        fmt = (fmt or "html").lower()
        if fmt not in {"html", "pdf"}:
            raise ReportGenerationError(f"Unsupported report format: {fmt}")

        html_content = self.render_html(scan, results, findings)
        file_path = None
        if fmt == "pdf":
            os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
            pdf_bytes = self.render_pdf(scan, results, findings)
            file_path = os.path.join(
                settings.REPORT_OUTPUT_DIR, f"scan_{scan.id}.pdf"
            )
            with open(file_path, "wb") as handle:
                handle.write(pdf_bytes)

        report = Report(
            scan_job_id=scan.id,
            user_id=user_id,
            title=f"Security Assessment Report — {scan.target_domain}",
            format=fmt,
            content_html=html_content,
            file_path=file_path,
            executive_summary=scan.ai_summary,
        )
        self.db.add(report)
        await self.db.flush()
        await self.db.refresh(report)
        logger.info("Report generated id=%s scan_id=%s format=%s", report.id, scan_id, fmt)
        return report

    async def get_report(self, report_id: int, user_id: int) -> Report:
        result = await self.db.execute(
            select(Report).where(Report.id == report_id, Report.user_id == user_id)
        )
        report = result.scalar_one_or_none()
        if not report:
            raise ReportNotFoundError("Report not found")
        return report

    async def html_for_scan(self, scan_id: int, user_id: int) -> str:
        scan = await self._owned_scan(scan_id, user_id)
        results, findings = await self._results_and_findings(scan_id)
        return self.render_html(scan, results, findings)

    async def pdf_bytes_for_scan(self, scan_id: int, user_id: int) -> bytes:
        scan = await self._owned_scan(scan_id, user_id)
        if scan.status != ScanStatus.COMPLETED.value:
            raise ScanNotCompleteError("Cannot generate report for an incomplete scan")
        results, findings = await self._results_and_findings(scan_id)
        return self.render_pdf(scan, results, findings)

    async def pdf_bytes_for_report(self, report_id: int, user_id: int) -> bytes:
        report = await self.get_report(report_id, user_id)
        if report.file_path and os.path.isfile(report.file_path):
            with open(report.file_path, "rb") as handle:
                return handle.read()
        scan = await self._owned_scan(report.scan_job_id, user_id)
        results, findings = await self._results_and_findings(scan.id)
        return self.render_pdf(scan, results, findings)

    async def list_reports(
        self, user_id: int, page: int = 1, page_size: int = 20
    ) -> Tuple[List[Report], int]:
        total = (
            await self.db.execute(
                select(func.count(Report.id)).where(Report.user_id == user_id)
            )
        ).scalar() or 0
        offset = (page - 1) * page_size
        rows = (
            await self.db.execute(
                select(Report)
                .where(Report.user_id == user_id)
                .order_by(desc(Report.created_at))
                .offset(offset)
                .limit(page_size)
            )
        ).scalars().all()
        return list(rows), total
