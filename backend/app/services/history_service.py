"""Scan history comparison — posture changes between two completed scans."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ScanNotFoundError
from app.models.scan import ScanResult
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)


class HistoryService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.scans = ScanService(db)

    async def compare_scans(
        self, user_id: int, scan_id_a: int, scan_id_b: int
    ) -> Dict[str, Any]:
        scan_a = await self.scans.require_scan(scan_id_a, user_id)
        scan_b = await self.scans.require_scan(scan_id_b, user_id)

        results_a = await self.scans.get_scan_results(scan_a.id)
        results_b = await self.scans.get_scan_results(scan_b.id)
        findings_a = await self.scans.get_scan_findings(scan_a.id)
        findings_b = await self.scans.get_scan_findings(scan_b.id)

        map_a = {self._check_key(r): r for r in results_a}
        map_b = {self._check_key(r): r for r in results_b}
        keys = sorted(set(map_a) | set(map_b))

        check_deltas: List[Dict[str, Any]] = []
        for key in keys:
            left = map_a.get(key)
            right = map_b.get(key)
            status_a = left.status if left else None
            status_b = right.status if right else None
            if status_a == status_b and (left and right) and left.score_impact == right.score_impact:
                continue
            sample = right or left
            check_deltas.append(
                {
                    "check_name": sample.check_name,
                    "title": sample.title,
                    "module_name": sample.module_name,
                    "status_a": status_a,
                    "status_b": status_b,
                    "score_a": left.score_impact if left else None,
                    "score_b": right.score_impact if right else None,
                }
            )

        titles_a = {f.title for f in findings_a}
        titles_b = {f.title for f in findings_b}
        score_a = scan_a.overall_score
        score_b = scan_b.overall_score
        score_delta = None
        if score_a is not None and score_b is not None:
            score_delta = round(score_b - score_a, 1)

        logger.info(
            "Compared scans %s vs %s for user_id=%s (%s check deltas)",
            scan_id_a,
            scan_id_b,
            user_id,
            len(check_deltas),
        )
        return {
            "scan_a": scan_a,
            "scan_b": scan_b,
            "score_delta": score_delta,
            "findings_added": sorted(titles_b - titles_a),
            "findings_resolved": sorted(titles_a - titles_b),
            "check_deltas": check_deltas,
        }

    @staticmethod
    def _check_key(row: ScanResult) -> str:
        return f"{row.module_name}:{row.check_name}"
