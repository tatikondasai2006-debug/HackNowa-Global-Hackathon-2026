"""Tests for scan history comparison."""

from app.services import history_service
from app.services.history_service import HistoryService
from app.services.scan_service import ScanService


def test_history_service_imports_scan_service():
    """Compare-scans used to NameError because ScanService was never imported."""
    assert history_service.ScanService is ScanService


def test_history_service_constructs_with_db_handle():
    service = HistoryService(db=object())
    assert isinstance(service.scans, ScanService)
