"""Application-level exceptions mapped to HTTP responses in main.py."""

from typing import Optional


class AppError(Exception):
    """Base error with an HTTP status code and public detail message."""

    status_code: int = 400

    def __init__(
        self,
        detail: str,
        status_code: Optional[int] = None,
        headers: Optional[dict] = None,
    ):
        self.detail = detail
        if status_code is not None:
            self.status_code = status_code
        self.headers = dict(headers) if headers else None
        super().__init__(detail)


class DomainValidationError(AppError):
    """Target domain failed sanitization or SSRF policy."""

    status_code = 400


class ScanNotFoundError(AppError):
    status_code = 404


class AuthorizationNotConfirmedError(AppError):
    """User did not attest that they are authorized to scan the target."""

    status_code = 403


class ScanNotCompleteError(AppError):
    status_code = 400


class ScanRateLimitError(AppError):
    """User exceeded SCAN_RATE_LIMIT_PER_HOUR for scans."""

    status_code = 429

    def __init__(
        self,
        detail: str,
        retry_after: Optional[int] = None,
        limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        self.retry_after = retry_after
        self.limit = limit
        self.window_seconds = window_seconds
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        super().__init__(detail, headers=headers)


class ScanConcurrencyLimitError(AppError):
    """No concurrency slot is available for a new scan."""

    status_code = 429

    def __init__(
        self,
        detail: str,
        retry_after: Optional[int] = None,
        limit: Optional[int] = None,
    ):
        self.retry_after = retry_after
        self.limit = limit
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        super().__init__(detail, headers=headers)


class LoginThrottledError(AppError):
    """Too many failed login attempts for this client/account pair."""

    status_code = 429

    def __init__(self, detail: str, retry_after: Optional[int] = None):
        self.retry_after = retry_after
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        super().__init__(detail, headers=headers)


class ReportNotFoundError(AppError):
    status_code = 404


class ReportGenerationError(AppError):
    status_code = 500
