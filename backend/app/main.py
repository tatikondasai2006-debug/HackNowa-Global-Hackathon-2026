"""CyberSentinel FastAPI Main Application Entry Point."""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.exceptions import AppError
from app.core.logging_config import install_secret_redaction
from app.db.session import init_db, close_db
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.reports import router as reports_router
from app.api.ai import router as ai_router
from app.api.dashboard import router as dashboard_router

# Scrub configured secret values out of every log record.
install_secret_redaction()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybersentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager handling DB table initialization and cleanup."""
    # Refuses to start when the configuration is unsafe for production.
    problems = settings.validate_runtime_config()
    if problems:
        logger.warning(
            "Configuration warnings:\n- %s", "\n- ".join(problems)
        )
    logger.info("Initializing CyberSentinel backend and database tables...")
    await init_db()
    yield
    logger.info("Closing database engine connections...")
    await close_db()


# API documentation is configurable and switched off by default in production.
_docs_enabled = settings.api_docs_enabled

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Small Business Cybersecurity Assessment Platform REST API",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)
logger.info(
    "API documentation endpoints are %s (ENVIRONMENT=%s, ENABLE_API_DOCS=%s)",
    "enabled" if _docs_enabled else "disabled",
    settings.ENVIRONMENT,
    settings.ENABLE_API_DOCS,
)

# Configure CORS for frontend access. Credentialed requests are allowed, so the
# origins must be explicit; a wildcard is refused by startup validation.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Register API Routers
api_v1_prefix = "/api/v1"
app.include_router(auth_router, prefix=api_v1_prefix)
app.include_router(scans_router, prefix=api_v1_prefix)
app.include_router(reports_router, prefix=api_v1_prefix)
app.include_router(ai_router, prefix=api_v1_prefix)
app.include_router(dashboard_router, prefix=api_v1_prefix)


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for container probes and monitoring."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "ai_enabled": settings.is_ai_enabled,
    }


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    """Map domain/service exceptions to API error responses."""
    logger.warning("Application error on %s: %s", request.url.path, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
):
    """Report validation failures without echoing the rejected input.

    Pydantic v2 includes the offending ``input`` in every error it raises, and
    FastAPI's built-in handler serialises that list verbatim. A request rejected
    by the password policy therefore came back as
    ``{"detail": [{"loc": ["body", "password"], "input": "<plaintext>"}]}``,
    reflecting the user's password in the response body and in anything that
    records it (proxies, client-side error logs, browser devtools).

    The field location and the human-readable reason are kept so the client can
    still show a useful message; only the submitted value and the raw exception
    object are dropped.
    """
    errors = [
        {key: value for key, value in error.items() if key not in ("input", "ctx")}
        for error in exc.errors()
    ]
    return JSONResponse(
        # 422 by literal: Starlette renamed HTTP_422_UNPROCESSABLE_ENTITY to
        # HTTP_422_UNPROCESSABLE_CONTENT, and the numeric status keeps this
        # working on either version without a deprecation warning.
        status_code=422,
        content={"detail": errors},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global safe exception handler to avoid exposing raw stack traces."""
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please try again later."},
    )
