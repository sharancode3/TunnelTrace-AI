"""Standard error envelopes and domain exception classes for TunnelTrace AI."""

from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.request_context import get_request_id


class ErrorDetail(BaseModel):
    """Structured error payload compliant with TunnelTrace AI architecture."""

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable explanation of error")
    request_id: str | None = Field(None, description="Correlation request ID")
    details: Any | None = Field(None, description="Additional context or validation errors")


class ErrorEnvelope(BaseModel):
    """Top-level error response envelope."""

    error: ErrorDetail


class TunnelTraceError(Exception):
    """Base domain exception for all TunnelTrace AI errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details

    @property
    def error_code(self) -> str:
        return self.code


class ConfigurationError(TunnelTraceError):
    """Raised when environment or subsystem configuration is invalid."""

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(
            message=message,
            code="CONFIGURATION_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


class ServiceUnavailableError(TunnelTraceError):
    """Raised when an internal dependent service (database, cache, storage) fails readiness."""

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(
            message=message,
            code="SERVICE_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
        )


class StorageError(TunnelTraceError):
    """Base exception for file and artifact storage failures."""

    def __init__(
        self, message: str, code: str = "STORAGE_ERROR", details: Any | None = None
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


class PathTraversalError(StorageError):
    """Security exception raised when an attempt to escape storage root is detected."""

    def __init__(self, message: str = "Access denied: Path traversal detected.") -> None:
        super().__init__(
            message=message,
            code="PATH_TRAVERSAL_DETECTED",
        )
        self.status_code = status.HTTP_403_FORBIDDEN


class NotFoundError(TunnelTraceError):
    """Raised when a requested resource does not exist."""

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class CaptureValidationError(TunnelTraceError):
    """Raised when an uploaded packet capture fails structural or format validation."""

    def __init__(self, message: str, code: str = "CAPTURE_INVALID_FORMAT", details: Any | None = None) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class CaptureNotFoundError(NotFoundError):
    """Raised when a specified capture artifact cannot be found."""

    def __init__(self, capture_id: str) -> None:
        super().__init__(
            message=f"Capture with ID '{capture_id}' was not found.",
            details={"capture_id": capture_id},
        )
        self.code = "CAPTURE_NOT_FOUND"


class AnalysisNotFoundError(NotFoundError):
    """Raised when a specified protocol analysis run cannot be found."""

    def __init__(self, analysis_id: str) -> None:
        super().__init__(
            message=f"Analysis run with ID '{analysis_id}' was not found.",
            details={"analysis_id": analysis_id},
        )
        self.code = "ANALYSIS_NOT_FOUND"


class ParserError(TunnelTraceError):
    """Raised when the deterministic protocol parser experiences an unrecoverable failure."""

    def __init__(self, message: str, code: str = "PARSER_FAILED", details: Any | None = None) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


class LiveCaptureError(TunnelTraceError):
    """Raised when a live capture operation is unauthorized, rejected, or encounters an error."""

    def __init__(
        self,
        message: str,
        code: str = "LIVE_CAPTURE_FAILED",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Any | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=status_code,
            details=details,
        )


def build_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Any | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Utility to build a uniform JSON error response envelope."""
    req_id = request_id or get_request_id()
    payload = ErrorEnvelope(
        error=ErrorDetail(
            code=code,
            message=message,
            request_id=req_id,
            details=details,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=payload.model_dump(),
    )


async def tunneltrace_error_handler(request: Request, exc: TunnelTraceError) -> JSONResponse:
    """Global exception handler for all domain TunnelTraceError instances."""
    return build_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all exception handler to ensure stack traces never leak to API clients."""
    return build_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected internal server error occurred.",
        details=None,
    )
