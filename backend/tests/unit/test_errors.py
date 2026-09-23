"""Unit tests for the standard error envelope and domain exception hierarchy."""

from app.core.errors import (
    ConfigurationError,
    ErrorDetail,
    ErrorEnvelope,
    PathTraversalError,
    ServiceUnavailableError,
    TunnelTraceError,
)


def test_error_envelope_structure():
    """Verify the standard error envelope serialization format."""
    detail = ErrorDetail(
        code="TEST_ERROR",
        message="A test error occurred.",
        request_id="req-999",
        details={"hint": "check params"},
    )
    envelope = ErrorEnvelope(error=detail)
    dumped = envelope.model_dump()

    assert "error" in dumped
    assert dumped["error"]["code"] == "TEST_ERROR"
    assert dumped["error"]["message"] == "A test error occurred."
    assert dumped["error"]["request_id"] == "req-999"
    assert dumped["error"]["details"] == {"hint": "check params"}


def test_exception_status_codes():
    """Verify custom exception definitions map to expected HTTP status codes."""
    e_base = TunnelTraceError("base error")
    assert e_base.status_code == 500
    assert e_base.error_code == "INTERNAL_SERVER_ERROR"

    e_unavail = ServiceUnavailableError("db offline")
    assert e_unavail.status_code == 503
    assert e_unavail.error_code == "SERVICE_UNAVAILABLE"

    e_traversal = PathTraversalError("illegal path")
    assert e_traversal.status_code == 403
    assert e_traversal.error_code == "PATH_TRAVERSAL_DETECTED"

    e_config = ConfigurationError("bad setting")
    assert e_config.status_code == 500
    assert e_config.error_code == "CONFIGURATION_ERROR"
