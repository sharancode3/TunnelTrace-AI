"""Request context variables for correlation and traceability across logging and errors."""

import contextvars

# Context variable holding the unique request/correlation ID for the active request
_request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)


def get_request_id() -> str | None:
    """Retrieve the active correlation request ID from context."""
    return _request_id_ctx.get()


def set_request_id(request_id: str) -> None:
    """Set the correlation request ID for the active request context."""
    _request_id_ctx.set(request_id)


def clear_request_id() -> None:
    """Clear the correlation request ID from context."""
    _request_id_ctx.set(None)
