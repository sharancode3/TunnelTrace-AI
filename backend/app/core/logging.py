"""Structured logging configuration with secret redaction and request context correlation."""

import logging
import re
import sys

from app.core.request_context import get_request_id

# Regex patterns to detect and redact sensitive parameters in log messages
SENSITIVE_PATTERNS = [
    re.compile(
        r"(password|passwd|pwd|secret|token|api_key|apikey|private_key|psk)=([^\s&]+)",
        re.IGNORECASE,
    ),
    re.compile(r"(Authorization:\s*Bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
    re.compile(r"(postgres(?:ql)?(?:\+[a-z0-9]+)?://[^:]+:)([^@]+)(@)", re.IGNORECASE),
    re.compile(r"(redis://:[^@]+@)", re.IGNORECASE),
]


class SecretRedactionFilter(logging.Filter):
    """Logging filter that masks credentials, tokens, and connection strings."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._redact(v) if isinstance(v, str) else v for k, v in record.args.items()
                }
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(
                    self._redact(v) if isinstance(v, str) else v for v in record.args
                )
        return True

    @staticmethod
    def _redact(text: str) -> str:
        # Key-value secrets (e.g. psk=..., api_key=...)
        text = re.sub(
            r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|private_key|psk)=([^\s&]+)",
            r"\1=[REDACTED]",
            text,
        )
        # Authorization Bearer tokens
        text = re.sub(
            r"(?i)\b(Authorization:\s*Bearer\s+)([A-Za-z0-9\-._~+/]+=*)",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)\b(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)",
            r"\1[REDACTED]",
            text,
        )
        # Database connection passwords
        text = re.sub(
            r"(?i)(postgres(?:ql)?(?:\+[a-z0-9]+)?://[^:]+:)([^@]+)(@)",
            r"\1[REDACTED]\3",
            text,
        )
        # Redis connection passwords
        text = re.sub(
            r"(?i)(redis://(?::[^@]+)@)",
            r"redis://:[REDACTED]@",
            text,
        )
        return text


class ContextualFormatter(logging.Formatter):
    """Formatter that attaches correlation request_id and UTC timestamp to logs."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = get_request_id() or "-"
        record.request_id = request_id  # type: ignore[attr-defined]
        return super().format(record)


def configure_logging(log_level: str = "INFO", app_env: str = "development") -> None:
    """Initialize system-wide logging with redaction filter and unified formatting."""
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level.upper())

    # Remove existing handlers to avoid duplicate log emissions
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level.upper())

    format_str = (
        "%(asctime)s.%(msecs)03dZ [%(levelname)s] [%(name)s] [req:%(request_id)s] %(message)s"
    )
    date_fmt = "%Y-%m-%dT%H:%M:%S"

    formatter = ContextualFormatter(fmt=format_str, datefmt=date_fmt)
    handler.setFormatter(formatter)
    handler.addFilter(SecretRedactionFilter())

    root_logger.addHandler(handler)

    # Align standard web server loggers
    for logger_name in (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "fastapi",
        "alembic",
        "celery",
    ):
        sub_logger = logging.getLogger(logger_name)
        sub_logger.handlers = []
        sub_logger.propagate = True
