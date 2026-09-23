"""Unit tests for secure logging and secret redaction."""

import logging

from app.core.logging import SecretRedactionFilter
from app.core.request_context import get_request_id, set_request_id


def test_secret_redaction_filter():
    """Verify that credentials and sensitive headers are redacted from log messages."""
    filter_instance = SecretRedactionFilter()

    test_cases = [
        ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz", "Bearer [REDACTED]"),
        ("authorization: Bearer mysecrettoken", "authorization: Bearer [REDACTED]"),
        ("postgres://user:password123@host:5432/db", "postgres://user:[REDACTED]@host:5432/db"),
        ("api_key=sk-1234567890abcdef", "api_key=[REDACTED]"),
        ("psk=MySecretPreSharedKey", "psk=[REDACTED]"),
    ]

    for raw_msg, expected_needle in test_cases:
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg=raw_msg,
            args=(),
            exc_info=None,
        )
        filter_instance.filter(record)
        assert expected_needle in record.msg, f"Expected '{expected_needle}' in '{record.msg}'"


def test_request_context_variable():
    """Verify context variable storage and retrieval for correlation ID."""
    assert get_request_id() is None
    set_request_id("req-trace-test-123")
    assert get_request_id() == "req-trace-test-123"
    set_request_id(None)
    assert get_request_id() is None
