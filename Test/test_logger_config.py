"""Unit tests for logger_config.py."""

from __future__ import annotations

import logging

from logger_config import SensitiveDataFilter, get_audit_logger, setup_logging


def test_setup_logging_returns_logger_with_handlers():
    logger = setup_logging()
    assert logger.name == "securevault"
    assert len(logger.handlers) >= 2


def test_setup_logging_is_idempotent():
    logger1 = setup_logging()
    logger2 = setup_logging()
    assert logger1 is logger2
    assert len(logger1.handlers) == len(logger2.handlers)


def test_get_audit_logger_returns_dedicated_logger():
    audit_logger = get_audit_logger()
    assert audit_logger.name == "securevault.audit"
    assert len(audit_logger.handlers) >= 1


def test_sensitive_data_filter_masks_password_field():
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="Adding entry with password=hunter2 for user bob", args=(), exc_info=None,
    )
    filt = SensitiveDataFilter()
    filt.filter(record)
    assert "hunter2" not in record.msg
    assert "REDACTED" in record.msg


def test_sensitive_data_filter_masks_key_field():
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="key=abcdef1234567890 loaded successfully", args=(), exc_info=None,
    )
    filt = SensitiveDataFilter()
    filt.filter(record)
    assert "abcdef1234567890" not in record.msg


def test_sensitive_data_filter_leaves_normal_messages_untouched():
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="Vault loaded with 5 entries", args=(), exc_info=None,
    )
    filt = SensitiveDataFilter()
    filt.filter(record)
    assert record.msg == "Vault loaded with 5 entries"
