"""
logger_config.py
================

Logging configuration for SecureVault.

Sets up rotating application logs, a separate rotating error log, and
a separate audit log for security-relevant events (entry creation,
deletion, exports, key rotation, restores). A logging filter masks
sensitive field values so passwords and encryption keys are never
written to disk in plaintext.
"""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler

from config import (
    AUDIT_LOG_FILE,
    ERROR_LOG_FILE,
    LOG_BACKUP_COUNT,
    LOG_DATE_FORMAT,
    LOG_FILE,
    LOG_FORMAT,
    LOG_LEVEL,
    LOG_MAX_BYTES,
    MASK_PLACEHOLDER,
    SENSITIVE_FIELD_NAMES,
)

_SENSITIVE_PATTERN = re.compile(
    r"(?i)(" + "|".join(re.escape(name) for name in SENSITIVE_FIELD_NAMES) + r")\s*[=:]\s*\S+"
)


class SensitiveDataFilter(logging.Filter):
    """Logging filter that masks values of sensitive fields in log messages.

    Scans rendered log messages for patterns like ``password=hunter2`` or
    ``key: abc123`` and replaces the value with a redaction placeholder,
    keyed off the field names configured in :data:`config.SENSITIVE_FIELD_NAMES`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Mask sensitive data in a log record's message before it is emitted.

        Args:
            record: The log record about to be emitted.

        Returns:
            bool: Always True (records are masked, never dropped).
        """
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True

        masked = _SENSITIVE_PATTERN.sub(
            lambda m: f"{m.group(1)}={MASK_PLACEHOLDER}", message
        )
        record.msg = masked
        record.args = ()
        return True


def setup_logging() -> logging.Logger:
    """Configure and return the root SecureVault application logger.

    Sets up three handlers:
        1. A rotating file handler for all application logs (INFO+ by default).
        2. A separate rotating file handler for ERROR+ logs only.
        3. A dedicated audit logger (retrieved separately via
           :func:`get_audit_logger`) for security-relevant events.

    Returns:
        logging.Logger: The configured "securevault" application logger.
    """
    logger = logging.getLogger("securevault")
    logger.setLevel(LOG_LEVEL)

    if logger.handlers:
        # Already configured (e.g. re-imported); avoid duplicate handlers.
        return logger

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    sensitive_filter = SensitiveDataFilter()

    app_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    app_handler.setFormatter(formatter)
    app_handler.addFilter(sensitive_filter)
    app_handler.setLevel(LOG_LEVEL)

    error_handler = RotatingFileHandler(
        ERROR_LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    error_handler.setFormatter(formatter)
    error_handler.addFilter(sensitive_filter)
    error_handler.setLevel(logging.ERROR)

    logger.addHandler(app_handler)
    logger.addHandler(error_handler)
    logger.propagate = False

    return logger


def get_audit_logger() -> logging.Logger:
    """Configure and return the dedicated security audit logger.

    The audit logger records security-relevant actions (vault entry
    creation/deletion, key rotation, exports, restores) to a separate
    log file so audit trails are never mixed with routine debug output.

    Returns:
        logging.Logger: The configured "securevault.audit" logger.
    """
    audit_logger = logging.getLogger("securevault.audit")
    audit_logger.setLevel(logging.INFO)

    if audit_logger.handlers:
        return audit_logger

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    handler = RotatingFileHandler(
        AUDIT_LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveDataFilter())
    audit_logger.addHandler(handler)
    audit_logger.propagate = False

    return audit_logger
