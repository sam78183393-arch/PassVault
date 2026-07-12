"""
config.py
=========

Centralized configuration module for SecureVault.

Every tunable constant used across the application lives here so that
behaviour can be adjusted in a single place without touching business
logic. Values may be overridden via environment variables to support
different deployment environments (development, staging, production)
without changing code.

No module in this project should hardcode a literal that belongs here.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
BACKUP_DIR: Path = DATA_DIR / "backups"
LOG_DIR: Path = BASE_DIR / "logs"
EXPORT_DIR: Path = DATA_DIR / "exports"

VAULT_FILE: Path = DATA_DIR / "vault.json"
KEY_FILE: Path = DATA_DIR / "key.json"

for _directory in (DATA_DIR, BACKUP_DIR, LOG_DIR, EXPORT_DIR):
    _directory.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Vault / schema configuration
# ---------------------------------------------------------------------------

VAULT_SCHEMA_VERSION: int = 2
VAULT_FILE_ENCODING: str = "utf-8"
MAX_BACKUP_COUNT: int = int(os.getenv("SECUREVAULT_MAX_BACKUPS", "10"))

# ---------------------------------------------------------------------------
# Encryption configuration
# ---------------------------------------------------------------------------

KEY_FILE_VERSION: int = 1
FERNET_KEY_BYTE_LENGTH: int = 32  # raw bytes before base64 encoding

# ---------------------------------------------------------------------------
# Password generator configuration
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH: int = 8
MAX_PASSWORD_LENGTH: int = 128
DEFAULT_PASSWORD_LENGTH: int = 16

LOWERCASE_CHARS: str = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_CHARS: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT_CHARS: str = "0123456789"
SYMBOL_CHARS: str = "!@#$%^&*()-_=+[]{};:,.<>?/|~"

# Characters that are commonly confused with one another when displayed
# (e.g. "l", "1", "I", "O", "0"). Excluded when the caller requests it.
AMBIGUOUS_CHARS: str = "il1LoO0|"

# ---------------------------------------------------------------------------
# Password strength analyzer configuration
# ---------------------------------------------------------------------------

STRENGTH_SCORE_MAX: int = 100

STRENGTH_THRESHOLDS: dict[str, int] = {
    "very_weak": 0,
    "weak": 25,
    "moderate": 50,
    "strong": 75,
    "very_strong": 90,
}

# A small, common-password / dictionary-word denylist used for heuristic
# dictionary-word detection. Kept intentionally small; this is a lightweight
# heuristic check, not a full dictionary attack simulator.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "123456", "123456789", "qwerty", "abc123", "letmein",
        "monkey", "111111", "iloveyou", "admin", "welcome", "login",
        "princess", "dragon", "football", "passw0rd", "master", "hello",
        "freedom", "whatever", "trustno1", "starwars", "sunshine",
    }
)

SEQUENTIAL_RUN_LENGTH: int = 3  # e.g. "abc", "123" count as sequential runs
MAX_REPEATED_RUN_LENGTH: int = 3  # e.g. "aaa" counts as a repeated run

# ---------------------------------------------------------------------------
# Breach checker (HaveIBeenPwned k-Anonymity API) configuration
# ---------------------------------------------------------------------------

HIBP_API_URL: str = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_REQUEST_TIMEOUT_SECONDS: float = 5.0
HIBP_MAX_RETRIES: int = 3
HIBP_BACKOFF_BASE_SECONDS: float = 0.5
HIBP_BACKOFF_MULTIPLIER: float = 2.0
HIBP_CACHE_TTL_SECONDS: int = 3600
HIBP_USER_AGENT: str = "SecureVault (+k-anonymity-client)"
HIBP_MIN_REQUEST_INTERVAL_SECONDS: float = 1.5  # simple client-side rate limit

# ---------------------------------------------------------------------------
# Exporter configuration
# ---------------------------------------------------------------------------

EXPORT_TIMESTAMP_FORMAT: str = "%Y%m%d_%H%M%S"
EXPORT_JSON_INDENT: int = 2
EXPORT_CSV_FIELDNAMES: list[str] = [
    "entry_id",
    "service",
    "username",
    "password",
    "url",
    "notes",
    "created_at",
    "updated_at",
]

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOG_FILE: Path = LOG_DIR / "securevault.log"
ERROR_LOG_FILE: Path = LOG_DIR / "securevault_error.log"
AUDIT_LOG_FILE: Path = LOG_DIR / "securevault_audit.log"

LOG_MAX_BYTES: int = 5 * 1024 * 1024  # 5 MB per file
LOG_BACKUP_COUNT: int = 5
LOG_LEVEL: str = os.getenv("SECUREVAULT_LOG_LEVEL", "INFO")
LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# Substrings used to identify and mask sensitive field names in log records.
SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {"password", "key", "secret", "token", "encryption_key"}
)
MASK_PLACEHOLDER: str = "***REDACTED***"

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

APP_NAME: str = "SecureVault"
