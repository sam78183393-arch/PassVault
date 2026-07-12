"""
utils.py
========

Shared, stateless helper functions used across multiple SecureVault
modules: validation helpers, formatting helpers, and small pure
utility functions. Keeping these in one place avoids duplicated logic
between the vault, generator, analyzer, and exporter modules.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from exceptions import ValidationError


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 formatted string.

    Returns:
        str: Timestamp such as ``"2026-07-08T12:30:00+00:00"``.
    """
    return datetime.now(timezone.utc).isoformat()


def validate_non_empty_string(value: Any, field_name: str) -> str:
    """Validate that ``value`` is a non-empty, non-whitespace string.

    Args:
        value: The candidate value to validate.
        field_name: Human-readable field name used in error messages.

    Returns:
        str: The stripped string value.

    Raises:
        ValidationError: If ``value`` is not a string, or is empty after
            stripping whitespace.
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string, got {type(value).__name__}.")
    stripped = value.strip()
    if not stripped:
        raise ValidationError(f"{field_name} cannot be empty.")
    return stripped


def validate_positive_int(
    value: Any, field_name: str, *, minimum: int = 1, maximum: int | None = None
) -> int:
    """Validate that ``value`` is an integer within an inclusive range.

    Args:
        value: The candidate value to validate.
        field_name: Human-readable field name used in error messages.
        minimum: The smallest acceptable value (inclusive).
        maximum: The largest acceptable value (inclusive), or ``None``
            for no upper bound.

    Returns:
        int: The validated integer.

    Raises:
        ValidationError: If ``value`` is not an integer or is out of range.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer, got {type(value).__name__}.")
    if value < minimum:
        raise ValidationError(f"{field_name} must be >= {minimum}, got {value}.")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{field_name} must be <= {maximum}, got {value}.")
    return value


def sha256_hex(data: bytes) -> str:
    """Compute the SHA-256 hex digest of ``data``.

    Args:
        data: Raw bytes to hash.

    Returns:
        str: Lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def sha1_hex_upper(data: str) -> str:
    """Compute the uppercase SHA-1 hex digest of a UTF-8 string.

    Used exclusively for the HaveIBeenPwned k-Anonymity protocol, which
    expects uppercase SHA-1 hex digests.

    Args:
        data: The plaintext string to hash.

    Returns:
        str: Uppercase hexadecimal SHA-1 digest.
    """
    return hashlib.sha1(data.encode("utf-8")).hexdigest().upper()


def sha256_file(path: Path) -> str:
    """Compute the SHA-256 hex digest of a file's contents.

    Args:
        path: Path to the file to hash.

    Returns:
        str: Lowercase hexadecimal SHA-256 digest.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mask_secret(value: str, *, visible_chars: int = 0) -> str:
    """Mask a secret value for safe display or logging.

    Args:
        value: The secret string to mask.
        visible_chars: Number of trailing characters to leave visible
            (useful for "ends in ****1234" style displays). Defaults to 0.

    Returns:
        str: A masked representation, e.g. ``"***REDACTED***"``.
    """
    if not value:
        return "***REDACTED***"
    if visible_chars > 0 and len(value) > visible_chars:
        return f"***{value[-visible_chars:]}"
    return "***REDACTED***"


def contains_sequential_run(text: str, run_length: int) -> bool:
    """Detect ascending or descending sequential character runs.

    Checks for runs like ``"abc"``, ``"cba"``, ``"123"``, or ``"321"``.

    Args:
        text: The string to inspect.
        run_length: Minimum run length that counts as sequential.

    Returns:
        bool: True if a sequential run of at least ``run_length`` is found.
    """
    if len(text) < run_length:
        return False
    lowered = text.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i : i + run_length]
        codes = [ord(c) for c in window]
        ascending = all(codes[j + 1] - codes[j] == 1 for j in range(len(codes) - 1))
        descending = all(codes[j] - codes[j + 1] == 1 for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def contains_repeated_run(text: str, run_length: int) -> bool:
    """Detect a character repeated consecutively ``run_length`` or more times.

    Args:
        text: The string to inspect.
        run_length: Minimum repeat count that counts as a repeated run.

    Returns:
        bool: True if such a run exists.
    """
    if len(text) < run_length:
        return False
    pattern = re.compile(r"(.)\1{" + str(run_length - 1) + r",}")
    return bool(pattern.search(text))


def normalize_for_dictionary_check(text: str) -> str:
    """Normalize a string for heuristic dictionary-word comparison.

    Strips accents, lowercases, and removes non-alphanumeric characters
    so that variants like ``"P@ssw0rd!"`` can still be compared against
    a plain-word denylist after light leetspeak normalization.

    Args:
        text: The input string.

    Returns:
        str: Normalized, lowercase, alphanumeric-only string.
    """
    nfkd = unicodedata.normalize("NFKD", text)
    ascii_only = "".join(c for c in nfkd if not unicodedata.combining(c))
    leet_map = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    translated = ascii_only.lower().translate(leet_map)
    return re.sub(r"[^a-z0-9]", "", translated)


def truncate_for_display(text: str, max_length: int = 40) -> str:
    """Truncate a string for safe display, appending an ellipsis if cut.

    Args:
        text: The string to truncate.
        max_length: Maximum length before truncation.

    Returns:
        str: The original string, or a truncated version ending in "...".
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
