"""
breach_checker.py
==================

Breach-checking client for SecureVault.

Uses the HaveIBeenPwned Pwned Passwords k-Anonymity API to check
whether a password appears in known breach corpora, without ever
transmitting the full password or its full hash over the network:
only the first 5 characters of the SHA-1 hash are sent, and the
matching suffix is looked up locally in the returned range.

Includes retry with exponential backoff, response validation, a
simple client-side rate limiter, and an in-memory TTL cache to avoid
redundant network calls for repeated lookups.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests

from config import (
    HIBP_API_URL,
    HIBP_BACKOFF_BASE_SECONDS,
    HIBP_BACKOFF_MULTIPLIER,
    HIBP_CACHE_TTL_SECONDS,
    HIBP_MAX_RETRIES,
    HIBP_MIN_REQUEST_INTERVAL_SECONDS,
    HIBP_REQUEST_TIMEOUT_SECONDS,
    HIBP_USER_AGENT,
)
from exceptions import BreachAPIResponseError, BreachAPITimeoutError
from utils import sha1_hex_upper, validate_non_empty_string


@dataclass
class BreachResult:
    """Result of a breach check for a single password.

    Attributes:
        is_breached: Whether the password was found in known breaches.
        occurrence_count: Number of times the password appeared in
            breach corpora (0 if not found).
        checked_at_epoch: Unix timestamp when the check was performed.
        from_cache: Whether this result was served from the local cache.
    """

    is_breached: bool
    occurrence_count: int
    checked_at_epoch: float
    from_cache: bool = False


class BreachChecker:
    """Checks passwords against HaveIBeenPwned using k-Anonymity.

    Attributes:
        session (requests.Session): HTTP session reused across requests.
    """

    def __init__(self, session: requests.Session | None = None) -> None:
        """Initialize the breach checker.

        Args:
            session: Optional pre-configured :class:`requests.Session`
                (primarily for testing/mocking). A new session is
                created if omitted.
        """
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": HIBP_USER_AGENT})
        self._cache: dict[str, tuple[float, BreachResult]] = {}
        self._last_request_time: float = 0.0

    def check_password(self, password: str) -> BreachResult:
        """Check whether a password appears in known breach corpora.

        Args:
            password: The plaintext password to check. Never transmitted
                in full or as a full hash; only a 5-character SHA-1
                prefix leaves the process.

        Returns:
            BreachResult: The outcome of the breach check.

        Raises:
            BreachAPITimeoutError: If the API does not respond within
                the configured timeout after all retries are exhausted.
            BreachAPIResponseError: If the API returns an invalid or
                unexpected response after all retries are exhausted.
        """
        validate_non_empty_string(password, "password")
        full_hash = sha1_hex_upper(password)
        prefix, suffix = full_hash[:5], full_hash[5:]

        cached = self._get_cached(full_hash)
        if cached is not None:
            return cached

        response_text = self._request_range_with_retry(prefix)
        occurrence_count = self._parse_response(response_text, suffix)

        result = BreachResult(
            is_breached=occurrence_count > 0,
            occurrence_count=occurrence_count,
            checked_at_epoch=time.time(),
            from_cache=False,
        )
        self._cache[full_hash] = (time.time(), result)
        return result

    def _get_cached(self, full_hash: str) -> BreachResult | None:
        """Look up a cached breach result if still within the TTL window.

        Args:
            full_hash: Full uppercase SHA-1 hash used as the cache key.

        Returns:
            BreachResult | None: The cached result (marked as from-cache),
                or None if there is no fresh cache entry.
        """
        cached = self._cache.get(full_hash)
        if cached is None:
            return None
        cached_at, result = cached
        if time.time() - cached_at > HIBP_CACHE_TTL_SECONDS:
            del self._cache[full_hash]
            return None
        return BreachResult(
            is_breached=result.is_breached,
            occurrence_count=result.occurrence_count,
            checked_at_epoch=result.checked_at_epoch,
            from_cache=True,
        )

    def _respect_rate_limit(self) -> None:
        """Sleep if necessary to respect the minimum client-side request interval."""
        elapsed = time.time() - self._last_request_time
        wait_time = HIBP_MIN_REQUEST_INTERVAL_SECONDS - elapsed
        if wait_time > 0:
            time.sleep(wait_time)

    def _request_range_with_retry(self, prefix: str) -> str:
        """Request the k-Anonymity range for a hash prefix, retrying on failure.

        Args:
            prefix: The first 5 characters of the password's SHA-1 hash.

        Returns:
            str: The raw response body text (newline-separated
                ``SUFFIX:COUNT`` pairs).

        Raises:
            BreachAPITimeoutError: If every retry attempt times out.
            BreachAPIResponseError: If every retry attempt yields an
                invalid HTTP response.
        """
        url = HIBP_API_URL.format(prefix=prefix)
        last_exception: Exception | None = None

        for attempt in range(HIBP_MAX_RETRIES):
            self._respect_rate_limit()
            try:
                self._last_request_time = time.time()
                response = self.session.get(url, timeout=HIBP_REQUEST_TIMEOUT_SECONDS)
            except requests.Timeout as exc:
                last_exception = exc
            except requests.RequestException as exc:
                last_exception = exc
            else:
                if response.status_code == 200:
                    return response.text
                last_exception = BreachAPIResponseError(
                    f"Unexpected HTTP status code {response.status_code} from breach API."
                )

            if attempt < HIBP_MAX_RETRIES - 1:
                backoff = HIBP_BACKOFF_BASE_SECONDS * (HIBP_BACKOFF_MULTIPLIER ** attempt)
                time.sleep(backoff)

        if isinstance(last_exception, requests.Timeout):
            raise BreachAPITimeoutError(
                f"Breach API request timed out after {HIBP_MAX_RETRIES} attempts."
            ) from last_exception
        raise BreachAPIResponseError(
            f"Breach API request failed after {HIBP_MAX_RETRIES} attempts: {last_exception}"
        ) from last_exception

    @staticmethod
    def _parse_response(response_text: str, suffix: str) -> int:
        """Parse a k-Anonymity range response and find the matching suffix.

        Args:
            response_text: Raw response body (``SUFFIX:COUNT`` lines).
            suffix: The remaining 35 characters of the target SHA-1 hash.

        Returns:
            int: Occurrence count if found, otherwise 0.

        Raises:
            BreachAPIResponseError: If the response is malformed.
        """
        try:
            for line in response_text.splitlines():
                if not line.strip():
                    continue
                line_suffix, _, count_str = line.partition(":")
                if line_suffix.strip().upper() == suffix:
                    return int(count_str.strip())
            return 0
        except (ValueError, AttributeError) as exc:
            raise BreachAPIResponseError(f"Malformed breach API response: {exc}") from exc
