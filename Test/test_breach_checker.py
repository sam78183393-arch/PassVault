"""Unit tests for breach_checker.py, using a mocked HTTP session."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from breach_checker import BreachChecker
from exceptions import BreachAPIResponseError, BreachAPITimeoutError, ValidationError
from utils import sha1_hex_upper


def _make_session_with_response(text: str, status_code: int = 200) -> MagicMock:
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    response = MagicMock()
    response.status_code = status_code
    response.text = text
    session.get.return_value = response
    return session


def test_password_found_in_breach_returns_true():
    password = "password123"
    full_hash = sha1_hex_upper(password)
    suffix = full_hash[5:]
    session = _make_session_with_response(f"{suffix}:12345\nOTHERSUFFIX:1")

    checker = BreachChecker(session=session)
    result = checker.check_password(password)

    assert result.is_breached is True
    assert result.occurrence_count == 12345


def test_password_not_found_returns_false():
    session = _make_session_with_response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2")
    checker = BreachChecker(session=session)
    result = checker.check_password("some-unlikely-password-xyz-987")
    assert result.is_breached is False
    assert result.occurrence_count == 0


def test_result_is_cached_on_second_call():
    password = "cached-password-test"
    full_hash = sha1_hex_upper(password)
    suffix = full_hash[5:]
    session = _make_session_with_response(f"{suffix}:99")

    checker = BreachChecker(session=session)
    first = checker.check_password(password)
    second = checker.check_password(password)

    assert first.from_cache is False
    assert second.from_cache is True
    assert session.get.call_count == 1


def test_only_prefix_sent_not_full_hash():
    session = _make_session_with_response("SOMESUFFIX:1")
    checker = BreachChecker(session=session)
    checker.check_password("test-password")

    called_url = session.get.call_args[0][0]
    full_hash = sha1_hex_upper("test-password")
    assert full_hash[:5] in called_url
    assert full_hash not in called_url  # full hash never transmitted


def test_timeout_raises_after_retries():
    session = MagicMock(spec=requests.Session)
    session.headers = {}
    session.get.side_effect = requests.Timeout("timed out")

    checker = BreachChecker(session=session)
    with pytest.raises(BreachAPITimeoutError):
        checker.check_password("some-password")
    assert session.get.call_count >= 1


def test_non_200_response_raises_after_retries():
    session = _make_session_with_response("", status_code=500)
    checker = BreachChecker(session=session)
    with pytest.raises(BreachAPIResponseError):
        checker.check_password("some-password")


def test_empty_password_raises_validation_error():
    checker = BreachChecker(session=MagicMock(spec=requests.Session, headers={}))
    with pytest.raises(ValidationError):
        checker.check_password("")
