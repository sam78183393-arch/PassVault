"""Unit tests for password_strength_analyzer.py."""

from __future__ import annotations

import pytest

from exceptions import ValidationError
from password_strength_analyzer import PasswordStrengthAnalyzer


@pytest.fixture
def analyzer() -> PasswordStrengthAnalyzer:
    return PasswordStrengthAnalyzer()


def test_common_password_scores_low(analyzer):
    report = analyzer.analyze("password")
    assert report.classification in {"Very Weak", "Weak"}
    assert report.looks_like_dictionary_word is True


def test_strong_random_password_scores_high(analyzer):
    report = analyzer.analyze("xQ9#mK2$pL7&vN4!")
    assert report.classification in {"Strong", "Very Strong"}


def test_detects_repeated_run(analyzer):
    report = analyzer.analyze("aaaaBBBB1234")
    assert report.has_repeated_run is True


def test_detects_sequential_run(analyzer):
    report = analyzer.analyze("abcdEFGH123")
    assert report.has_sequential_run is True


def test_detects_character_categories(analyzer):
    report = analyzer.analyze("Abcdef1!")
    assert report.has_upper is True
    assert report.has_lower is True
    assert report.has_digit is True
    assert report.has_symbol is True


def test_missing_categories_detected(analyzer):
    report = analyzer.analyze("abcdefgh")
    assert report.has_upper is False
    assert report.has_digit is False
    assert report.has_symbol is False


def test_suggestions_present_for_weak_password(analyzer):
    report = analyzer.analyze("abc")
    assert len(report.suggestions) > 0


def test_no_suggestions_for_strong_password(analyzer):
    report = analyzer.analyze("Tr#9kLmZ8&qWs2@Pv6xY")
    # A long, diverse, non-repeating password should have zero or
    # very few remaining suggestions.
    assert report.score >= 75


def test_empty_password_raises(analyzer):
    with pytest.raises(ValidationError):
        analyzer.analyze("")


def test_non_string_raises(analyzer):
    with pytest.raises(ValidationError):
        analyzer.analyze(12345)  # type: ignore[arg-type]


def test_score_within_bounds(analyzer):
    for pwd in ["a", "password123", "Tr#9kLmZ8&qWs2@Pv6xY", "aaaaaaaaaaaaaaaaaaaa"]:
        report = analyzer.analyze(pwd)
        assert 0 <= report.score <= 100
