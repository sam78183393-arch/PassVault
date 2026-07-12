"""
password_strength_analyzer.py
==============================

Heuristic password strength analysis for SecureVault.

Scores a password out of 100 based on length, character diversity,
repeated/sequential character runs, dictionary-word similarity, and
estimated entropy, then classifies the result and produces actionable
improvement suggestions.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from config import (
    COMMON_PASSWORDS,
    MAX_REPEATED_RUN_LENGTH,
    SEQUENTIAL_RUN_LENGTH,
    STRENGTH_SCORE_MAX,
    STRENGTH_THRESHOLDS,
)
from utils import (
    contains_repeated_run,
    contains_sequential_run,
    normalize_for_dictionary_check,
    validate_non_empty_string,
)

_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")


@dataclass
class StrengthReport:
    """Result of analyzing a password's strength.

    Attributes:
        score: Overall score out of 100.
        classification: One of "Very Weak", "Weak", "Moderate", "Strong",
            "Very Strong".
        entropy_bits: Estimated Shannon entropy in bits.
        has_upper: Whether the password contains an uppercase letter.
        has_lower: Whether the password contains a lowercase letter.
        has_digit: Whether the password contains a digit.
        has_symbol: Whether the password contains a symbol.
        has_repeated_run: Whether a repeated-character run was detected.
        has_sequential_run: Whether a sequential-character run was detected.
        looks_like_dictionary_word: Whether the password closely matches
            a common/dictionary word.
        suggestions: List of human-readable improvement suggestions.
    """

    score: int
    classification: str
    entropy_bits: float
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_symbol: bool
    has_repeated_run: bool
    has_sequential_run: bool
    looks_like_dictionary_word: bool
    suggestions: list[str] = field(default_factory=list)


class PasswordStrengthAnalyzer:
    """Analyzes passwords and produces a :class:`StrengthReport`."""

    def analyze(self, password: str) -> StrengthReport:
        """Analyze a password and produce a full strength report.

        Args:
            password: The password to analyze.

        Returns:
            StrengthReport: The full analysis result.

        Raises:
            ValidationError: If ``password`` is not a non-empty string.
        """
        validate_non_empty_string(password, "password")

        has_upper = bool(_UPPER_RE.search(password))
        has_lower = bool(_LOWER_RE.search(password))
        has_digit = bool(_DIGIT_RE.search(password))
        has_symbol = bool(_SYMBOL_RE.search(password))

        has_repeated = contains_repeated_run(password, MAX_REPEATED_RUN_LENGTH)
        has_sequential = contains_sequential_run(password, SEQUENTIAL_RUN_LENGTH)
        looks_dictionary = self._looks_like_dictionary_word(password)

        pool_size = self._effective_pool_size(has_upper, has_lower, has_digit, has_symbol)
        entropy_bits = len(password) * math.log2(pool_size) if pool_size > 1 else 0.0

        score = self._compute_score(
            password=password,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_symbol=has_symbol,
            has_repeated=has_repeated,
            has_sequential=has_sequential,
            looks_dictionary=looks_dictionary,
            entropy_bits=entropy_bits,
        )
        classification = self._classify(score)
        suggestions = self._build_suggestions(
            password=password,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_symbol=has_symbol,
            has_repeated=has_repeated,
            has_sequential=has_sequential,
            looks_dictionary=looks_dictionary,
        )

        return StrengthReport(
            score=score,
            classification=classification,
            entropy_bits=round(entropy_bits, 2),
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_symbol=has_symbol,
            has_repeated_run=has_repeated,
            has_sequential_run=has_sequential,
            looks_like_dictionary_word=looks_dictionary,
            suggestions=suggestions,
        )

    @staticmethod
    def _effective_pool_size(has_upper: bool, has_lower: bool, has_digit: bool, has_symbol: bool) -> int:
        """Estimate the effective character pool size given observed categories.

        Args:
            has_upper: Whether uppercase letters are present.
            has_lower: Whether lowercase letters are present.
            has_digit: Whether digits are present.
            has_symbol: Whether symbols are present.

        Returns:
            int: Estimated pool size used for entropy calculation.
        """
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 32
        return pool_size

    @staticmethod
    def _looks_like_dictionary_word(password: str) -> bool:
        """Heuristically check whether a password resembles a common/dictionary word.

        Args:
            password: The password to check.

        Returns:
            bool: True if the normalized password matches a known common
                password/word, or contains one as a large substring.
        """
        normalized = normalize_for_dictionary_check(password)
        if normalized in COMMON_PASSWORDS:
            return True
        return any(
            len(word) >= 5 and word in normalized
            for word in COMMON_PASSWORDS
        )

    @staticmethod
    def _compute_score(
        *,
        password: str,
        has_upper: bool,
        has_lower: bool,
        has_digit: bool,
        has_symbol: bool,
        has_repeated: bool,
        has_sequential: bool,
        looks_dictionary: bool,
        entropy_bits: float,
    ) -> int:
        """Compute an overall strength score out of 100.

        The score blends length, character diversity, and entropy, then
        applies penalties for repeated runs, sequential runs, and
        dictionary-word similarity.

        Returns:
            int: Score clamped to the range [0, 100].
        """
        score = 0.0

        # Length contribution (up to 40 points).
        length = len(password)
        score += min(length, 20) * 1.5  # up to 30 points for first 20 chars
        if length > 20:
            score += min(length - 20, 10) * 1.0  # up to 10 more points

        # Diversity contribution (up to 30 points).
        categories_present = sum([has_upper, has_lower, has_digit, has_symbol])
        score += categories_present * 7.5

        # Entropy contribution (up to 30 points).
        score += min(entropy_bits, 90) / 3.0

        # Penalties.
        if has_repeated:
            score -= 15
        if has_sequential:
            score -= 15
        if looks_dictionary:
            score -= 25

        return max(0, min(STRENGTH_SCORE_MAX, round(score)))

    @staticmethod
    def _classify(score: int) -> str:
        """Map a numeric score to a human-readable classification label.

        Args:
            score: The computed score (0-100).

        Returns:
            str: One of "Very Weak", "Weak", "Moderate", "Strong", "Very Strong".
        """
        if score >= STRENGTH_THRESHOLDS["very_strong"]:
            return "Very Strong"
        if score >= STRENGTH_THRESHOLDS["strong"]:
            return "Strong"
        if score >= STRENGTH_THRESHOLDS["moderate"]:
            return "Moderate"
        if score >= STRENGTH_THRESHOLDS["weak"]:
            return "Weak"
        return "Very Weak"

    @staticmethod
    def _build_suggestions(
        *,
        password: str,
        has_upper: bool,
        has_lower: bool,
        has_digit: bool,
        has_symbol: bool,
        has_repeated: bool,
        has_sequential: bool,
        looks_dictionary: bool,
    ) -> list[str]:
        """Build a list of actionable suggestions to improve password strength.

        Returns:
            list[str]: Human-readable suggestions, empty if none apply.
        """
        suggestions: list[str] = []
        if len(password) < 12:
            suggestions.append(
                "Use at least 12 characters; longer passwords are exponentially harder to crack."
            )
        if not has_upper:
            suggestions.append("Add at least one uppercase letter.")
        if not has_lower:
            suggestions.append("Add at least one lowercase letter.")
        if not has_digit:
            suggestions.append("Add at least one digit.")
        if not has_symbol:
            suggestions.append("Add at least one symbol (e.g. !, @, #, %).")
        if has_repeated:
            suggestions.append("Avoid repeating the same character multiple times in a row.")
        if has_sequential:
            suggestions.append("Avoid sequential runs like 'abc' or '123'.")
        if looks_dictionary:
            suggestions.append("Avoid common words or well-known passwords, even with substitutions.")
        return suggestions
