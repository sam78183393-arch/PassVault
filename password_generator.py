"""
password_generator.py
======================

Cryptographically secure password generation for SecureVault.

Uses the :mod:`secrets` module exclusively for all randomness decisions
(never :mod:`random`), guarantees inclusion of every selected character
category, and performs a secure Fisher-Yates shuffle so that guaranteed
characters are not predictably positioned.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass, field

from config import (
    AMBIGUOUS_CHARS,
    DEFAULT_PASSWORD_LENGTH,
    DIGIT_CHARS,
    LOWERCASE_CHARS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SYMBOL_CHARS,
    UPPERCASE_CHARS,
)
from exceptions import GeneratorError
from utils import validate_positive_int


@dataclass(frozen=True)
class PasswordResult:
    """Result of a password generation request.

    Attributes:
        password: The generated password.
        length: Length of the generated password.
        entropy_bits: Estimated Shannon entropy in bits.
        strength_label: Coarse strength classification based on entropy.
        categories_used: Character categories included in the password.
        pool_size: Size of the character pool the password was drawn from.
    """

    password: str
    length: int
    entropy_bits: float
    strength_label: str
    categories_used: list[str] = field(default_factory=list)
    pool_size: int = 0


class PasswordGenerator:
    """Generates cryptographically secure passwords using ``secrets``.

    All randomness is sourced from :mod:`secrets`, which is backed by
    the operating system's CSPRNG. The :mod:`random` module is never
    used anywhere in this class.
    """

    def __init__(
        self,
        *,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False,
    ) -> None:
        """Configure which character categories the generator will use.

        Args:
            use_uppercase: Include uppercase letters.
            use_lowercase: Include lowercase letters.
            use_digits: Include digits.
            use_symbols: Include symbol characters.
            exclude_ambiguous: Remove visually ambiguous characters
                (e.g. ``l``, ``1``, ``I``, ``O``, ``0``) from all pools.
        """
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_digits = use_digits
        self.use_symbols = use_symbols
        self.exclude_ambiguous = exclude_ambiguous

    def _build_pools(self) -> dict[str, str]:
        """Build the per-category character pools based on configuration.

        Returns:
            dict[str, str]: Mapping of category name to its character pool.

        Raises:
            GeneratorError: If no character categories are enabled.
        """
        pools: dict[str, str] = {}
        if self.use_lowercase:
            pools["lowercase"] = LOWERCASE_CHARS
        if self.use_uppercase:
            pools["uppercase"] = UPPERCASE_CHARS
        if self.use_digits:
            pools["digits"] = DIGIT_CHARS
        if self.use_symbols:
            pools["symbols"] = SYMBOL_CHARS

        if not pools:
            raise GeneratorError("At least one character category must be enabled.")

        if self.exclude_ambiguous:
            for name, chars in pools.items():
                filtered = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
                if not filtered:
                    raise GeneratorError(
                        f"Excluding ambiguous characters leaves the '{name}' pool empty."
                    )
                pools[name] = filtered
        return pools

    @staticmethod
    def _secure_shuffle(characters: list[str]) -> list[str]:
        """Perform an in-place Fisher-Yates shuffle using ``secrets.randbelow``.

        Args:
            characters: List of characters to shuffle.

        Returns:
            list[str]: The same list, shuffled in place, returned for convenience.
        """
        for i in range(len(characters) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            characters[i], characters[j] = characters[j], characters[i]
        return characters

    def generate(self, length: int = DEFAULT_PASSWORD_LENGTH) -> PasswordResult:
        """Generate a single secure password of the requested length.

        Guarantees at least one character from every enabled category,
        then fills the remainder of the password randomly from the
        combined pool, and finally shuffles the result with a
        cryptographically secure Fisher-Yates shuffle.

        Args:
            length: Desired password length.

        Returns:
            PasswordResult: The generated password and its metadata.

        Raises:
            GeneratorError: If ``length`` is out of the allowed range,
                or too short to contain one of each enabled category.
        """
        validate_positive_int(
            length, "length", minimum=MIN_PASSWORD_LENGTH, maximum=MAX_PASSWORD_LENGTH
        )
        pools = self._build_pools()

        if length < len(pools):
            raise GeneratorError(
                f"Password length {length} is too short to include at least one "
                f"character from each of the {len(pools)} selected categories."
            )

        # Guarantee one character per category.
        guaranteed = [secrets.choice(pool) for pool in pools.values()]

        # Fill the remainder from the combined pool.
        combined_pool = "".join(pools.values())
        remaining_count = length - len(guaranteed)
        filler = [secrets.choice(combined_pool) for _ in range(remaining_count)]

        all_chars = guaranteed + filler
        self._secure_shuffle(all_chars)
        password = "".join(all_chars)

        entropy_bits = self._estimate_entropy(len(combined_pool), length)
        strength_label = self._classify_entropy(entropy_bits)

        return PasswordResult(
            password=password,
            length=length,
            entropy_bits=round(entropy_bits, 2),
            strength_label=strength_label,
            categories_used=sorted(pools.keys()),
            pool_size=len(combined_pool),
        )

    def generate_many(self, count: int, length: int = DEFAULT_PASSWORD_LENGTH) -> list[PasswordResult]:
        """Generate multiple independent secure passwords.

        Args:
            count: Number of passwords to generate.
            length: Desired length for each password.

        Returns:
            list[PasswordResult]: One result per generated password.

        Raises:
            GeneratorError: If ``count`` is not a positive integer.
        """
        validate_positive_int(count, "count", minimum=1, maximum=1000)
        return [self.generate(length) for _ in range(count)]

    @staticmethod
    def _estimate_entropy(pool_size: int, length: int) -> float:
        """Estimate Shannon entropy in bits for a random string.

        Args:
            pool_size: Size of the character pool the string was drawn from.
            length: Length of the string.

        Returns:
            float: Estimated entropy in bits (``length * log2(pool_size)``).
        """
        if pool_size <= 1:
            return 0.0
        return length * math.log2(pool_size)

    @staticmethod
    def _classify_entropy(entropy_bits: float) -> str:
        """Classify a password's strength based on its entropy in bits.

        Args:
            entropy_bits: Estimated entropy in bits.

        Returns:
            str: One of "very_weak", "weak", "moderate", "strong", "very_strong".
        """
        if entropy_bits < 28:
            return "very_weak"
        if entropy_bits < 36:
            return "weak"
        if entropy_bits < 60:
            return "moderate"
        if entropy_bits < 80:
            return "strong"
        return "very_strong"
