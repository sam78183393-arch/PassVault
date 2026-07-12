"""Unit tests for password_generator.py."""

from __future__ import annotations

import pytest

from config import AMBIGUOUS_CHARS, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from exceptions import GeneratorError, ValidationError
from password_generator import PasswordGenerator


def test_generate_default_length():
    generator = PasswordGenerator()
    result = generator.generate()
    assert len(result.password) == 16


def test_generate_custom_length():
    generator = PasswordGenerator()
    result = generator.generate(length=24)
    assert len(result.password) == 24
    assert result.length == 24


def test_generate_includes_all_selected_categories():
    generator = PasswordGenerator(
        use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True
    )
    result = generator.generate(length=20)
    pwd = result.password
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(not c.isalnum() for c in pwd)


def test_generate_respects_disabled_categories():
    generator = PasswordGenerator(
        use_uppercase=False, use_lowercase=True, use_digits=False, use_symbols=False
    )
    result = generator.generate(length=12)
    assert all(c.islower() for c in result.password)


def test_generate_excludes_ambiguous_characters():
    generator = PasswordGenerator(exclude_ambiguous=True)
    for _ in range(20):
        result = generator.generate(length=32)
        assert not any(c in AMBIGUOUS_CHARS for c in result.password)


def test_generate_no_categories_raises():
    generator = PasswordGenerator(
        use_uppercase=False, use_lowercase=False, use_digits=False, use_symbols=False
    )
    with pytest.raises(GeneratorError):
        generator.generate(length=10)


def test_generate_length_too_short_for_categories_raises():
    # MIN_PASSWORD_LENGTH (8) comfortably fits 4 categories, so the
    # "too short for categories" branch can't be hit at the public
    # minimum length. We verify it directly against the generator's
    # internal category count instead.
    generator = PasswordGenerator(
        use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True
    )
    pools = generator._build_pools()
    assert MIN_PASSWORD_LENGTH >= len(pools)  # documents why length-based trigger is unreachable publicly

    with pytest.raises(GeneratorError):
        # Directly exercise the guard by calling generate with a length
        # equal to MIN_PASSWORD_LENGTH but with more categories than
        # length would allow, using a generator requiring 5 "categories"
        # is not possible (max 4), so instead assert the guard fires
        # when length < number of enabled pools using a crafted generator.
        small_generator = PasswordGenerator(
            use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True
        )
        small_generator._build_pools = lambda: {  # type: ignore[method-assign]
            str(i): "x" for i in range(MIN_PASSWORD_LENGTH + 1)
        }
        small_generator.generate(length=MIN_PASSWORD_LENGTH)


def test_generate_length_below_minimum_raises():
    generator = PasswordGenerator()
    with pytest.raises(ValidationError):
        generator.generate(length=MIN_PASSWORD_LENGTH - 1)


def test_generate_length_above_maximum_raises():
    generator = PasswordGenerator()
    with pytest.raises(ValidationError):
        generator.generate(length=MAX_PASSWORD_LENGTH + 1)


def test_generate_many_returns_requested_count():
    generator = PasswordGenerator()
    results = generator.generate_many(5, length=16)
    assert len(results) == 5
    assert len({r.password for r in results}) == 5  # all unique


def test_generate_many_invalid_count_raises():
    generator = PasswordGenerator()
    with pytest.raises(ValidationError):
        generator.generate_many(0)


def test_entropy_increases_with_length():
    generator = PasswordGenerator()
    short_result = generator.generate(length=8)
    long_result = generator.generate(length=32)
    assert long_result.entropy_bits > short_result.entropy_bits


def test_strength_label_is_valid_category():
    generator = PasswordGenerator()
    result = generator.generate(length=20)
    assert result.strength_label in {"very_weak", "weak", "moderate", "strong", "very_strong"}


def test_passwords_are_not_deterministic():
    generator = PasswordGenerator()
    passwords = {generator.generate(length=16).password for _ in range(10)}
    assert len(passwords) == 10
