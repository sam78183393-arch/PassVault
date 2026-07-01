"""
SecureVault - Password Strength Analyzer
----------------------------------------
This module analyzes the strength of a given password based on:
- Length
- Uppercase letters
- Lowercase letters
- Digits
- Special symbols

It assigns a score (0–100) and classifies the password as:
Weak, Moderate, Strong, or Very Strong.

Suggestions for improvement are also provided.
"""

import re
from typing import Dict, List


def check_strength(password: str) -> Dict[str, str | int | List[str]]:
    """
    Analyze password strength and provide suggestions.

    Args:
        password (str): The password to analyze.

    Returns:
        Dict[str, str | int | List[str]]: Dictionary containing:
            - password (str)
            - score (int)
            - classification (str)
            - suggestions (List[str])
    """
    score: int = 0
    suggestions: List[str] = []

    # Length check
    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 20
        suggestions.append("Increase length to at least 12 characters")
    else:
        score += 10
        suggestions.append("Increase length to at least 8 characters")

    # Uppercase check
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        suggestions.append("Add uppercase letters")

    # Lowercase check
    if re.search(r"[a-z]", password):
        score += 15
    else:
        suggestions.append("Add lowercase letters")

    # Digit check
    if re.search(r"[0-9]", password):
        score += 15
    else:
        suggestions.append("Add digits")

    # Symbol check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 25
    else:
        suggestions.append("Add special symbols")

    if len(suggestions)==0:
        suggestions.append("No changes required")

    # Classification
    if score < 40:
        classification = "Weak"
    elif score < 60:
        classification = "Moderate"
    elif score < 80:
        classification = "Strong"
    else:
        classification = "Very Strong"

    return {
        "password": password,
        "score": score,
        "classification": classification,
        "suggestions": suggestions,
    }


if __name__ == "__main__":
    # Example usage
    test_password = input("Enter password:")
    result = check_strength(test_password)
    print(f"Password: {result['password']}")
    print(f"Strength: {result['classification']} ({result['score']}/100)")
    print("Suggestions:", ", ".join(result["suggestions"]))
