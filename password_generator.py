"""
SecureVault - Secure Password Generator
---------------------------------------
This module generates cryptographically secure passwords using Python's
secrets module. Users can customize:
- Length
- Inclusion of uppercase, lowercase, digits, and symbols
"""

import secrets
import string
from typing import Dict


def generate_password(
    length: int = 12,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> Dict[str, str]:
    """
    Generate a secure password.

    Args:
        length (int): Desired password length.
        use_uppercase (bool): Include uppercase letters.
        use_lowercase (bool): Include lowercase letters.
        use_digits (bool): Include digits.
        use_symbols (bool): Include special symbols.

    Returns:
        Dict[str, str]: Dictionary containing:
            - password (str): Generated password
            - length (int): Length of password
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    charset = ""
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += string.punctuation

    if not charset:
        raise ValueError("At least one character set must be selected.")

    password = "".join(secrets.choice(charset) for _ in range(length))

    return {"password": password, "length": length}


if __name__ == "__main__":
    # Example usage
    result = generate_password(length=16, use_symbols=True)
    print(f"Generated Password: {result['password']}")
    print(f"Length: {result['length']}")
