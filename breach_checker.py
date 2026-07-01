"""
SecureVault - Password Breach Checker
-------------------------------------
This module checks if a password has been exposed in known breaches
using the HaveIBeenPwned API (k-anonymity model).

Steps:
1. SHA1 hash the password.
2. Send the first 5 characters of the hash to the API.
3. Compare suffixes returned.
4. Report breach count.
"""

import hashlib
import requests
from typing import Dict


def check_breach(password: str) -> Dict[str, str | int]:
    """
    Check if a password has been exposed in breaches.

    Args:
        password (str): The password to check.

    Returns:
        Dict[str, str | int]: Dictionary containing:
            - password (str)
            - breaches (int)
            - recommendation (str)
    """
    # Hash password with SHA1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return {
                "password": password,
                "breaches": -1,
                "recommendation": "Error contacting breach API",
            }

        hashes = (line.split(":") for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return {
                    "password": password,
                    "breaches": int(count),
                    "recommendation": "Change password immediately",
                }

        return {
            "password": password,
            "breaches": 0,
            "recommendation": "Password not found in breaches",
        }

    except requests.RequestException:
        return {
            "password": password,
            "breaches": -1,
            "recommendation": "Network error, try again later",
        }


if __name__ == "__main__":
    # Example usage
    test_password = "SecurePass123!"
    result = check_breach(test_password)
    print(f"Password: {result['password']}")
    print(f"Breaches: {result['breaches']}")
    print(f"Recommendation: {result['recommendation']}")
