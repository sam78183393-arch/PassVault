"""
SecureVault - Encryption Module
-------------------------------
This module handles encryption and decryption of passwords using
Fernet symmetric encryption from the cryptography library.

Functions:
- generate_key()
- load_key()
- encrypt_password()
- decrypt_password()
"""

from cryptography.fernet import Fernet
from pathlib import Path
from typing import Optional

KEY_FILE = Path("data/key.key")


def generate_key() -> None:
    """
    Generate a new Fernet key and save it to key.key.
    """
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)


def load_key() -> bytes:
    """
    Load the Fernet key from key.key.
    If missing, generate a new one.
    """
    if not KEY_FILE.exists():
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()


def encrypt_password(password: str, key: bytes) -> str:
    """
    Encrypt a password using Fernet.

    Args:
        password (str): Plain text password.
        key (bytes): Encryption key.

    Returns:
        str: Encrypted password (base64 encoded).
    """
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    return encrypted.decode()


def decrypt_password(encrypted_password: str, key: bytes) -> Optional[str]:
    """
    Decrypt a password using Fernet.

    Args:
        encrypted_password (str): Encrypted password string.
        key (bytes): Encryption key.

    Returns:
        Optional[str]: Decrypted password, or None if decryption fails.
    """
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_password.encode())
        return decrypted.decode()
    except Exception:
        return None


if __name__ == "__main__":
    # Example usage
    generate_key()
    key = load_key()
    encrypted = encrypt_password("MySecurePass123!", key)
    print("Encrypted:", encrypted)
    decrypted = decrypt_password(encrypted, key)
    print("Decrypted:", decrypted)
