"""
encryption.py
=============

Encryption layer for SecureVault.

Wraps :mod:`cryptography.fernet` to provide authenticated symmetric
encryption for vault contents. Responsible for key generation, secure
key storage (versioned JSON key file), key loading, and key rotation.

No plaintext key material is ever logged. Callers must not hardcode
keys; keys are always generated via ``secrets``-backed CSPRNG calls
inside :mod:`cryptography` itself.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from config import KEY_FILE, KEY_FILE_VERSION
from exceptions import DecryptionFailedError, EncryptionError, KeyNotFoundError
from utils import utc_now_iso


class EncryptionManager:
    """Manages generation, storage, loading, and use of the vault's Fernet key.

    Attributes:
        key_path (Path): Filesystem location of the versioned key file.
    """

    def __init__(self, key_path: Path = KEY_FILE) -> None:
        """Initialize the encryption manager.

        Args:
            key_path: Location of the key file. Defaults to the path
                configured in :mod:`config`.
        """
        self.key_path = key_path
        self._fernet: Fernet | None = None

    # ------------------------------------------------------------------
    # Key lifecycle
    # ------------------------------------------------------------------

    def ensure_key(self) -> None:
        """Ensure a valid key exists on disk, generating one if needed.

        Raises:
            EncryptionError: If a key file exists but is malformed.
        """
        if self.key_path.exists():
            self._load_key()
        else:
            self._generate_and_save_key()

    def _generate_and_save_key(self) -> None:
        """Generate a new Fernet key and persist it in the versioned key file."""
        raw_key = Fernet.generate_key()
        payload = {
            "version": KEY_FILE_VERSION,
            "created_at": utc_now_iso(),
            "key": raw_key.decode("utf-8"),
        }
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.key_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp_path, self.key_path)
        self._restrict_permissions(self.key_path)
        self._fernet = Fernet(raw_key)

    def _load_key(self) -> None:
        """Load and validate the key file from disk.

        Raises:
            EncryptionError: If the key file is missing required fields
                or contains an invalid key.
        """
        try:
            with open(self.key_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise EncryptionError(f"Key file is unreadable or corrupted: {exc}") from exc

        if "key" not in payload or "version" not in payload:
            raise EncryptionError("Key file is missing required fields ('key', 'version').")

        try:
            self._fernet = Fernet(payload["key"].encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise EncryptionError(f"Key file contains an invalid Fernet key: {exc}") from exc

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        """Best-effort restriction of key file permissions to owner read/write only.

        Args:
            path: Path to the key file.
        """
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Not all platforms (e.g. certain Windows configurations)
            # support POSIX permission bits; failing silently here is
            # acceptable since this is a defense-in-depth measure only.
            pass

    def rotate_key(self) -> Fernet:
        """Rotate the encryption key, generating and persisting a new one.

        Callers are responsible for re-encrypting any data with the new
        key returned; this method does not touch vault data itself.

        Returns:
            Fernet: The newly active Fernet cipher instance.
        """
        old_fernet = self._require_fernet() if self.key_path.exists() else None
        self._generate_and_save_key()
        return old_fernet if old_fernet is not None else self._require_fernet()

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------

    def _require_fernet(self) -> Fernet:
        """Return the active Fernet instance, loading the key if necessary.

        Returns:
            Fernet: The active cipher.

        Raises:
            KeyNotFoundError: If no key file exists on disk.
        """
        if self._fernet is None:
            if not self.key_path.exists():
                raise KeyNotFoundError(f"No encryption key found at {self.key_path}.")
            self._load_key()
        assert self._fernet is not None
        return self._fernet

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt raw bytes using the active key.

        Args:
            plaintext: Data to encrypt.

        Returns:
            bytes: Fernet ciphertext token.

        Raises:
            EncryptionError: If encryption fails for any reason.
        """
        fernet = self._require_fernet()
        try:
            return fernet.encrypt(plaintext)
        except Exception as exc:  # pragma: no cover - defensive
            raise EncryptionError(f"Failed to encrypt data: {exc}") from exc

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt a Fernet ciphertext token using the active key.

        Args:
            token: Ciphertext token previously produced by :meth:`encrypt`.

        Returns:
            bytes: The recovered plaintext.

        Raises:
            DecryptionFailedError: If the token is invalid, tampered
                with, or was encrypted under a different key.
        """
        fernet = self._require_fernet()
        try:
            return fernet.decrypt(token)
        except InvalidToken as exc:
            raise DecryptionFailedError(
                "Decryption failed: data is corrupted, tampered with, "
                "or was encrypted with a different key."
            ) from exc

    def encrypt_str(self, plaintext: str) -> str:
        """Encrypt a UTF-8 string and return the token as a string.

        Args:
            plaintext: Plaintext string to encrypt.

        Returns:
            str: Base64-encoded Fernet token, decoded to ``str``.
        """
        return self.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt_str(self, token: str) -> str:
        """Decrypt a Fernet token string and return the recovered UTF-8 string.

        Args:
            token: Base64-encoded Fernet token as produced by :meth:`encrypt_str`.

        Returns:
            str: The recovered plaintext string.
        """
        return self.decrypt(token.encode("utf-8")).decode("utf-8")
