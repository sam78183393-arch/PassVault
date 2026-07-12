"""Unit tests for encryption.py."""

from __future__ import annotations

import json

import pytest

from encryption import EncryptionManager
from exceptions import DecryptionFailedError, EncryptionError, KeyNotFoundError


def test_ensure_key_generates_key_file(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    manager = EncryptionManager(key_path=key_path)
    assert not key_path.exists()
    manager.ensure_key()
    assert key_path.exists()


def test_key_file_contains_version_and_timestamp(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    manager = EncryptionManager(key_path=key_path)
    manager.ensure_key()
    payload = json.loads(key_path.read_text())
    assert "version" in payload
    assert "created_at" in payload
    assert "key" in payload


def test_encrypt_decrypt_roundtrip(encryption_manager):
    plaintext = "correct horse battery staple"
    token = encryption_manager.encrypt_str(plaintext)
    assert token != plaintext
    assert encryption_manager.decrypt_str(token) == plaintext


def test_decrypt_with_tampered_token_raises(encryption_manager):
    token = encryption_manager.encrypt_str("hello world")
    tampered = token[:-4] + "abcd"
    with pytest.raises(DecryptionFailedError):
        encryption_manager.decrypt_str(tampered)


def test_load_existing_key_reuses_same_key(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    first = EncryptionManager(key_path=key_path)
    first.ensure_key()
    token = first.encrypt_str("secret-value")

    second = EncryptionManager(key_path=key_path)
    second.ensure_key()
    assert second.decrypt_str(token) == "secret-value"


def test_malformed_key_file_raises_encryption_error(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    key_path.write_text("not valid json")
    manager = EncryptionManager(key_path=key_path)
    with pytest.raises(EncryptionError):
        manager.ensure_key()


def test_missing_key_field_raises_encryption_error(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    key_path.write_text(json.dumps({"version": 1}))
    manager = EncryptionManager(key_path=key_path)
    with pytest.raises(EncryptionError):
        manager.ensure_key()


def test_require_fernet_without_key_file_raises(tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    manager = EncryptionManager(key_path=key_path)
    with pytest.raises(KeyNotFoundError):
        manager.encrypt_str("test")


def test_rotate_key_generates_new_key(encryption_manager, tmp_vault_paths):
    _, key_path, _ = tmp_vault_paths
    original_payload = json.loads(key_path.read_text())
    encryption_manager.rotate_key()
    new_payload = json.loads(key_path.read_text())
    assert original_payload["key"] != new_payload["key"]
