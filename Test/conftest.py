"""
conftest.py
===========

Shared pytest fixtures for the SecureVault test suite. Ensures every
test runs against an isolated, temporary vault/key/backup location so
tests never touch the real ``data/`` directory.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from encryption import EncryptionManager
from password_manager import VaultManager


@pytest.fixture
def tmp_vault_paths(tmp_path: Path):
    """Provide isolated vault, key, and backup paths within a temp directory."""
    vault_path = tmp_path / "vault.json"
    key_path = tmp_path / "key.json"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return vault_path, key_path, backup_dir


@pytest.fixture
def encryption_manager(tmp_vault_paths):
    """Provide an EncryptionManager backed by an isolated temp key file."""
    _, key_path, _ = tmp_vault_paths
    manager = EncryptionManager(key_path=key_path)
    manager.ensure_key()
    return manager


@pytest.fixture
def vault_manager(tmp_vault_paths, encryption_manager):
    """Provide a VaultManager backed by isolated temp vault/backup paths."""
    vault_path, _, backup_dir = tmp_vault_paths
    return VaultManager(
        vault_path=vault_path, backup_dir=backup_dir, encryption_manager=encryption_manager
    )
