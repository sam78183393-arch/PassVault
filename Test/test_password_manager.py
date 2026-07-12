"""Unit and integration tests for password_manager.py."""

from __future__ import annotations

import pytest

from exceptions import DuplicateEntryError, EntryNotFoundError, VaultIntegrityError
from password_manager import VaultManager


def test_new_vault_starts_empty(vault_manager: VaultManager):
    assert len(vault_manager) == 0
    assert vault_manager.list_entries() == []


def test_add_entry_persists_and_returns_entry(vault_manager: VaultManager):
    entry = vault_manager.add_entry("GitHub", "octocat", "s3cr3t-P@ss")
    assert entry.service == "GitHub"
    assert entry.username == "octocat"
    assert len(vault_manager) == 1


def test_add_duplicate_entry_raises(vault_manager: VaultManager):
    vault_manager.add_entry("GitHub", "octocat", "password1")
    with pytest.raises(DuplicateEntryError):
        vault_manager.add_entry("GitHub", "octocat", "password2")


def test_get_decrypted_password_roundtrip(vault_manager: VaultManager):
    entry = vault_manager.add_entry("AWS", "admin", "MyS3cretPass!")
    assert vault_manager.get_decrypted_password(entry.entry_id) == "MyS3cretPass!"


def test_get_entry_not_found_raises(vault_manager: VaultManager):
    with pytest.raises(EntryNotFoundError):
        vault_manager.get_entry("does-not-exist")


def test_list_entries_returns_all(vault_manager: VaultManager):
    vault_manager.add_entry("A", "u1", "p1")
    vault_manager.add_entry("B", "u2", "p2")
    assert len(vault_manager.list_entries()) == 2


def test_search_entries_matches_service(vault_manager: VaultManager):
    vault_manager.add_entry("Netflix", "viewer", "pw1")
    vault_manager.add_entry("Spotify", "listener", "pw2")
    results = vault_manager.search_entries("net")
    assert len(results) == 1
    assert results[0].service == "Netflix"


def test_update_entry_changes_fields(vault_manager: VaultManager):
    entry = vault_manager.add_entry("Slack", "team", "oldpass")
    updated = vault_manager.update_entry(entry.entry_id, username="team2", password="newpass")
    assert updated.username == "team2"
    assert vault_manager.get_decrypted_password(entry.entry_id) == "newpass"


def test_update_nonexistent_entry_raises(vault_manager: VaultManager):
    with pytest.raises(EntryNotFoundError):
        vault_manager.update_entry("missing-id", username="x")


def test_delete_entry_removes_it(vault_manager: VaultManager):
    entry = vault_manager.add_entry("Dropbox", "user", "pw")
    vault_manager.delete_entry(entry.entry_id)
    assert len(vault_manager) == 0
    with pytest.raises(EntryNotFoundError):
        vault_manager.get_entry(entry.entry_id)


def test_delete_nonexistent_entry_raises(vault_manager: VaultManager):
    with pytest.raises(EntryNotFoundError):
        vault_manager.delete_entry("missing-id")


def test_verify_integrity_true_for_healthy_vault(vault_manager: VaultManager):
    vault_manager.add_entry("Service", "user", "pw")
    assert vault_manager.verify_integrity() is True


def test_vault_persists_across_reloads(tmp_vault_paths, encryption_manager):
    vault_path, _, backup_dir = tmp_vault_paths
    manager1 = VaultManager(vault_path=vault_path, backup_dir=backup_dir, encryption_manager=encryption_manager)
    manager1.add_entry("Persistent", "user", "pw123")

    manager2 = VaultManager(vault_path=vault_path, backup_dir=backup_dir, encryption_manager=encryption_manager)
    assert len(manager2) == 1
    assert manager2.list_entries()[0].service == "Persistent"


def test_corrupted_vault_file_raises_integrity_error(tmp_vault_paths, encryption_manager):
    vault_path, _, backup_dir = tmp_vault_paths
    vault_path.write_text("{not valid json")
    with pytest.raises(VaultIntegrityError):
        VaultManager(vault_path=vault_path, backup_dir=backup_dir, encryption_manager=encryption_manager)


def test_backup_created_on_write(vault_manager: VaultManager):
    vault_manager.add_entry("First", "u", "p")
    vault_manager.add_entry("Second", "u2", "p2")  # triggers a backup of prior state
    assert len(vault_manager.list_backups()) >= 1


def test_restore_backup_recovers_previous_state(vault_manager: VaultManager):
    vault_manager.add_entry("Keep", "u", "p")
    backups_before = vault_manager.list_backups()
    vault_manager.add_entry("ToBeUndone", "u2", "p2")
    assert len(vault_manager) == 2

    # Restore from the backup taken before "ToBeUndone" was added.
    vault_manager.restore_backup(backups_before[0])
    assert len(vault_manager) == 1
    assert vault_manager.list_entries()[0].service == "Keep"
