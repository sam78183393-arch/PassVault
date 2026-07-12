"""
password_manager.py
====================

Core vault management for SecureVault.

Provides encrypted CRUD storage for credential entries, atomic writes,
automatic timestamped backups, vault schema versioning/migration, and
integrity verification. Passwords are always encrypted at rest via
:class:`encryption.EncryptionManager`; they are only ever decrypted
in memory when explicitly requested by the caller.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from config import (
    BACKUP_DIR,
    EXPORT_TIMESTAMP_FORMAT,
    MAX_BACKUP_COUNT,
    VAULT_FILE,
    VAULT_FILE_ENCODING,
    VAULT_SCHEMA_VERSION,
)
from encryption import EncryptionManager
from exceptions import (
    DuplicateEntryError,
    EntryNotFoundError,
    VaultIntegrityError,
)
from utils import utc_now_iso, validate_non_empty_string


@dataclass
class VaultEntry:
    """A single credential entry stored in the vault.

    Attributes:
        entry_id: Unique identifier for the entry.
        service: Name of the service/site the credential belongs to.
        username: Username or account identifier.
        encrypted_password: The password, encrypted at rest.
        url: Optional URL associated with the service.
        notes: Optional free-text notes.
        created_at: ISO-8601 creation timestamp.
        updated_at: ISO-8601 last-updated timestamp.
    """

    entry_id: str
    service: str
    username: str
    encrypted_password: str
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, str]:
        """Serialize the entry to a plain dictionary.

        Returns:
            dict[str, str]: Dictionary representation suitable for JSON.
        """
        return {
            "entry_id": self.entry_id,
            "service": self.service,
            "username": self.username,
            "encrypted_password": self.encrypted_password,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultEntry":
        """Deserialize an entry from a plain dictionary.

        Args:
            data: Dictionary previously produced by :meth:`to_dict`.

        Returns:
            VaultEntry: The reconstructed entry.
        """
        return cls(
            entry_id=data["entry_id"],
            service=data["service"],
            username=data["username"],
            encrypted_password=data["encrypted_password"],
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", utc_now_iso()),
            updated_at=data.get("updated_at", utc_now_iso()),
        )


class VaultManager:
    """Manages the encrypted credential vault: CRUD, backups, and integrity.

    Attributes:
        vault_path (Path): Location of the vault JSON file.
        backup_dir (Path): Directory where timestamped backups are stored.
        encryption (EncryptionManager): Encryption manager used for at-rest
            password encryption.
    """

    def __init__(
        self,
        vault_path: Path = VAULT_FILE,
        backup_dir: Path = BACKUP_DIR,
        encryption_manager: EncryptionManager | None = None,
    ) -> None:
        """Initialize the vault manager and ensure encryption keys exist.

        Args:
            vault_path: Location of the vault JSON file.
            backup_dir: Directory where timestamped backups are stored.
            encryption_manager: Optional pre-configured encryption manager
                (primarily for testing). A new one is created if omitted.
        """
        self.vault_path = vault_path
        self.backup_dir = backup_dir
        self.encryption = encryption_manager or EncryptionManager()
        self.encryption.ensure_key()
        self._entries: dict[str, VaultEntry] = {}
        self._load_or_initialize()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _empty_vault_payload(self) -> dict[str, Any]:
        """Build an empty vault payload with current schema version.

        Returns:
            dict[str, Any]: An empty, schema-versioned vault structure.
        """
        return {"schema_version": VAULT_SCHEMA_VERSION, "entries": []}

    def _load_or_initialize(self) -> None:
        """Load the vault from disk, or initialize a new empty vault.

        Raises:
            VaultIntegrityError: If the vault file exists but is corrupted
                or fails schema validation.
        """
        if not self.vault_path.exists():
            self._entries = {}
            self._write_vault()
            return

        try:
            with open(self.vault_path, "r", encoding=VAULT_FILE_ENCODING) as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise VaultIntegrityError(f"Vault file is corrupted and cannot be parsed: {exc}") from exc

        payload = self._migrate_if_needed(payload)
        self._validate_schema(payload)

        self._entries = {
            item["entry_id"]: VaultEntry.from_dict(item) for item in payload["entries"]
        }

    @staticmethod
    def _validate_schema(payload: dict[str, Any]) -> None:
        """Validate that a loaded vault payload matches the expected schema.

        Args:
            payload: The parsed vault JSON payload.

        Raises:
            VaultIntegrityError: If required keys are missing or malformed.
        """
        if "schema_version" not in payload or "entries" not in payload:
            raise VaultIntegrityError("Vault file is missing required top-level keys.")
        if not isinstance(payload["entries"], list):
            raise VaultIntegrityError("Vault 'entries' field must be a list.")
        required_fields = {"entry_id", "service", "username", "encrypted_password"}
        for item in payload["entries"]:
            missing = required_fields - item.keys()
            if missing:
                raise VaultIntegrityError(f"Vault entry is missing required fields: {missing}")

    @staticmethod
    def _migrate_if_needed(payload: dict[str, Any]) -> dict[str, Any]:
        """Migrate an older vault schema version forward to the current version.

        Args:
            payload: The parsed vault JSON payload, possibly from an older
                schema version.

        Returns:
            dict[str, Any]: A payload conforming to the current schema version.
        """
        version = payload.get("schema_version", 1)

        if version < 2:
            # Schema v1 -> v2: entries gained 'url' and 'notes' fields and
            # explicit created_at/updated_at timestamps.
            for item in payload.get("entries", []):
                item.setdefault("url", "")
                item.setdefault("notes", "")
                item.setdefault("created_at", utc_now_iso())
                item.setdefault("updated_at", utc_now_iso())
            payload["schema_version"] = 2

        return payload

    def _write_vault(self) -> None:
        """Atomically persist the current in-memory vault state to disk.

        Writes to a temporary file first and then performs an atomic
        rename, so a crash mid-write can never leave a half-written
        vault file on disk. Automatically rotates a timestamped backup
        before overwriting an existing vault file.
        """
        if self.vault_path.exists():
            self._create_backup()

        payload = {
            "schema_version": VAULT_SCHEMA_VERSION,
            "entries": [entry.to_dict() for entry in self._entries.values()],
        }

        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.vault_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding=VAULT_FILE_ENCODING) as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp_path, self.vault_path)

    def _create_backup(self) -> Path:
        """Create a timestamped backup copy of the current vault file.

        Also prunes old backups beyond :data:`config.MAX_BACKUP_COUNT`.

        Returns:
            Path: Path to the newly created backup file.
        """
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime(EXPORT_TIMESTAMP_FORMAT)
        backup_path = self.backup_dir / f"vault_backup_{timestamp}.json"
        shutil.copy2(self.vault_path, backup_path)
        self._prune_old_backups()
        return backup_path

    def _prune_old_backups(self) -> None:
        """Delete oldest backups beyond the configured maximum count."""
        backups = sorted(self.backup_dir.glob("vault_backup_*.json"))
        excess = len(backups) - MAX_BACKUP_COUNT
        for old_backup in backups[:max(excess, 0)]:
            old_backup.unlink(missing_ok=True)

    def restore_backup(self, backup_path: Path) -> None:
        """Restore the vault from a specific backup file.

        Args:
            backup_path: Path to a previously created backup file.

        Raises:
            VaultIntegrityError: If the backup file is missing or corrupted.
        """
        if not backup_path.exists():
            raise VaultIntegrityError(f"Backup file not found: {backup_path}")
        try:
            with open(backup_path, "r", encoding=VAULT_FILE_ENCODING) as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise VaultIntegrityError(f"Backup file is corrupted: {exc}") from exc

        payload = self._migrate_if_needed(payload)
        self._validate_schema(payload)
        self._entries = {
            item["entry_id"]: VaultEntry.from_dict(item) for item in payload["entries"]
        }
        self._write_vault()

    def list_backups(self) -> list[Path]:
        """List available backup files, most recent first.

        Returns:
            list[Path]: Backup file paths sorted newest-first.
        """
        return sorted(self.backup_dir.glob("vault_backup_*.json"), reverse=True)

    def verify_integrity(self) -> bool:
        """Verify that every stored entry can be decrypted with the active key.

        Returns:
            bool: True if every entry's password decrypts successfully.
        """
        for entry in self._entries.values():
            try:
                self.encryption.decrypt_str(entry.encrypted_password)
            except Exception:
                return False
        return True

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_entry(
        self, service: str, username: str, password: str, *, url: str = "", notes: str = ""
    ) -> VaultEntry:
        """Add a new credential entry to the vault.

        Args:
            service: Name of the service/site.
            username: Username or account identifier.
            password: Plaintext password to encrypt and store.
            url: Optional URL for the service.
            notes: Optional free-text notes.

        Returns:
            VaultEntry: The newly created entry (with encrypted password).

        Raises:
            DuplicateEntryError: If an entry with the same service and
                username already exists.
        """
        service = validate_non_empty_string(service, "service")
        username = validate_non_empty_string(username, "username")
        validate_non_empty_string(password, "password")

        if self._find_by_service_and_username(service, username) is not None:
            raise DuplicateEntryError(
                f"An entry for service='{service}', username='{username}' already exists."
            )

        entry = VaultEntry(
            entry_id=str(uuid.uuid4()),
            service=service,
            username=username,
            encrypted_password=self.encryption.encrypt_str(password),
            url=url,
            notes=notes,
        )
        self._entries[entry.entry_id] = entry
        self._write_vault()
        return entry

    def get_entry(self, entry_id: str) -> VaultEntry:
        """Retrieve a single entry by its ID.

        Args:
            entry_id: Unique identifier of the entry.

        Returns:
            VaultEntry: The matching entry.

        Raises:
            EntryNotFoundError: If no entry with that ID exists.
        """
        entry = self._entries.get(entry_id)
        if entry is None:
            raise EntryNotFoundError(f"No entry found with id '{entry_id}'.")
        return entry

    def get_decrypted_password(self, entry_id: str) -> str:
        """Retrieve the plaintext password for a specific entry.

        Args:
            entry_id: Unique identifier of the entry.

        Returns:
            str: The decrypted plaintext password.

        Raises:
            EntryNotFoundError: If no entry with that ID exists.
            DecryptionFailedError: If decryption fails.
        """
        entry = self.get_entry(entry_id)
        return self.encryption.decrypt_str(entry.encrypted_password)

    def list_entries(self) -> list[VaultEntry]:
        """List all entries currently stored in the vault.

        Returns:
            list[VaultEntry]: All entries, in insertion order.
        """
        return list(self._entries.values())

    def search_entries(self, query: str) -> list[VaultEntry]:
        """Search entries by case-insensitive substring match on service or username.

        Args:
            query: Search term.

        Returns:
            list[VaultEntry]: Matching entries.
        """
        query_lower = query.lower()
        return [
            entry
            for entry in self._entries.values()
            if query_lower in entry.service.lower() or query_lower in entry.username.lower()
        ]

    def update_entry(
        self,
        entry_id: str,
        *,
        service: str | None = None,
        username: str | None = None,
        password: str | None = None,
        url: str | None = None,
        notes: str | None = None,
    ) -> VaultEntry:
        """Update one or more fields of an existing entry.

        Args:
            entry_id: Unique identifier of the entry to update.
            service: New service name, if changing.
            username: New username, if changing.
            password: New plaintext password, if changing.
            url: New URL, if changing.
            notes: New notes, if changing.

        Returns:
            VaultEntry: The updated entry.

        Raises:
            EntryNotFoundError: If no entry with that ID exists.
        """
        entry = self.get_entry(entry_id)

        if service is not None:
            entry.service = validate_non_empty_string(service, "service")
        if username is not None:
            entry.username = validate_non_empty_string(username, "username")
        if password is not None:
            validate_non_empty_string(password, "password")
            entry.encrypted_password = self.encryption.encrypt_str(password)
        if url is not None:
            entry.url = url
        if notes is not None:
            entry.notes = notes

        entry.updated_at = utc_now_iso()
        self._write_vault()
        return entry

    def delete_entry(self, entry_id: str) -> None:
        """Delete an entry from the vault.

        Args:
            entry_id: Unique identifier of the entry to delete.

        Raises:
            EntryNotFoundError: If no entry with that ID exists.
        """
        if entry_id not in self._entries:
            raise EntryNotFoundError(f"No entry found with id '{entry_id}'.")
        del self._entries[entry_id]
        self._write_vault()

    def _find_by_service_and_username(self, service: str, username: str) -> VaultEntry | None:
        """Find an existing entry matching a service and username exactly.

        Args:
            service: Service name to match.
            username: Username to match.

        Returns:
            VaultEntry | None: The matching entry, or None if not found.
        """
        for entry in self._entries.values():
            if entry.service == service and entry.username == username:
                return entry
        return None

    def __len__(self) -> int:
        """Return the number of entries currently stored in the vault."""
        return len(self._entries)
