"""
exporter.py
===========

Export and backup functionality for SecureVault.

Supports exporting vault entries to JSON, CSV, and ZIP formats, each
accompanied by a SHA-256 integrity hash so exported data can later be
verified as unmodified. Also supports restoring the vault from a
previously created ZIP export.

Note: exported JSON/CSV files contain *decrypted* plaintext passwords
by design, since the whole point of exporting is to produce a
human/spreadsheet-readable copy. Callers are responsible for storing
exported files securely.
"""

from __future__ import annotations

import csv
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from config import (
    EXPORT_CSV_FIELDNAMES,
    EXPORT_DIR,
    EXPORT_JSON_INDENT,
    EXPORT_TIMESTAMP_FORMAT,
)
from exceptions import ExportError, RestoreError
from password_manager import VaultManager
from utils import sha256_file


@dataclass
class ExportResult:
    """Metadata describing a completed export.

    Attributes:
        file_path: Path to the exported file.
        sha256_hash: SHA-256 hex digest of the exported file's contents.
        entry_count: Number of vault entries included in the export.
        created_at: ISO-8601 timestamp of when the export was created.
    """

    file_path: Path
    sha256_hash: str
    entry_count: int
    created_at: str


class Exporter:
    """Exports and restores vault data in JSON, CSV, and ZIP formats.

    Attributes:
        vault (VaultManager): The vault manager providing entry data.
        export_dir (Path): Directory where export files are written.
    """

    def __init__(self, vault: VaultManager, export_dir: Path = EXPORT_DIR) -> None:
        """Initialize the exporter.

        Args:
            vault: The vault manager to export from / restore into.
            export_dir: Directory where export files are written.
        """
        self.vault = vault
        self.export_dir = export_dir
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def _timestamp(self) -> str:
        """Return the current timestamp formatted for use in filenames.

        Returns:
            str: Timestamp string, e.g. ``"20260708_143000"``.
        """
        return datetime.now().strftime(EXPORT_TIMESTAMP_FORMAT)

    def export_json(self) -> ExportResult:
        """Export all vault entries (with decrypted passwords) to a JSON file.

        Returns:
            ExportResult: Metadata about the created export.

        Raises:
            ExportError: If the export cannot be written.
        """
        entries = self.vault.list_entries()
        data = []
        try:
            for entry in entries:
                record = entry.to_dict()
                record["password"] = self.vault.get_decrypted_password(entry.entry_id)
                del record["encrypted_password"]
                data.append(record)

            file_path = self.export_dir / f"vault_export_{self._timestamp()}.json"
            with open(file_path, "w", encoding="utf-8") as handle:
                json.dump({"entries": data}, handle, indent=EXPORT_JSON_INDENT)
        except OSError as exc:
            raise ExportError(f"Failed to write JSON export: {exc}") from exc

        return ExportResult(
            file_path=file_path,
            sha256_hash=sha256_file(file_path),
            entry_count=len(data),
            created_at=datetime.now().isoformat(),
        )

    def export_csv(self) -> ExportResult:
        """Export all vault entries (with decrypted passwords) to a CSV file.

        Returns:
            ExportResult: Metadata about the created export.

        Raises:
            ExportError: If the export cannot be written.
        """
        entries = self.vault.list_entries()
        try:
            file_path = self.export_dir / f"vault_export_{self._timestamp()}.csv"
            with open(file_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=EXPORT_CSV_FIELDNAMES)
                writer.writeheader()
                for entry in entries:
                    writer.writerow(
                        {
                            "entry_id": entry.entry_id,
                            "service": entry.service,
                            "username": entry.username,
                            "password": self.vault.get_decrypted_password(entry.entry_id),
                            "url": entry.url,
                            "notes": entry.notes,
                            "created_at": entry.created_at,
                            "updated_at": entry.updated_at,
                        }
                    )
        except OSError as exc:
            raise ExportError(f"Failed to write CSV export: {exc}") from exc

        return ExportResult(
            file_path=file_path,
            sha256_hash=sha256_file(file_path),
            entry_count=len(entries),
            created_at=datetime.now().isoformat(),
        )

    def export_zip(self) -> ExportResult:
        """Export the raw (still-encrypted) vault file into a ZIP archive.

        Unlike :meth:`export_json` and :meth:`export_csv`, this method
        archives the vault file as-is (passwords remain encrypted),
        making it suitable as a portable, secure backup rather than a
        human-readable export.

        Returns:
            ExportResult: Metadata about the created export.

        Raises:
            ExportError: If the export cannot be written.
        """
        try:
            file_path = self.export_dir / f"vault_backup_{self._timestamp()}.zip"
            with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.write(self.vault.vault_path, arcname="vault.json")
        except OSError as exc:
            raise ExportError(f"Failed to write ZIP export: {exc}") from exc

        return ExportResult(
            file_path=file_path,
            sha256_hash=sha256_file(file_path),
            entry_count=len(self.vault),
            created_at=datetime.now().isoformat(),
        )

    def verify_export(self, file_path: Path, expected_hash: str) -> bool:
        """Verify an exported file's integrity against a known SHA-256 hash.

        Args:
            file_path: Path to the exported file.
            expected_hash: The SHA-256 hash to compare against.

        Returns:
            bool: True if the file's current hash matches ``expected_hash``.

        Raises:
            ExportError: If the file does not exist.
        """
        if not file_path.exists():
            raise ExportError(f"Export file not found: {file_path}")
        return sha256_file(file_path) == expected_hash

    def restore_from_zip(self, zip_path: Path) -> None:
        """Restore the vault from a ZIP backup created by :meth:`export_zip`.

        Args:
            zip_path: Path to the ZIP archive to restore from.

        Raises:
            RestoreError: If the archive is missing, malformed, or does
                not contain a valid vault file.
        """
        if not zip_path.exists():
            raise RestoreError(f"Backup archive not found: {zip_path}")
        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                if "vault.json" not in archive.namelist():
                    raise RestoreError("Backup archive does not contain a vault.json file.")
                extracted_dir = self.export_dir / "_restore_tmp"
                extracted_dir.mkdir(parents=True, exist_ok=True)
                archive.extract("vault.json", path=extracted_dir)
                restored_path = extracted_dir / "vault.json"
        except zipfile.BadZipFile as exc:
            raise RestoreError(f"Backup archive is corrupted: {exc}") from exc

        self.vault.restore_backup(restored_path)
