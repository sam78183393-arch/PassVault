"""Unit tests for exporter.py."""

from __future__ import annotations

import csv
import json

import pytest

from exceptions import ExportError, RestoreError
from exporter import Exporter


@pytest.fixture
def exporter(vault_manager, tmp_path):
    export_dir = tmp_path / "exports"
    return Exporter(vault_manager, export_dir=export_dir)


def test_export_json_creates_file_with_correct_entries(vault_manager, exporter):
    vault_manager.add_entry("ServiceA", "userA", "passA")
    result = exporter.export_json()

    assert result.file_path.exists()
    assert result.entry_count == 1

    data = json.loads(result.file_path.read_text())
    assert data["entries"][0]["password"] == "passA"
    assert "encrypted_password" not in data["entries"][0]


def test_export_csv_creates_file_with_header(vault_manager, exporter):
    vault_manager.add_entry("ServiceB", "userB", "passB")
    result = exporter.export_csv()

    assert result.file_path.exists()
    with open(result.file_path, newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["password"] == "passB"


def test_export_zip_contains_vault_json(vault_manager, exporter):
    vault_manager.add_entry("ServiceC", "userC", "passC")
    result = exporter.export_zip()
    assert result.file_path.exists()
    assert result.file_path.suffix == ".zip"


def test_verify_export_matches_hash(vault_manager, exporter):
    vault_manager.add_entry("ServiceD", "userD", "passD")
    result = exporter.export_json()
    assert exporter.verify_export(result.file_path, result.sha256_hash) is True


def test_verify_export_detects_tampering(vault_manager, exporter):
    vault_manager.add_entry("ServiceE", "userE", "passE")
    result = exporter.export_json()
    with open(result.file_path, "a") as handle:
        handle.write("\n// tampered")
    assert exporter.verify_export(result.file_path, result.sha256_hash) is False


def test_verify_export_missing_file_raises(exporter, tmp_path):
    missing = tmp_path / "does_not_exist.json"
    with pytest.raises(ExportError):
        exporter.verify_export(missing, "irrelevant-hash")


def test_export_zip_and_restore_roundtrip(vault_manager, exporter):
    vault_manager.add_entry("Persisted", "user", "pw")
    result = exporter.export_zip()

    vault_manager.add_entry("Extra", "user2", "pw2")
    assert len(vault_manager) == 2

    exporter.restore_from_zip(result.file_path)
    assert len(vault_manager) == 1
    assert vault_manager.list_entries()[0].service == "Persisted"


def test_restore_from_missing_zip_raises(exporter, tmp_path):
    missing = tmp_path / "missing.zip"
    with pytest.raises(RestoreError):
        exporter.restore_from_zip(missing)


def test_restore_from_corrupted_zip_raises(exporter, tmp_path):
    bad_zip = tmp_path / "bad.zip"
    bad_zip.write_text("not a real zip file")
    with pytest.raises(RestoreError):
        exporter.restore_from_zip(bad_zip)
