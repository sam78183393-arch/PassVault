"""
main.py
=======

Command-line interface for SecureVault.

Provides an interactive menu-driven CLI that ties together the
password generator, strength analyzer, vault manager, breach checker,
and exporter into a single application entry point.

Run with:
    python main.py
"""

from __future__ import annotations

import sys

from breach_checker import BreachChecker
from config import APP_NAME, DEFAULT_PASSWORD_LENGTH
from exceptions import SecureVaultError
from exporter import Exporter
from logger_config import get_audit_logger, setup_logging
from password_generator import PasswordGenerator
from password_manager import VaultManager
from password_strength_analyzer import PasswordStrengthAnalyzer

logger = setup_logging()
audit_logger = get_audit_logger()


def _print_header() -> None:
    """Print the application banner."""
    print("=" * 60)
    print(f"{APP_NAME}".center(60))
    print("=" * 60)


def _print_menu() -> None:
    """Print the main interactive menu."""
    print(
        """
1.  Generate a password
2.  Analyze password strength
3.  Add vault entry
4.  List vault entries
5.  Search vault entries
6.  View a password
7.  Update an entry
8.  Delete an entry
9.  Check a password against known breaches
10. Export vault (JSON)
11. Export vault (CSV)
12. Export vault (ZIP backup)
13. Restore vault from ZIP backup
14. Verify vault integrity
15. Rotate encryption key
0.  Exit
"""
    )


def _prompt(text: str) -> str:
    """Prompt the user for input, stripping surrounding whitespace.

    Args:
        text: The prompt text to display.

    Returns:
        str: The user's input, stripped.
    """
    return input(text).strip()


def handle_generate(generator_factory) -> None:
    """Handle the 'generate a password' menu action."""
    try:
        length_input = _prompt(f"Length [{DEFAULT_PASSWORD_LENGTH}]: ")
        length = int(length_input) if length_input else DEFAULT_PASSWORD_LENGTH
        exclude_ambiguous = _prompt("Exclude ambiguous characters? (y/N): ").lower() == "y"
        generator = generator_factory(exclude_ambiguous=exclude_ambiguous)
        result = generator.generate(length)
        print(f"\nGenerated password: {result.password}")
        print(f"Entropy: {result.entropy_bits} bits | Strength: {result.strength_label}")
    except SecureVaultError as exc:
        print(f"Error: {exc}")
    except ValueError:
        print("Error: length must be a valid integer.")


def handle_analyze(analyzer: PasswordStrengthAnalyzer) -> None:
    """Handle the 'analyze password strength' menu action."""
    try:
        password = _prompt("Password to analyze: ")
        report = analyzer.analyze(password)
        print(f"\nScore: {report.score}/100 ({report.classification})")
        print(f"Entropy: {report.entropy_bits} bits")
        if report.suggestions:
            print("Suggestions:")
            for suggestion in report.suggestions:
                print(f"  - {suggestion}")
        else:
            print("No suggestions — this password looks solid.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_add_entry(vault: VaultManager) -> None:
    """Handle the 'add vault entry' menu action."""
    try:
        service = _prompt("Service: ")
        username = _prompt("Username: ")
        password = _prompt("Password: ")
        url = _prompt("URL (optional): ")
        notes = _prompt("Notes (optional): ")
        entry = vault.add_entry(service, username, password, url=url, notes=notes)
        audit_logger.info("Entry added: service=%s entry_id=%s", entry.service, entry.entry_id)
        print(f"\nEntry added with id: {entry.entry_id}")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_list_entries(vault: VaultManager) -> None:
    """Handle the 'list vault entries' menu action."""
    entries = vault.list_entries()
    if not entries:
        print("\nVault is empty.")
        return
    print(f"\n{'ID':<38} {'Service':<20} {'Username':<20}")
    print("-" * 78)
    for entry in entries:
        print(f"{entry.entry_id:<38} {entry.service:<20} {entry.username:<20}")


def handle_search(vault: VaultManager) -> None:
    """Handle the 'search vault entries' menu action."""
    query = _prompt("Search term: ")
    matches = vault.search_entries(query)
    if not matches:
        print("\nNo matches found.")
        return
    for entry in matches:
        print(f"{entry.entry_id} | {entry.service} | {entry.username}")


def handle_view_password(vault: VaultManager) -> None:
    """Handle the 'view a password' menu action."""
    try:
        entry_id = _prompt("Entry ID: ")
        password = vault.get_decrypted_password(entry_id)
        print(f"\nPassword: {password}")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_update_entry(vault: VaultManager) -> None:
    """Handle the 'update an entry' menu action."""
    try:
        entry_id = _prompt("Entry ID: ")
        print("Leave a field blank to keep its current value.")
        service = _prompt("New service: ") or None
        username = _prompt("New username: ") or None
        password = _prompt("New password: ") or None
        url = _prompt("New URL: ") or None
        notes = _prompt("New notes: ") or None
        entry = vault.update_entry(
            entry_id, service=service, username=username, password=password, url=url, notes=notes
        )
        audit_logger.info("Entry updated: entry_id=%s", entry.entry_id)
        print("\nEntry updated.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_delete_entry(vault: VaultManager) -> None:
    """Handle the 'delete an entry' menu action."""
    try:
        entry_id = _prompt("Entry ID: ")
        confirm = _prompt("Are you sure? (y/N): ").lower()
        if confirm == "y":
            vault.delete_entry(entry_id)
            audit_logger.info("Entry deleted: entry_id=%s", entry_id)
            print("\nEntry deleted.")
        else:
            print("\nCancelled.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_breach_check(checker: BreachChecker) -> None:
    """Handle the 'check a password against known breaches' menu action."""
    try:
        password = _prompt("Password to check: ")
        result = checker.check_password(password)
        if result.is_breached:
            print(f"\nWARNING: This password has appeared in {result.occurrence_count} known breaches!")
        else:
            print("\nGood news: this password was not found in known breaches.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_export(exporter: Exporter, fmt: str) -> None:
    """Handle export menu actions for a given format.

    Args:
        exporter: The exporter instance to use.
        fmt: One of "json", "csv", "zip".
    """
    try:
        method = {"json": exporter.export_json, "csv": exporter.export_csv, "zip": exporter.export_zip}[fmt]
        result = method()
        audit_logger.info("Vault exported: format=%s file=%s", fmt, result.file_path)
        print(f"\nExported to: {result.file_path}")
        print(f"SHA-256: {result.sha256_hash}")
        print(f"Entries exported: {result.entry_count}")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_restore(exporter: Exporter) -> None:
    """Handle the 'restore vault from ZIP backup' menu action."""
    try:
        from pathlib import Path

        zip_path = Path(_prompt("Path to ZIP backup: "))
        exporter.restore_from_zip(zip_path)
        audit_logger.info("Vault restored from: %s", zip_path)
        print("\nVault restored successfully.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def handle_verify_integrity(vault: VaultManager) -> None:
    """Handle the 'verify vault integrity' menu action."""
    if vault.verify_integrity():
        print("\nVault integrity check passed: all entries decrypt successfully.")
    else:
        print("\nVault integrity check FAILED: one or more entries could not be decrypted.")


def handle_rotate_key(vault: VaultManager) -> None:
    """Handle the 'rotate encryption key' menu action.

    Re-encrypts every vault entry's password under a newly generated key.
    """
    try:
        old_fernet = vault.encryption.rotate_key()
        for entry in vault.list_entries():
            plaintext = old_fernet.decrypt(entry.encrypted_password.encode("utf-8")).decode("utf-8")
            vault.update_entry(entry.entry_id, password=plaintext)
        audit_logger.info("Encryption key rotated; %d entries re-encrypted.", len(vault))
        print(f"\nKey rotated. {len(vault)} entries re-encrypted under the new key.")
    except SecureVaultError as exc:
        print(f"Error: {exc}")


def main() -> None:
    """Run the SecureVault interactive CLI."""
    _print_header()

    try:
        vault = VaultManager()
    except SecureVaultError as exc:
        print(f"Fatal: could not initialize vault: {exc}")
        sys.exit(1)

    analyzer = PasswordStrengthAnalyzer()
    checker = BreachChecker()
    exporter = Exporter(vault)

    def generator_factory(exclude_ambiguous: bool) -> PasswordGenerator:
        return PasswordGenerator(exclude_ambiguous=exclude_ambiguous)

    actions = {
        "1": lambda: handle_generate(generator_factory),
        "2": lambda: handle_analyze(analyzer),
        "3": lambda: handle_add_entry(vault),
        "4": lambda: handle_list_entries(vault),
        "5": lambda: handle_search(vault),
        "6": lambda: handle_view_password(vault),
        "7": lambda: handle_update_entry(vault),
        "8": lambda: handle_delete_entry(vault),
        "9": lambda: handle_breach_check(checker),
        "10": lambda: handle_export(exporter, "json"),
        "11": lambda: handle_export(exporter, "csv"),
        "12": lambda: handle_export(exporter, "zip"),
        "13": lambda: handle_restore(exporter),
        "14": lambda: handle_verify_integrity(vault),
        "15": lambda: handle_rotate_key(vault),
    }

    while True:
        _print_menu()
        choice = _prompt("Select an option: ")
        if choice == "0":
            print("Goodbye.")
            break
        action = actions.get(choice)
        if action is None:
            print("Invalid option.")
            continue
        try:
            action()
        except Exception as exc:  # pragma: no cover - top-level safety net
            logger.error("Unhandled error in menu action %s: %s", choice, exc)
            print(f"An unexpected error occurred: {exc}")


if __name__ == "__main__":
    main()
