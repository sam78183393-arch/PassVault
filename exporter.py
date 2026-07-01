"""
SecureVault - Exporter Module
-----------------------------
This module handles exporting vault data into JSON and CSV formats.
It also creates timestamped backups for recovery.
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from password_manager import list_credentials

EXPORT_DIR = Path("data/backups")


def _timestamp() -> str:
    """Generate a timestamp string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_json() -> str:
    """
    Export vault data to a JSON file with timestamp.

    Returns:
        str: Path to exported file.
    """
    credentials: List[Dict[str, str]] = list_credentials()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = EXPORT_DIR / f"vault_backup_{_timestamp()}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(credentials, f, indent=4)

    return str(filename)


def export_csv() -> str:
    """
    Export vault data to a CSV file with timestamp.

    Returns:
        str: Path to exported file.
    """
    credentials: List[Dict[str, str]] = list_credentials()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = EXPORT_DIR / f"vault_backup_{_timestamp()}.csv"

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["website", "username", "password"])
        writer.writeheader()
        writer.writerows(credentials)

    return str(filename)


if __name__ == "__main__":
    # Example usage
    json_file = export_json()
    print(f"Exported JSON backup: {json_file}")

    csv_file = export_csv()
    print(f"Exported CSV backup: {csv_file}")
