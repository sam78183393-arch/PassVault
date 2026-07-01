"""
SecureVault - Password Manager
------------------------------
This module manages credentials (website, username, password).
Operations:
- Add credentials
- Search credentials
- Update credentials
- Delete credentials
- List all entries

Passwords are encrypted using Fernet before storage.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from encryption import encrypt_password, decrypt_password, load_key  # ✅ fixed import

VAULT_FILE = Path("data/vault.json")


def _load_vault() -> List[Dict[str, str]]:
    """Load vault data from JSON file."""
    if not VAULT_FILE.exists():
        return []
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def _save_vault(data: List[Dict[str, str]]) -> None:
    """Save vault data to JSON file."""
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def add_credential(website: str, username: str, password: str) -> None:
    """Add a new credential to the vault."""
    vault = _load_vault()
    key = load_key()
    encrypted_password = encrypt_password(password, key)
    vault.append({"website": website, "username": username, "password": encrypted_password})
    _save_vault(vault)


def search_credential(website: str) -> Optional[Dict[str, str]]:
    """Search for a credential by website."""
    vault = _load_vault()
    key = load_key()
    for entry in vault:
        if entry["website"].lower() == website.lower():
            decrypted_password = decrypt_password(entry["password"], key)
            return {"website": entry["website"], "username": entry["username"], "password": decrypted_password}
    return None


def update_credential(website: str, username: str, new_password: str) -> bool:
    """Update password for a given website and username."""
    vault = _load_vault()
    key = load_key()
    for entry in vault:
        if entry["website"].lower() == website.lower() and entry["username"].lower() == username.lower():
            entry["password"] = encrypt_password(new_password, key)
            _save_vault(vault)
            return True
    return False


def delete_credential(website: str, username: str) -> bool:
    """Delete a credential from the vault."""
    vault = _load_vault()
    new_vault = [entry for entry in vault if not (
        entry["website"].lower() == website.lower() and entry["username"].lower() == username.lower()
    )]
    if len(new_vault) != len(vault):
        _save_vault(new_vault)
        return True
    return False


def list_credentials() -> List[Dict[str, str]]:
    """List all credentials (passwords decrypted)."""
    vault = _load_vault()
    key = load_key()
    result = []
    for entry in vault:
        decrypted_password = decrypt_password(entry["password"], key)
        result.append({"website": entry["website"], "username": entry["username"], "password": decrypted_password})
    return result


if __name__ == "__main__":
    # Example usage
    add_credential("example.com", "user1", "SecurePass123!")
    print(search_credential("example.com"))
    print(list_credentials())
