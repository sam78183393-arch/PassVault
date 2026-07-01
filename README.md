# 🔐 PassVault

**PassVault** is a command-line password security suite written in Python. It lets you generate strong passwords, analyze password strength, check passwords against known data breaches, and securely store, retrieve, and manage credentials — all from a simple interactive menu.

---

## ✨ Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Analyze Password** | Scores a password (0–100) and classifies it as Weak, Moderate, Strong, or Very Strong, with improvement suggestions. |
| 2 | **Generate Password** | Creates cryptographically secure passwords using Python's `secrets` module, with customizable length and character sets. |
| 3 | **Add Credential** | Stores a website/username/password entry in an encrypted local vault. |
| 4 | **Search Credential** | Looks up and decrypts a stored credential by website. |
| 5 | **Update Credential** | Updates the password for an existing website/username pair. |
| 6 | **Delete Credential** | Removes a credential from the vault. |
| 7 | **List Credentials** | Displays all stored credentials (decrypted). |
| 8 | **Check Password Breach** | Checks a password against the [Have I Been Pwned](https://haveibeenpwned.com/) database using the k-anonymity model (your password is never sent over the network). |
| 9 | **Export Data** | Exports the vault to timestamped JSON and CSV backups. |
| 0 | **Exit** | Closes the application. |

---

## 🗂️ Project Structure

```
PassVault/
├── main.py                        # CLI entry point and interactive menu
├── password_generator.py          # Secure password generation
├── password_strength_analyzer.py  # Password strength scoring
├── breach_checker.py              # HaveIBeenPwned breach lookup
├── password_manager.py            # CRUD operations on the credential vault
├── encryption.py                  # Fernet-based encryption/decryption + key management
├── exporter.py                    # JSON/CSV export & backup
├── logger_config.py               # Centralized logging setup
├── utils.py                       # Shared CLI menu helpers
├── requirements.txt                # Project dependencies
└── data/                          # Created at runtime (vault, key, backups)
    ├── vault.json
    ├── key.key
    └── backups/
```

---

## ⚙️ Requirements

- Python 3.9+
- [`cryptography`](https://pypi.org/project/cryptography/) — for Fernet encryption
- [`requests`](https://pypi.org/project/requests/) — for the breach-check API calls

Install dependencies:

```bash
pip install -r requirements.txt
```

> **Note:** Make sure `requirements.txt` lists `cryptography` and `requests` — these are the two external packages this project depends on.

---

## 🚀 Getting Started

1. **Clone or download** this repository.
2. **Install dependencies** (see above).
3. **Run the app:**

   ```bash
   python main.py
   ```

4. Use the on-screen menu to generate passwords, analyze strength, check breaches, or manage your credential vault.

On first run, PassVault will automatically create:
- `data/key.key` — your local encryption key
- `data/vault.json` — your encrypted credential vault
- `logs/securevault.log` — application logs

---

## 🔒 Security Notes

- Passwords are encrypted at rest using **Fernet symmetric encryption** (AES-128 in CBC mode with HMAC authentication) before being written to `data/vault.json`.
- The encryption key is stored locally in `data/key.key`. **Anyone with access to this file can decrypt your vault** — keep it private, back it up securely, and never commit it to version control.
- Breach checking uses the **k-anonymity model**: only the first 5 characters of your password's SHA-1 hash are sent to the HaveIBeenPwned API, so your full password or hash is never exposed.
- `data/`, `logs/`, and other sensitive/generated paths should be excluded from version control via `.gitignore`.
- This tool is intended for personal/local use and educational purposes. For production-grade password management, consider a dedicated, audited solution.

---

## 📋 Example Usage

```
=== PassVault – Password Security Suite ===
1. Analyze Password
2. Generate Password
3. Add Credential
4. Search Credential
5. Update Credential
6. Delete Credential
7. List Credentials
8. Check Password Breach
9. Export Data
0. Exit
Enter choice: 2
Enter length (min 8): 16
Include uppercase? (y/n): y
Include lowercase? (y/n): y
Include digits? (y/n): y
Include symbols? (y/n): y
Generated Password: xK9!mQ2p$Lw7@rTz
```

---

## 🛠️ Logging

All actions (credential changes, password checks, errors, etc.) are logged to `logs/securevault.log` and printed to the console, using Python's built-in `logging` module (configured in `logger_config.py`).

---

## 📤 Exporting & Backups

Choosing **Export Data** from the menu creates timestamped backups of your vault in both JSON and CSV formats under `data/backups/`, e.g.:

```
data/backups/vault_backup_20260701_143022.json
data/backups/vault_backup_20260701_143022.csv
```

> ⚠️ Exported files contain **decrypted** passwords in plain text — store and share them carefully.

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome. Feel free to open an issue or submit a pull request.

---


