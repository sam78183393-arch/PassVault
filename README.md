# SecureVault

A production-quality, layered-architecture password management CLI written in Python 3.12+. SecureVault generates cryptographically secure passwords, analyzes password strength, stores credentials encrypted at rest, checks passwords against known breach corpora, and exports/backs up vault data with integrity verification.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Architecture](#architecture)
- [Folder Structure](#folder-structure)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [How to Test](#how-to-test)
- [Security Features](#security-features)
- [Screenshots](#screenshots)
- [Future Scope](#future-scope)
- [License](#license)

---

## Project Overview

SecureVault is a modular, layered CLI application for managing credentials securely. It was built to demonstrate production-grade Python engineering practices: strict layering, full type annotations, a custom exception hierarchy, comprehensive automated tests, and defense-in-depth security handling for secrets.

## Features

- **Secure password generation** — uses `secrets` exclusively (never `random`), guarantees inclusion of every selected character category, and performs a secure Fisher-Yates shuffle.
- **Password strength analysis** — scores passwords out of 100 based on length, character diversity, repeated/sequential runs, dictionary-word similarity, and entropy; returns actionable suggestions.
- **Encrypted vault storage** — every stored password is encrypted at rest with `cryptography.fernet`; atomic writes prevent partial/corrupted saves.
- **Full CRUD** — add, list, search, update, and delete credential entries, with duplicate detection.
- **Automatic backups** — a timestamped backup is taken before every vault write, with automatic pruning of old backups.
- **Vault schema versioning & migration** — older vault files are automatically migrated to the current schema on load.
- **Integrity verification** — verify that every stored entry can still be decrypted with the active key.
- **Breach checking** — checks passwords against the HaveIBeenPwned Pwned Passwords API using the k-Anonymity model (only a 5-character hash prefix ever leaves your machine), with retries, exponential backoff, and caching.
- **Exporting** — export the vault to JSON, CSV, or an encrypted ZIP backup, each with a SHA-256 integrity hash.
- **Key rotation** — rotate the encryption key and automatically re-encrypt every stored password.
- **Rotating, security-conscious logging** — separate application, error, and audit logs; sensitive fields (passwords, keys) are automatically masked before being written to disk.

## Architecture

SecureVault follows a strict layered architecture, with each module holding a single responsibility (SOLID principles):

```
        CLI (main.py)
             │
      Service / Business Logic
   (password_manager, password_generator,
    password_strength_analyzer, breach_checker,
    exporter)
             │
       Encryption Layer
        (encryption.py)
             │
        Storage Layer
     (vault.json / key.json)
```

Cross-cutting concerns (`config.py`, `exceptions.py`, `utils.py`, `logger_config.py`) are shared across every layer without introducing circular dependencies.

## Folder Structure

```
SecureVault/
├── main.py                        # CLI entry point
├── config.py                      # All configuration constants
├── password_manager.py            # Vault CRUD, persistence, backups
├── password_generator.py          # Secure password generation
├── password_strength_analyzer.py  # Password strength scoring
├── encryption.py                  # Fernet-based encryption layer
├── breach_checker.py              # HaveIBeenPwned k-Anonymity client
├── exporter.py                    # JSON/CSV/ZIP export & restore
├── logger_config.py               # Rotating, masked logging setup
├── exceptions.py                  # Custom exception hierarchy
├── utils.py                       # Shared validation/formatting helpers
│
├── data/
│   ├── vault.json                 # Encrypted credential vault
│   ├── key.json                   # Versioned encryption key file
│   └── backups/                   # Timestamped vault backups
│
├── logs/                          # Rotating application/error/audit logs
│
├── tests/                         # Pytest unit & integration tests
│   ├── conftest.py
│   ├── test_password_manager.py
│   ├── test_generator.py
│   ├── test_encryption.py
│   ├── test_exporter.py
│   ├── test_breach_checker.py
│   ├── test_strength.py
│   └── test_logger_config.py
│
├── README.md
├── requirements.txt
├── LICENSE
└── SECURITY.md
```

## Installation

Requires Python 3.12 or later.

```bash
git clone <this-repository>
cd SecureVault
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## How to Run

```bash
python main.py
```

You'll be presented with an interactive menu to generate passwords, analyze strength, manage vault entries, check for breaches, and export/back up your vault. On first run, SecureVault automatically creates `data/vault.json` and `data/key.json`.

## How to Test

```bash
pip install -r requirements.txt
pytest tests/ -v --cov=. --cov-report=term-missing
```

The suite includes unit tests for every module and integration tests covering the full add → persist → reload → backup → restore lifecycle, with the HaveIBeenPwned API mocked so tests never make real network calls. Business-logic coverage exceeds 90% (see `setup.cfg`, which excludes the thin interactive CLI wiring in `main.py` from the coverage target).

## Security Features

- Passwords are **never** stored in plaintext; all vault contents are encrypted with Fernet (AES-128 in CBC mode with HMAC authentication).
- Passwords and encryption keys are **never written to log files**; a logging filter automatically masks sensitive field values.
- Breach checks use the **k-Anonymity model** — only a 5-character hash prefix is ever transmitted; the full password and full hash never leave your machine.
- All vault writes are **atomic** (write-to-temp-then-rename), so a crash mid-write cannot corrupt the vault.
- Every vault write automatically creates a **timestamped backup**, with automatic pruning of old backups.
- The key file is written with **restrictive file permissions** (owner read/write only) on POSIX systems.
- All external input is validated before use; failures raise specific, typed exceptions rather than failing silently or insecurely.

See [SECURITY.md](SECURITY.md) for the full security policy.

## Screenshots

> _Screenshots of the CLI in action (menu, password generation, breach check, and export flows) go here. Run `python main.py` locally and capture your terminal session to fill in this section._

- `docs/screenshots/main-menu.png` — the interactive main menu
- `docs/screenshots/generate-password.png` — password generation with entropy/strength output
- `docs/screenshots/breach-check.png` — a breach check result
- `docs/screenshots/export-summary.png` — an export operation with its SHA-256 hash

## Future Scope

- Master-password-based key derivation (e.g. Argon2/PBKDF2) instead of a bare stored key file, so the vault is protected even if the key file is copied.
- A TOTP/2FA generator module for storing and generating one-time codes alongside credentials.
- A REST API layer on top of the existing service layer for browser-extension integration.
- Multi-user support with per-user encrypted vaults.
- Cross-vault password reuse detection.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
