# Security Policy

## Overview

SecureVault stores sensitive credential data and is designed with a security-first mindset throughout its architecture. This document describes the security model, known limitations, and how to report a vulnerability.

## Threat Model

SecureVault is designed as a **local, single-user credential manager**. It assumes:

- The user's machine and filesystem are reasonably trusted (SecureVault does not defend against an attacker with arbitrary code execution or root access on the host).
- The primary threats being defended against are: accidental disclosure (e.g. via logs, exports, or crash artifacts), tampering with vault data at rest, and reuse of breached or weak passwords.
- Network communication is limited to the HaveIBeenPwned breach-checking API, which is contacted using the k-Anonymity protocol described below.

## Data at Rest

- All stored passwords are encrypted using **Fernet** (`cryptography.fernet`), which combines AES-128 in CBC mode with HMAC-SHA256 for authenticated encryption. Ciphertext that has been tampered with will fail to decrypt rather than silently returning corrupted plaintext.
- The encryption key is stored in a separate, versioned key file (`data/key.json`), never hardcoded in source code.
- On POSIX systems, the key file is written with owner-only read/write permissions (`chmod 600`).
- Vault writes are **atomic**: data is written to a temporary file and then renamed into place, so a crash or power loss mid-write cannot corrupt the vault file.
- A timestamped backup is automatically created before every vault write, with automatic pruning beyond a configurable retention count.

## Data in Transit

- The only network calls SecureVault makes are to the HaveIBeenPwned Pwned Passwords API, using the **k-Anonymity model**: only the first 5 characters of a password's SHA-1 hash are transmitted. The full password and full hash never leave the local machine.
- All API requests are made over HTTPS, with a bounded timeout, retry with exponential backoff, and response validation.

## Logging

- SecureVault logs are split into application, error, and audit logs.
- A logging filter (`SensitiveDataFilter`) automatically masks values associated with sensitive field names (password, key, secret, token) before any log line is written to disk.
- Passwords and encryption keys are never intentionally logged in plaintext anywhere in the codebase.

## Exports

- JSON and CSV exports are, by design, human-readable and contain **decrypted plaintext passwords** — this is the explicit purpose of exporting. Exported files are not encrypted and are the user's responsibility to store securely or delete after use.
- ZIP backups (`export_zip`) archive the vault file as-is, so passwords remain encrypted within the archive.
- Every export includes a SHA-256 integrity hash so tampering can be detected later.

## Known Limitations

- The encryption key file itself is not additionally protected by a master password or key-derivation function in this version; anyone with read access to both `vault.json` and `key.json` can decrypt the vault. See "Future Scope" in the README for planned master-password-based key derivation.
- The dictionary-word check in the strength analyzer is a small, illustrative denylist, not a comprehensive breached-password corpus (breach corpus coverage is instead provided by the HaveIBeenPwned integration).
- SecureVault does not implement its own transport encryption; it relies entirely on HTTPS/TLS for the HaveIBeenPwned API call.

## Reporting a Vulnerability

If you discover a security vulnerability in SecureVault, please do not open a public issue. Instead, report it privately to the maintainers so a fix can be prepared before public disclosure. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, if applicable.
- Any suggested remediation.

We aim to acknowledge reports within a reasonable timeframe and to credit reporters (unless anonymity is requested) once a fix has been released.
