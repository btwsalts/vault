# 🔐 Vault

### Local Secrets Manager · Encryption · Authentication · Audit Logging

Vault is a learning-focused web application for storing personal secrets locally with encrypted secret values, password-hashed accounts, and an activity log.

## Features

- User registration and login
- Password hashing with Werkzeug
- Per-user Fernet encryption key
- Encrypted secret values in SQLite
- Categories and usernames/identifiers
- Copy-to-clipboard for revealed secrets
- Activity/audit history
- Local-only Flask interface
- Responsive dark UI

## Stack

Python · Flask · SQLite · Cryptography · HTML/CSS

## Run locally

```bash
git clone https://github.com/btwsalts/vault.git
cd vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:5000**.

## Security model

Passwords are stored as one-way password hashes. Secret values are encrypted with a Fernet key generated for each user. The database stores ciphertext rather than plaintext secret values.

## Important limitations

This is an educational local project, not a production password manager. The default Flask session secret is intended only for development and should be replaced with a strong random environment variable before any deployment. A production implementation would also need CSRF protection, secure cookie configuration, key rotation/recovery, rate limiting, stronger session management, and a carefully designed threat model.

## Roadmap

- REST API
- Search and filtering
- Import/export
- Secret editing
- Password generator
- CSRF protection
- Secure deployment configuration
- Automated tests
- Docker

## Author

Built by **btwsalts** as a cybersecurity and software-engineering learning project.
