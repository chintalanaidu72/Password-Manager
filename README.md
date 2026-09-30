# Password Manager – Python Internship Project

A desktop Password Manager built with **Python, Tkinter, SQLite and AES-256-GCM encryption**.

## Features
- Master password creation and login
- PBKDF2-HMAC-SHA256 key derivation
- AES-256-GCM encryption of stored credentials
- Add, view, update and delete credentials
- Password generator
- Local SQLite database
- Simple graphical user interface

## Project Structure
- `app.py` – main GUI and application logic
- `crypto_utils.py` – password hashing, key derivation and encryption
- `requirements.txt` – Python dependency
- `password_manager.db` – created automatically on first run

## Requirements
- Python 3.10 or later
- Tkinter (usually included with Python on Windows)
- Internet connection only for installing the cryptography package

## Run
Open a terminal in this folder:

```bash
python -m pip install -r requirements.txt
python app.py
```

On first launch, create a master password. On later launches, use it to unlock the vault.

## Security Design
The master password itself is not stored. A salted PBKDF2-derived value is stored for authentication. A separate PBKDF2-derived 256-bit key is used to encrypt/decrypt vault data. Credentials are encrypted using AES-GCM with a fresh random nonce for each value.

## Internship Explanation
This project demonstrates Python programming, GUI development, database operations, authentication, encryption, CRUD operations, testing and documentation.

## Important
This is an educational internship project. For a production password manager, additional protections such as OS keychain integration, memory-hard password derivation, secure clipboard handling, backups, audit logging and stronger threat modeling would be appropriate.
