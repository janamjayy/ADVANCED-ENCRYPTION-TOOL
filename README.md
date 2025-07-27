# ADVANCED-ENCRYPTION-TOOL

A simple command-line utility for AES-256 file encryption and decryption using password-based key derivation.

## Features

- AES-256 encryption (CBC mode) with PBKDF2-HMAC-SHA256 key derivation
- Secure random salt and IV for each encryption
- Password confirmation for encryption
- Logging of encryption and decryption operations
- Overwrite protection for output files

## Requirements

- Python 3.6+
- [pycryptodome](https://pypi.org/project/pycryptodome/)

Install dependencies:
```sh
pip install pycryptodome
```

## Usage

### Encrypt a file

```sh
python main.py encrypt <input_file> <output_file>
```

Example:
```sh
python main.py encrypt secret.txt enc.bin
```

You will be prompted to enter and confirm a password.

### Decrypt a file

```sh
python main.py decrypt <input_file> <output_file>
```

Example:
```sh
python main.py decrypt enc.bin output.txt
```

You will be prompted to enter the password used for encryption.

## Logging

All operations are logged to `encryption_log.txt` in the project directory.

## File Structure

- `main.py` — Command-line interface and logging
- `crypto_tool.py` — Encryption/decryption logic
- `encryption_log.txt` — Log file for operations
- `secret.txt` — Example plaintext file

## Security Notes

- Passwords are not stored.
- Use strong, unique passwords.
- Encrypted files contain the salt and IV prepended to the ciphertext.
