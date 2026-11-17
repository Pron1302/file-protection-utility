# File Protection Utility

A Python program that converts file content into a protected (encrypted) format and restores it when the correct password is provided.

## Features

- Protect any file with a password
- Restore the original content with the same password
- Wrong password or tampered file is detected and rejected
- Uses only Python's built-in modules (no installation needed)

## How to Run

```
python file_protector.py
```

Choose **1** to protect a file or **2** to restore one, then enter the file path and password.

## How It Works

1. The password is converted into keys using PBKDF2 with a random salt.
2. File bytes are XOR-ed with a key-based pseudo-random stream.
3. An HMAC is stored with the file to verify the password and detect changes.
4. Restoring reverses the process only if the password is correct.

## Note

This project is for learning the concept of data protection and controlled access. For production use, rely on a vetted library such as `cryptography` (Fernet).

## Author

Pron1302
