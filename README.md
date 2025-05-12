
# Secure File Encryption/Decryption Utility

This Python script provides functionality to securely encrypt and decrypt files with optional compression and integrity verification using SHA-256. The utility leverages password-based encryption with a high iteration PBKDF2 key derivation method to ensure robust security.

## Features

- **Password-based encryption** using PBKDF2 with SHA-256
- **Integrity verification** with SHA-256 hash during encryption/decryption
- **Optional file compression** using GZIP
- **Secure file deletion** after encryption or decryption
- **Command-line interface** for ease of use

## Requirements

To use the Secure File Encryption/Decryption Utility, you'll need:
- Python 3.6 or higher
- The following Python libraries:
  - `cryptography` (install via `pip install cryptography`)
  - `getpass` (usually pre-installed with Python)
  - `gzip` (usually pre-installed with Python)
  - `struct` (usually pre-installed with Python)
  - `hmac` (usually pre-installed with Python)

## Installation

1. Clone the repository or download the `sf.py` file.
2. Install required dependencies:
   ```bash
   pip install cryptography
   ```

## Usage

You can use the script via the command line to encrypt or decrypt files.

### Encryption

To encrypt a file, run the following command:

```bash
python sf.py --encrypt --input <input_file> --output <output_file> [options]
```

#### Options:
- `--delete`: Securely delete the input file after encryption.
- `--overwrite`: Overwrite the output file if it already exists.
- `--compress`: Compress the file using GZIP before encryption.
- `--no-hash`: Disable hash verification (no SHA-256 hash will be saved during encryption).

Example:

```bash
python sf.py --encrypt --input example.txt --output example_encrypted.enc --compress --delete
```

This will encrypt `example.txt`, compress it before encryption, and securely delete the original file after encryption.

### Decryption

To decrypt a file, use the following command:

```bash
python sf.py --decrypt --input <input_file> --output <output_file> [options]
```

#### Options:
- `--delete`: Securely delete the encrypted file after decryption.
- `--overwrite`: Overwrite the output file if it already exists.

Example:

```bash
python sf.py --decrypt --input example_encrypted.enc --output example_decrypted.txt --delete
```

This will decrypt `example_encrypted.enc`, saving the result to `example_decrypted.txt`, and securely delete the encrypted file after decryption.

### Password Prompts

- During encryption, you will be asked to enter a password twice for confirmation.
- During decryption, you will be asked to enter the password used during encryption.

## Security

- **Password**: The password you choose is used to derive a cryptographic key using PBKDF2 with SHA-256, iterated 600,000 times, to make brute-force attacks more difficult.
- **Encryption**: The encryption algorithm used is AES with a 256-bit key, provided by the `cryptography` library's `Fernet` module.
- **Hash Verification**: During encryption, a SHA-256 hash of the file content is computed and stored. During decryption, this hash is used to verify the integrity of the file. If the hash does not match, the file has been tampered with.
- **File Deletion**: After encryption or decryption, you can choose to securely delete the input or encrypted file using methods designed for both Windows and UNIX-like systems.

## Troubleshooting

- If you encounter issues with file reading or writing, check that the paths to the input and output files are correct and that you have the necessary permissions.
- Ensure that the encryption and decryption passwords match. If the passwords do not match, decryption will fail.
- If you encounter any issues with compression or decompression, ensure that the file is correctly compressed and that it has not been corrupted.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Script Overview

The `sf.py` script is designed for secure file encryption and decryption. It utilizes the `cryptography` library to perform encryption with the `Fernet` symmetric encryption system, which is based on AES encryption. The script also includes features for file compression, hash verification, and secure file deletion.

### Classes
- **SecureFile**: This class handles file encryption and decryption, as well as password management, key generation, and file compression. It contains methods for encryption (`encrypt()`) and decryption (`decrypt()`), along with helper methods for secure password input and file handling.

### Methods
- `_generate_salt()`: Generates a random salt for key derivation.
- `_get_password()`: Prompts the user to securely input a password for encryption or decryption.
- `_generate_key()`: Generates a cryptographic key based on the user's password and salt.
- `encrypt()`: Encrypts the input file and saves the encrypted file to the output location.
- `decrypt()`: Decrypts the input file and saves the result to the output location.
- `_secure_delete()`: Securely deletes a file from disk after encryption or decryption.

---
