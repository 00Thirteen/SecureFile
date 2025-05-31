# 🔐 Secure File Encryption/Decryption Utility

**SecureFile** is a Python command-line utility for securely encrypting and decrypting files using **AES-GCM** encryption and strong, password-based key derivation with **Argon2id** or **PBKDF2**.

---

## 🚀 Features

- ✅ **AES-GCM encryption** (authenticated encryption with 256-bit keys)
- 🔑 **Argon2id** (default) or **PBKDF2-HMAC-SHA256** key derivation
- 🛡️ Optional **SHA-256 hash verification** to detect tampering
- 📦 Optional **GZIP compression** before encryption
- 🧹 **Secure deletion** of original files with cross-platform support
- 🖥️ **CLI-based workflow** for flexible and scriptable use
- 🔁 **Automatic decryption compatibility** with KDF detection

---

## 📋 Requirements

- Python 3.6+
- Dependencies:
  ```bash
  pip install cryptography argon2-cffi
  ```

---

## 🧑‍💻 Installation

1. Clone this repository or download `sf.py`.
2. Install the required packages as shown above.

---

## 🔧 Usage

Run from the terminal:

### 🔐 Encrypt a File

```bash
python sf.py --encrypt --input <input_file> --output <output_file> [options]
```

#### Encryption Options
- `--kdf argon2|pbkdf2` → Choose key derivation function (default: `argon2`)
- `--compress` → Compress input with GZIP before encryption
- `--no-hash` → Disable hash verification
- `--delete` → Securely delete input file after encryption
- `--overwrite` → Overwrite output file if it already exists

✅ Example:

```bash
python sf.py --encrypt --input notes.txt --output notes.enc --compress --delete
```

---

### 🔓 Decrypt a File

```bash
python sf.py --decrypt --input <input_file> --output <output_file> [options]
```

#### Decryption Options
- `--delete` → Securely delete encrypted file after decryption
- `--overwrite` → Overwrite the output file if it already exists

✅ Example:

```bash
python sf.py --decrypt --input notes.enc --output notes_restored.txt --delete
```

---

### 🔑 Password Input

- During encryption, you’ll enter your password **twice** for confirmation.
- During decryption, you’ll enter the password used during encryption.
- Passwords are **securely wiped from memory** after key derivation.

---

## 🔐 Security Details

| Area               | Implementation                                  |
|--------------------|--------------------------------------------------|
| **Encryption**      | AES-GCM (Galois/Counter Mode), 256-bit key       |
| **KDFs Supported**  | Argon2id (default), PBKDF2-HMAC-SHA256           |
| **Key Size**        | 256 bits (32 bytes)                              |
| **Integrity**       | SHA-256 hash (optional) + built-in GCM tag       |
| **Compression**     | Optional GZIP before encryption                  |
| **Deletion**        | Secure file overwrite + removal on Windows/Unix |
| **File Format**     | Custom binary format with embedded metadata      |

---

### 📦 File Format Layout

Each encrypted file includes the following header layout:

```
[1 byte]     → KDF method flag (0x01 = PBKDF2, 0x02 = Argon2)
[1 byte]     → Feature flags (compression, hash, etc.)
[4 bytes]    → Salt length (uint32)
[salt]       → Random salt for KDF
[12 bytes]   → Nonce used by AES-GCM
[ciphertext] → Encrypted and authenticated file contents
```

---

## 🧪 Troubleshooting

- Ensure your input/output paths are valid.
- Match encryption and decryption passwords exactly.
- If hash verification fails, the file may have been tampered with.
- If decryption fails, confirm the correct password and file format were used.

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🧠 Script Architecture

### 🔧 Class: `SecureFile`

Handles all secure operations:

| Method             | Description                                                |
|--------------------|------------------------------------------------------------|
| `_generate_salt()` | Generates a 256-bit salt                                    |
| `_get_password()`  | Securely prompts user for password                         |
| `_generate_key()`  | Uses Argon2id or PBKDF2 to derive encryption key           |
| `encrypt()`        | Encrypts file using AES-GCM with optional compression/hash |
| `decrypt()`        | Decrypts file and verifies integrity if enabled            |
| `_secure_delete()` | Securely deletes files via overwrite/removal               |