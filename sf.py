# --- SecureFile CLI Encryption/Decryption --- #
# --- sf.py --- #
"""
Secure File Encryption/Decryption Utility

This module provides functionality to encrypt and decrypt files with optional compression
and integrity verification using SHA-256. Password-based encryption is used with a high iteration PBKDF2 key derivation.
"""
import argparse
import base64
import getpass
import gzip
import hashlib
import io
import os
import struct
import logging

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secrets import token_bytes
from hmac import compare_digest

SALT_SIZE = 32
ITERATIONS = 600000
MAX_PASSWORD_ATTEMPTS = 3

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

class SecureFile:
    """
    A class to handle secure encryption and decryption of files.

    Attributes:
        input_file (str): Path to the input file.
        output_file (str): Path to the output file.
    """
    def __init__(self, input_file: str, output_file: str):
        """
        Initialize SecureFile with input and output file paths.
        """
        self.input_file = input_file
        self.output_file = output_file

    @staticmethod
    def _generate_salt() -> bytes:
        """Generate a random salt for key derivation."""
        return token_bytes(SALT_SIZE)

    @staticmethod
    def _get_password(purpose: str = "encryption") -> bytearray:
        """
        Prompt the user to enter a password securely.

        Args:
            purpose (str): Either "encryption" or "decryption".

        Returns:
            bytearray: The password in bytes.
        """
        attempts = 0
        while attempts < MAX_PASSWORD_ATTEMPTS:
            password_bytes = bytearray(getpass.getpass(f"Enter password for {purpose}:  "), 'utf-8')
            if purpose == "encryption":
                verify_password_bytes = bytearray(getpass.getpass(f"Re-enter password for {purpose}:  "), 'utf-8')
                if compare_digest(password_bytes, verify_password_bytes):
                    for i in range(len(verify_password_bytes)):
                        verify_password_bytes[i] = 0
                    del verify_password_bytes
                    return password_bytes
                else:
                    logging.warning("Passwords do not match. Please try again.")
            else:
                return password_bytes
            attempts += 1
        raise ValueError(f"Failed to enter the correct password after {MAX_PASSWORD_ATTEMPTS} attempts.")

    @staticmethod
    def _generate_key(password: bytes, salt: bytes) -> bytes:
        """
        Derive a cryptographic key from the password and salt.

        Args:
            password (bytes): The user's password.
            salt (bytes): Randomly generated salt.

        Returns:
            bytes: A base64-encoded key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def encrypt(self,
                delete: bool = False,
                overwrite: bool = False,
                compress: bool = False,
                no_hash: bool = False
                ) -> None:
        """
        Encrypt the input file and save it to the output file.

        Args:
            delete (bool): If True, securely delete the input file after encryption.
            overwrite (bool): If True, overwrite the output file if it exists.
            compress (bool): If True, compress the file before encryption.
            no_hash (bool): If True, skip SHA-256 hash computation.
        """
        salt = self._generate_salt()
        salt_length = len(salt)
        password_bytes = self._get_password()
        key = self._generate_key(password_bytes, salt)
        for i in range(len(password_bytes)):
            password_bytes[i] = 0
        del password_bytes

        fernet = Fernet(key)
        del key

        try:
            with open(self.input_file, 'rb') as f:
                plain_bytes = f.read()
        except FileNotFoundError:
            logging.error(f"File not found: {self.input_file}")
            return
        flags = 0x00
        if compress:
            compressed_stream = io.BytesIO()
            with gzip.GzipFile(fileobj=compressed_stream, mode='wb') as gz:
                gz.write(plain_bytes)
            plain_bytes = compressed_stream.getvalue()
            flags |= 0x02
            logging.info("GZIP compression successful.")

        if not no_hash:
            digest = hashlib.sha256(plain_bytes).digest()
            plain_bytes += digest
            flags |= 0x01

        encrypted_bytes = fernet.encrypt(plain_bytes)
        logging.info("Encryption successful.")

        save_data = struct.pack('B', flags) + struct.pack('>I', salt_length) + salt + encrypted_bytes

        if os.path.exists(self.output_file) and not overwrite:
            raise FileExistsError(
                f"Error: {self.output_file} already exists. Use '-ow' or '--overwrite' to force overwrite.")

        with open(self.output_file, 'wb') as f:
            f.write(save_data)
        logging.info(f"File {self.output_file} saved successfully.")

        if delete:
            self._secure_delete(self.input_file)

    def decrypt(self, delete: bool = False, overwrite: bool = False) -> None:
        """
        Decrypt the input file and save the result to the output file.

        Args:
            delete (bool): If True, securely delete the encrypted file after decryption.
            overwrite (bool): If True, overwrite the output file if it exists.
        """
        try:
            with open(self.input_file, 'rb') as f:
                flags_byte = f.read(1)
                if not flags_byte:
                    raise Exception("Missing flags byte in file.")
                flags = struct.unpack('B', flags_byte)[0]
                has_hash = flags & 0x01
                has_compression = flags & 0x02
                salt_length_bytes = f.read(4)
                if not salt_length_bytes:
                    raise Exception("File is empty or incomplete.")
                salt_length = struct.unpack('>I', salt_length_bytes)[0]
                salt = f.read(salt_length)
                if len(salt) != salt_length:
                    raise Exception("Could not read expected amount of salt.")
                encrypted_bytes = f.read()
        except FileNotFoundError as fnfe:
            logging.error(f"File not found: {fnfe}")
            return
        except struct.error as se:
            logging.error(f"Error reading file format: {se}")
            return

        password = self._get_password(purpose="decryption")
        key = self._generate_key(password, salt)
        for i in range(len(password)):
            password[i] = 0
        del password

        fernet = Fernet(key)
        del key

        try:
            plain_bytes = fernet.decrypt(encrypted_bytes)
            logging.info("Decryption successful.")
        except Exception as e:
            raise Exception(f"Decryption error: {e}")

        if has_hash:
            data, expected_hash = plain_bytes[:-32], plain_bytes[-32:]
            actual_hash = hashlib.sha256(data).digest()

            if not compare_digest(expected_hash, actual_hash):
                raise Exception("Integrity check failed:  hash mismatch.")
            else:
                plain_bytes = data
                logging.info("Hash verification passed.")

        if has_compression:
            try:
                compressed_stream = io.BytesIO(plain_bytes)
                with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gz:
                    plain_bytes = gz.read()
                logging.info("Decompressed GZIP-compressed content.")
            except gzip.BadGzipFile as e:
                raise Exception(f"Decompression failed: {e}")

        if os.path.exists(self.output_file) and not overwrite:
            logging.error(f"{self.output_file} already exists. Use '-ow' or '--overwrite' to force overwrite.")
            return

        with open(self.output_file, 'wb') as f:
            f.write(plain_bytes)
        logging.info(f"File {self.output_file} saved successfully.")

        if delete:
            self._secure_delete(self.input_file)

    @staticmethod
    def _secure_delete(filename: str):
        """
        Securely overwrite and delete a file from disk.

        Args:
            filename (str): The file path to delete.
        """
        try:
            file_size = os.path.getsize(filename)
            with open(filename, 'wb') as f:
                f.write(os.urandom(file_size))
            os.remove(filename)
            logging.info(f"Original file '{filename}' securely deleted.")
        except Exception as e:
            logging.warning(f"Error securely deleting file '{filename}': {e}")
            if os.name == 'nt':
                try:
                    os.system(f'del /f /q "{filename}"')
                    logging.info(f"Windows secure delete successful for '{filename}'.")
                    return
                except Exception as e:
                    logging.warning(f"Windows secure delete failed: {e}")
            elif os.name == 'posix':
                try:
                    os.system(f'shred -u "{filename}"')
                    logging.info(f"Unix/macOS secure delete successful for '{filename}'.")
                    return
                except Exception as e:
                    logging.warning(f"Unix/macOS secure delete failed: {e}")
            logging.warning("Secure delete fallback in use. File may not be securely removed.")

def main() -> None:
    """
    Entry point for command-line interface.
    Parses arguments and performs encryption or decryption accordingly.
    """
    parser = argparse.ArgumentParser(description="File Encryption/Decryption Utility")

    parser.add_argument("-i", "--input", required=True, help="File path requiring encryption or decryption.")
    parser.add_argument("-o", "--output", required=True, help="File path to save encrypted or decrypted file to.")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt input to output.")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt input to output.")

    parser.add_argument("-del", "--delete", action="store_true", help="Delete the input file after encryption/decryption.")
    parser.add_argument("-ow", "--overwrite", action="store_true", help="Overwrite the output file if it already exists.")
    parser.add_argument("-c", "--compress", action="store_true", help="Enable GZIP compression before encryption.")
    parser.add_argument("--no-hash", action="store_true", help="Disable hash verification.  A hash will not be created and saved during encryption.")
    args = parser.parse_args()
    sf = SecureFile(args.input, args.output)

    if args.encrypt:
        sf.encrypt(delete=args.delete, overwrite=args.overwrite, compress=args.compress, no_hash=args.no_hash)
    elif args.decrypt:
        sf.decrypt(delete=args.delete, overwrite=args.overwrite)

if __name__ == "__main__":
    main()
