# --- test_secure_file.py ---#
import os
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sf import SecureFile, NONCE_SIZE


class TestSecureFile(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.input_path = os.path.join(self.temp_dir, "test_input.txt")
        self.output_path = os.path.join(self.temp_dir, "test_output.sec")
        self.decrypted_path = os.path.join(self.temp_dir, "test_decrypted.txt")
        with open(self.input_path, 'w') as f:
            f.write("Secret message.")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('getpass.getpass', return_value='password')
    def test_encrypt_decrypt(self, _):
        sf = SecureFile(self.input_path, self.output_path)
        sf.encrypt()
        sf = SecureFile(self.output_path, self.decrypted_path)
        sf.decrypt()
        with open(self.decrypted_path) as f:
            self.assertEqual(f.read(), "Secret message.")

    @patch('getpass.getpass', return_value='password')
    def test_compression(self, _):
        sf = SecureFile(self.input_path, self.output_path)
        sf.encrypt(compress=True)
        sf = SecureFile(self.output_path, self.decrypted_path)
        sf.decrypt()
        with open(self.decrypted_path) as f:
            self.assertEqual(f.read(), "Secret message.")

    @patch('getpass.getpass', return_value='password')
    def test_no_hash(self, _):
        sf = SecureFile(self.input_path, self.output_path)
        sf.encrypt(no_hash=True)
        sf = SecureFile(self.output_path, self.decrypted_path)
        sf.decrypt()
        with open(self.decrypted_path) as f:
            self.assertEqual(f.read(), "Secret message.")

    @patch('getpass.getpass', return_value='password')
    def test_missing_file(self, _):
        sf = SecureFile("nonexistent.txt", self.output_path)
        with self.assertLogs(level='ERROR') as cm:
            sf.encrypt()
        self.assertIn("File not found", cm.output[0])

    @patch('getpass.getpass', side_effect=['wrong', 'right', 'wrong', 'right', 'wrong', 'right'])
    def test_password_failure(self, _):
        sf = SecureFile(self.input_path, self.output_path)
        with self.assertRaises(ValueError):
            sf._get_password()

    @patch('getpass.getpass', side_effect=['password', 'password', 'password'])  # 3 calls: 2 for encrypt, 1 for decrypt
    def test_hash_mismatch(self, _):
        sf = SecureFile(self.input_path, self.output_path)
        sf.encrypt()

        # Decrypt to get plain_bytes and manually corrupt hash
        with open(self.output_path, 'rb') as f:
            kdf_method = struct.unpack('B', f.read(1))[0]
            flags = struct.unpack('B', f.read(1))[0]
            salt_len = struct.unpack('>I', f.read(4))[0]
            salt = f.read(salt_len)
            nonce = f.read(NONCE_SIZE)
            encrypted_data = f.read()

        key = sf._generate_key(bytearray(b'password'), salt)
        aesgcm = AESGCM(key)
        plain_bytes = aesgcm.decrypt(nonce, encrypted_data, associated_data=None)

        corrupted = plain_bytes[:-32] + b'\\x00' * 32  # Overwrite hash with zeros

        # Re-encrypt and overwrite the file with corrupted content
        corrupted_encrypted = aesgcm.encrypt(nonce, corrupted, associated_data=None)
        with open(self.output_path, 'wb') as f:
            f.write(struct.pack('B', kdf_method))
            f.write(struct.pack('B', flags))
            f.write(struct.pack('>I', salt_len))
            f.write(salt)
            f.write(nonce)
            f.write(corrupted_encrypted)

        sf = SecureFile(self.output_path, self.decrypted_path)
        with self.assertRaises(Exception) as context:
            sf.decrypt()

        self.assertIn("Integrity check failed:  hash mismatch.", str(context.exception))


if __name__ == '__main__':
    unittest.main()
