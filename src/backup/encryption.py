"""
AES-256-GCM encryption for backup artifacts (Phase 40).
Provides authenticated encryption to prevent tampering and ensure confidentiality.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class BackupEncryption:
    """
    Handles authenticated encryption for backup artifacts.
    Uses AES-256-GCM with PBKDF2 key derivation.
    """

    ITERATIONS = 100_000
    SALT_SIZE = 16
    NONCE_SIZE = 12

    def __init__(self, secret_key: str):
        if not secret_key:
            raise ValueError("Secret key must not be empty")
        self.secret_key = secret_key.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit key from the secret and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(self.secret_key)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        Returns: salt (16) + nonce (12) + ciphertext + tag (16)
        """
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        key = self._derive_key(salt)
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None) # No associated data
        
        return salt + nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        Expects: salt (16) + nonce (12) + ciphertext + tag (16)
        """
        if len(encrypted_data) < self.SALT_SIZE + self.NONCE_SIZE + 16:
            raise ValueError("Invalid encrypted data format or too short")
            
        salt = encrypted_data[:self.SALT_SIZE]
        nonce = encrypted_data[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext = encrypted_data[self.SALT_SIZE + self.NONCE_SIZE :]
        
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        
        return aesgcm.decrypt(nonce, ciphertext, None)
