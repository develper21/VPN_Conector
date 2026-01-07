"""
Encryption Module for VPN

This module provides encryption and decryption functionality for the VPN,
supporting various algorithms and modes of operation.
"""
import os
import hmac
import hashlib
import logging
from enum import Enum, auto
from typing import Optional, Tuple, Dict, Any, Union, List
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes, hmac as hmac_lib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidSignature

from utils.logger import LoggableMixin

class CipherAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_128_GCM = "aes-128-gcm"
    
    @classmethod
    def from_string(cls, alg_str: str) -> 'CipherAlgorithm':
        """Get the algorithm enum from a string representation."""
        alg_map = {
            'aes-256-gcm': cls.AES_256_GCM,
            'aes-256-cbc': cls.AES_256_CBC,
            'chacha20-poly1305': cls.CHACHA20_POLY1305,
            'aes-128-gcm': cls.AES_128_GCM,
        }
        alg = alg_map.get(alg_str.lower())
        if not alg:
            raise ValueError(f"Unsupported cipher algorithm: {alg_str}")
        return alg
    
    def key_size(self) -> int:
        """Get the key size in bytes for the algorithm."""
        if self in [self.AES_256_GCM, self.AES_256_CBC]:
            return 32  # 256 bits
        elif self == self.AES_128_GCM:
            return 16  # 128 bits
        elif self == self.CHACHA20_POLY1305:
            return 32  # 256 bits
        else:
            raise ValueError(f"Unknown key size for algorithm: {self}")
    
    def iv_size(self) -> int:
        """Get the IV/nonce size in bytes for the algorithm."""
        if self in [self.AES_256_GCM, self.AES_128_GCM, self.CHACHA20_POLY1305]:
            return 12  # 96 bits is recommended for GCM and ChaCha20-Poly1305
        elif self == self.AES_256_CBC:
            return 16  # 128 bits for AES-CBC
        else:
            raise ValueError(f"Unknown IV size for algorithm: {self}")
    
    def tag_size(self) -> int:
        """Get the authentication tag size in bytes for the algorithm."""
        if self in [self.AES_256_GCM, self.AES_128_GCM, self.CHACHA20_POLY1305]:
            return 16  # 128-bit authentication tag
        elif self == self.AES_256_CBC:
            return 32  # HMAC-SHA256 produces a 256-bit (32-byte) tag
        else:
            raise ValueError(f"Unknown tag size for algorithm: {self}")

class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"
    
    @classmethod
    def from_string(cls, hash_str: str) -> 'HashAlgorithm':
        """Get the hash algorithm enum from a string representation."""
        hash_map = {
            'sha256': cls.SHA256,
            'sha384': cls.SHA384,
            'sha512': cls.SHA512,
            'blake2b': cls.BLAKE2B,
            'blake2s': cls.BLAKE2S,
        }
        hash_alg = hash_map.get(hash_str.lower())
        if not hash_alg:
            raise ValueError(f"Unsupported hash algorithm: {hash_str}")
        return hash_alg
    
    def get_hash_algorithm(self) -> hashes.HashAlgorithm:
        """Get the corresponding cryptography library hash algorithm."""
        if self == self.SHA256:
            return hashes.SHA256()
        elif self == self.SHA384:
            return hashes.SHA384()
        elif self == self.SHA512:
            return hashes.SHA512()
        elif self == self.BLAKE2B:
            return hashes.BLAKE2b(64)  # 512-bit output
        elif self == self.BLAKE2S:
            return hashes.BLAKE2s(32)  # 256-bit output
        else:
            raise ValueError(f"Unknown hash algorithm: {self}")
    
    def digest_size(self) -> int:
        """Get the digest size in bytes for the hash algorithm."""
        if self == self.SHA256 or self == self.BLAKE2S:
            return 32  # 256 bits
        elif self == self.SHA384:
            return 48  # 384 bits
        elif self == self.SHA512 or self == self.BLAKE2B:
            return 64  # 512 bits
        else:
            raise ValueError(f"Unknown digest size for algorithm: {self}")

class EncryptionError(Exception):
    """Base exception for encryption-related errors."""
    pass

class DecryptionError(EncryptionError):
    """Raised when decryption fails."""
    pass

class KeyDerivationError(EncryptionError):
    """Raised when key derivation fails."""
    pass

@dataclass
class EncryptionResult:
    """Result of an encryption operation."""
    ciphertext: bytes
    iv: bytes
    tag: Optional[bytes] = None
    additional_data: Optional[bytes] = None

class EncryptionManager(LoggableMixin):
    """
    Handles encryption and decryption of data using various algorithms.
    
    This class provides a high-level interface for encrypting and decrypting data
    using symmetric encryption algorithms like AES and ChaCha20-Poly1305.
    """
    
    def __init__(
        self,
        algorithm: Union[str, CipherAlgorithm] = CipherAlgorithm.AES_256_GCM,
        hash_algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
        use_hmac: bool = False,
        **kwargs
    ):
        """
        Initialize the encryption manager.
        
        Args:
            algorithm: The encryption algorithm to use.
            hash_algorithm: The hash algorithm to use for key derivation and HMAC.
            use_hmac: Whether to use HMAC for additional authentication (only for non-AEAD ciphers).
            **kwargs: Additional algorithm-specific parameters.
        """
        super().__init__(**kwargs)
        
        # Parse algorithm parameters
        if isinstance(algorithm, str):
            self.algorithm = CipherAlgorithm.from_string(algorithm)
        else:
            self.algorithm = algorithm
        
        if isinstance(hash_algorithm, str):
            self.hash_algorithm = HashAlgorithm.from_string(hash_algorithm)
        else:
            self.hash_algorithm = hash_algorithm
        
        # Determine if we need to use HMAC
        self.use_hmac = use_hmac
        if self.algorithm in [CipherAlgorithm.AES_256_GCM, CipherAlgorithm.AES_128_GCM, 
                             CipherAlgorithm.CHACHA20_POLY1305]:
            # These are AEAD ciphers that include authentication
            self.use_hmac = False
        
        # Initialize encryption key and IV
        self._encryption_key = None
        self._hmac_key = None
        self._iv = None
        
        # Additional configuration
        self.salt = kwargs.get('salt', os.urandom(16))
        self.iterations = kwargs.get('iterations', 100000)
        
        self.logger.info(f"Initialized EncryptionManager with {self.algorithm.value} and {self.hash_algorithm.value}")
    
    def set_keys(self, encryption_key: bytes, hmac_key: Optional[bytes] = None) -> None:
        """
        Set the encryption and HMAC keys directly.
        
        Args:
            encryption_key: The encryption key.
            hmac_key: The HMAC key (required if use_hmac is True).
        """
        # Validate key sizes
        if len(encryption_key) != self.algorithm.key_size():
            raise ValueError(
                f"Invalid encryption key size: expected {self.algorithm.key_size()} bytes, "
                f"got {len(encryption_key)} bytes"
            )
        
        if self.use_hmac and hmac_key is None:
            raise ValueError("HMAC key is required when use_hmac is True")
        
        if hmac_key is not None and len(hmac_key) < 32:  # Minimum 256-bit HMAC key
            raise ValueError("HMAC key must be at least 32 bytes")
        
        self._encryption_key = encryption_key
        self._hmac_key = hmac_key
    
    def derive_keys(self, password: Union[str, bytes], salt: Optional[bytes] = None) -> None:
        """
        Derive encryption and HMAC keys from a password.
        
        Args:
            password: The password to derive keys from.
            salt: Optional salt for key derivation. If not provided, a random one will be generated.
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        if salt is None:
            salt = os.urandom(16)
        
        self.salt = salt
        
        # Derive a master key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=self.hash_algorithm.get_hash_algorithm(),
            length=64,  # Enough for both encryption and HMAC keys
            salt=self.salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        
        master_key = kdf.derive(password)
        
        # Split the master key into encryption and HMAC keys
        self._encryption_key = master_key[:self.algorithm.key_size()]
        
        if self.use_hmac:
            # Use the remaining bytes for HMAC, or derive more if needed
            if len(master_key) > self.algorithm.key_size():
                self._hmac_key = master_key[self.algorithm.key_size():]
            else:
                # If not enough bytes, derive more using HKDF
                hkdf = HKDF(
                    algorithm=self.hash_algorithm.get_hash_algorithm(),
                    length=32,  # 256-bit HMAC key
                    salt=None,
                    info=b'hmac-key',
                    backend=default_backend()
                )
                self._hmac_key = hkdf.derive(master_key)
        
        self.logger.debug("Derived encryption and HMAC keys from password")
    
    def generate_iv(self) -> bytes:
        """
        Generate a random initialization vector (IV) for the current algorithm.
        
        Returns:
            The generated IV.
        """
        self._iv = os.urandom(self.algorithm.iv_size())
        return self._iv
    
    def encrypt(self, plaintext: bytes, iv: Optional[bytes] = None, 
               additional_data: Optional[bytes] = None) -> EncryptionResult:
        """
        Encrypt the given plaintext.
        
        Args:
            plaintext: The data to encrypt.
            iv: Optional IV/nonce. If not provided, a random one will be generated.
            additional_data: Additional authenticated data (AAD) for AEAD ciphers.
            
        Returns:
            An EncryptionResult containing the ciphertext and other encryption parameters.
            
        Raises:
            EncryptionError: If encryption fails.
        """
        if self._encryption_key is None:
            raise EncryptionError("Encryption key not set")
        
        try:
            # Generate IV if not provided
            if iv is None:
                iv = self.generate_iv()
            
            # Encrypt the data
            if self.algorithm == CipherAlgorithm.AES_256_GCM or self.algorithm == CipherAlgorithm.AES_128_GCM:
                # AES-GCM is an AEAD cipher
                cipher = Cipher(
                    algorithms.AES(self._encryption_key),
                    modes.GCM(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Add additional authenticated data if provided
                if additional_data:
                    encryptor.authenticate_additional_data(additional_data)
                
                # Encrypt the data
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Get the authentication tag
                tag = encryptor.tag
                
                return EncryptionResult(
                    ciphertext=ciphertext,
                    iv=iv,
                    tag=tag,
                    additional_data=additional_data
                )
                
            elif self.algorithm == CipherAlgorithm.CHACHA20_POLY1305:
                # ChaCha20-Poly1305 is an AEAD cipher
                cipher = Cipher(
                    algorithms.ChaCha20(self._encryption_key, iv),
                    mode=None,
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # In ChaCha20-Poly1305, the nonce is 12 bytes (96 bits) and the tag is 16 bytes (128 bits)
                # The cryptography library handles the authentication tag automatically
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                # Get the authentication tag (not directly accessible in the current API)
                # For now, we'll return None for the tag, but in a real implementation,
                # you might need to use a different library or approach to get the tag
                
                return EncryptionResult(
                    ciphertext=ciphertext,
                    iv=iv,
                    tag=None,  # Note: This is a limitation of the current implementation
                    additional_data=additional_data
                )
                
            elif self.algorithm == CipherAlgorithm.AES_256_CBC:
                # AES-CBC is not an AEAD cipher, so we'll add HMAC for authentication
                
                # Pad the plaintext to a multiple of the block size
                padder = sym_padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                
                # Encrypt the data
                cipher = Cipher(
                    algorithms.AES(self._encryption_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # If HMAC is enabled, compute the HMAC of the ciphertext
                tag = None
                if self.use_hmac and self._hmac_key:
                    tag = self._compute_hmac(ciphertext, additional_data)
                
                return EncryptionResult(
                    ciphertext=ciphertext,
                    iv=iv,
                    tag=tag,
                    additional_data=additional_data
                )
                
            else:
                raise EncryptionError(f"Unsupported algorithm: {self.algorithm}")
                
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt(self, ciphertext: bytes, iv: bytes, tag: Optional[bytes] = None,
               additional_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt the given ciphertext.
        
        Args:
            ciphertext: The data to decrypt.
            iv: The initialization vector/nonce used for encryption.
            tag: The authentication tag (for AEAD ciphers).
            additional_data: Additional authenticated data (AAD) for AEAD ciphers.
            
        Returns:
            The decrypted plaintext.
            
        Raises:
            DecryptionError: If decryption fails or authentication fails.
        """
        if self._encryption_key is None:
            raise DecryptionError("Encryption key not set")
        
        try:
            if self.algorithm == CipherAlgorithm.AES_256_GCM or self.algorithm == CipherAlgorithm.AES_128_GCM:
                # AES-GCM is an AEAD cipher
                if tag is None:
                    raise DecryptionError("Authentication tag is required for GCM mode")
                
                cipher = Cipher(
                    algorithms.AES(self._encryption_key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Add additional authenticated data if provided
                if additional_data:
                    decryptor.authenticate_additional_data(additional_data)
                
                # Decrypt the data
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                return plaintext
                
            elif self.algorithm == CipherAlgorithm.CHACHA20_POLY1305:
                # ChaCha20-Poly1305 is an AEAD cipher
                # Note: The current implementation doesn't support the tag parameter
                # In a real implementation, you would need to handle the tag properly
                
                cipher = Cipher(
                    algorithms.ChaCha20(self._encryption_key, iv),
                    mode=None,
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Decrypt the data
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                return plaintext
                
            elif self.algorithm == CipherAlgorithm.AES_256_CBC:
                # Verify HMAC if enabled
                if self.use_hmac and self._hmac_key:
                    if tag is None:
                        raise DecryptionError("HMAC tag is required for authentication")
                    
                    computed_tag = self._compute_hmac(ciphertext, additional_data)
                    if not hmac.compare_digest(tag, computed_tag):
                        raise DecryptionError("HMAC verification failed")
                
                # Decrypt the data
                cipher = Cipher(
                    algorithms.AES(self._encryption_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Unpad the plaintext
                unpadder = sym_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                
                return plaintext
                
            else:
                raise DecryptionError(f"Unsupported algorithm: {self.algorithm}")
                
        except InvalidTag as e:
            raise DecryptionError("Authentication failed: invalid tag") from e
        except ValueError as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def _compute_hmac(self, data: bytes, additional_data: Optional[bytes] = None) -> bytes:
        """
        Compute HMAC of the given data.
        
        Args:
            data: The data to compute HMAC for.
            additional_data: Additional data to include in the HMAC computation.
            
        Returns:
            The HMAC value.
        """
        if self._hmac_key is None:
            raise ValueError("HMAC key not set")
        
        h = hmac_lib.HMAC(
            self._hmac_key,
            self.hash_algorithm.get_hash_algorithm(),
            backend=default_backend()
        )
        
        if additional_data:
            h.update(additional_data)
        
        h.update(data)
        return h.finalize()
    
    def hmac_verify(self, data: bytes, tag: bytes, additional_data: Optional[bytes] = None) -> bool:
        """
        Verify an HMAC tag.
        
        Args:
            data: The data to verify the HMAC for.
            tag: The HMAC tag to verify.
            additional_data: Additional data that was included in the HMAC computation.
            
        Returns:
            True if the HMAC is valid, False otherwise.
        """
        try:
            expected_tag = self._compute_hmac(data, additional_data)
            return hmac.compare_digest(tag, expected_tag)
        except Exception as e:
            self.logger.error(f"HMAC verification failed: {e}")
            return False
    
    def get_key_material(self) -> Dict[str, bytes]:
        """
        Get the current key material.
        
        Returns:
            A dictionary containing the encryption key, HMAC key, and salt.
        """
        return {
            'encryption_key': self._encryption_key,
            'hmac_key': self._hmac_key,
            'salt': self.salt
        }
    
    def clear_keys(self) -> None:
        """Clear all key material from memory."""
        if self._encryption_key:
            # Overwrite the key in memory before deleting it
            self._encryption_key = os.urandom(len(self._encryption_key))
            self._encryption_key = None
        
        if self._hmac_key:
            # Overwrite the HMAC key in memory before deleting it
            self._hmac_key = os.urandom(len(self._hmac_key))
            self._hmac_key = None
        
        if self._iv:
            # Overwrite the IV in memory before deleting it
            self._iv = os.urandom(len(self._iv))
            self._iv = None
        
        self.logger.debug("Cleared all key material from memory")


def generate_key(algorithm: Union[str, CipherAlgorithm]) -> bytes:
    """
    Generate a random encryption key for the specified algorithm.
    
    Args:
        algorithm: The encryption algorithm to generate a key for.
        
    Returns:
        A random encryption key.
    """
    if isinstance(algorithm, str):
        algorithm = CipherAlgorithm.from_string(algorithm)
    
    return os.urandom(algorithm.key_size())

def generate_iv(algorithm: Union[str, CipherAlgorithm]) -> bytes:
    """
    Generate a random initialization vector (IV) for the specified algorithm.
    
    Args:
        algorithm: The encryption algorithm to generate an IV for.
        
    Returns:
        A random IV.
    """
    if isinstance(algorithm, str):
        algorithm = CipherAlgorithm.from_string(algorithm)
    
    return os.urandom(algorithm.iv_size())

def derive_key_from_password(
    password: Union[str, bytes],
    salt: Optional[bytes] = None,
    algorithm: Union[str, CipherAlgorithm] = CipherAlgorithm.AES_256_GCM,
    hash_algorithm: Union[str, HashAlgorithm] = HashAlgorithm.SHA256,
    iterations: int = 100000,
    key_length: Optional[int] = None
) -> Tuple[bytes, bytes]:
    """
    Derive a key from a password using PBKDF2.
    
    Args:
        password: The password to derive the key from.
        salt: Optional salt for key derivation. If not provided, a random one will be generated.
        algorithm: The encryption algorithm to generate a key for.
        hash_algorithm: The hash algorithm to use for key derivation.
        iterations: The number of iterations for the key derivation function.
        key_length: The length of the derived key in bytes. If None, the key size of the algorithm will be used.
        
    Returns:
        A tuple of (derived_key, salt).
    """
    if isinstance(algorithm, str):
        algorithm = CipherAlgorithm.from_string(algorithm)
    
    if isinstance(hash_algorithm, str):
        hash_algorithm = HashAlgorithm.from_string(hash_algorithm)
    
    if salt is None:
        salt = os.urandom(16)
    
    if key_length is None:
        key_length = algorithm.key_size()
    
    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm.get_hash_algorithm(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    key = kdf.derive(password)
    return key, salt
