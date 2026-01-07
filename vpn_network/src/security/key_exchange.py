"""
Key Exchange Module for VPN

This module provides key exchange functionality for the VPN, supporting various
algorithms for securely establishing shared secrets between clients and servers.
"""
import os
import logging
import hashlib
import hmac
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Optional, Dict, Any, Tuple, Union, List, Type, TypeVar

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh, x25519, x448, ed25519, ed448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_pem_private_key, Encoding, PublicFormat, PrivateFormat,
    NoEncryption, BestAvailableEncryption, KeySerializationEncryption
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes, PublicKeyTypes
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils.logger import LoggableMixin

# Type variable for key exchange classes
KT = TypeVar('KT', bound='KeyExchange')

class KeyExchangeError(Exception):
    """Base exception for key exchange errors."""
    pass

class KeyExchange(ABC, LoggableMixin):
    """Abstract base class for key exchange implementations."""
    
    def __init__(self, **kwargs):
        """Initialize the key exchange with the given parameters."""
        super().__init__(**kwargs)
        self._private_key = None
        self._public_key = None
        self._peer_public_key = None
        self._shared_secret = None
    
    @property
    def private_key(self) -> Optional[PrivateKeyTypes]:
        """Get the private key."""
        return self._private_key
    
    @property
    def public_key(self) -> Optional[PublicKeyTypes]:
        """Get the public key."""
        return self._public_key
    
    @property
    def peer_public_key(self) -> Optional[PublicKeyTypes]:
        """Get the peer's public key."""
        return self._peer_public_key
    
    @peer_public_key.setter
    def peer_public_key(self, key: Union[PublicKeyTypes, bytes, str]) -> None:
        """
        Set the peer's public key.
        
        Args:
            key: The peer's public key as a PublicKeyTypes object, PEM-encoded bytes, or PEM string.
            
        Raises:
            ValueError: If the key is invalid or cannot be loaded.
        """
        if key is None:
            self._peer_public_key = None
            return
        
        if isinstance(key, (str, bytes)):
            if isinstance(key, str):
                key = key.encode('utf-8')
            
            try:
                self._peer_public_key = load_pem_public_key(key, backend=default_backend())
            except Exception as e:
                raise ValueError(f"Failed to load public key: {e}") from e
        elif isinstance(key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey, dh.DHPublicKey,
                            x25519.X25519PublicKey, x448.X448PublicKey,
                            ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            self._peer_public_key = key
        else:
            raise ValueError(f"Unsupported public key type: {type(key).__name__}")
    
    @property
    def shared_secret(self) -> Optional[bytes]:
        """Get the shared secret (if it has been computed)."""
        return self._shared_secret
    
    @abstractmethod
    def generate_keypair(self) -> None:
        """Generate a new key pair."""
        pass
    
    @abstractmethod
    def compute_shared_secret(self) -> bytes:
        """
        Compute the shared secret using the peer's public key.
        
        Returns:
            The shared secret as bytes.
            
        Raises:
            KeyExchangeError: If the shared secret cannot be computed.
        """
        pass
    
    def derive_key(self, length: int = 32, salt: Optional[bytes] = None,
                  info: Optional[bytes] = None) -> bytes:
        """
        Derive a key from the shared secret using HKDF.
        
        Args:
            length: The length of the derived key in bytes.
            salt: Optional salt for the HKDF.
            info: Optional context and application specific information.
            
        Returns:
            The derived key.
            
        Raises:
            KeyExchangeError: If the shared secret has not been computed.
        """
        if self._shared_secret is None:
            raise KeyExchangeError("Shared secret has not been computed")
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        return hkdf.derive(self._shared_secret)
    
    def get_public_key_bytes(self, encoding: Encoding = Encoding.PEM) -> bytes:
        """
        Get the public key in the specified encoding.
        
        Args:
            encoding: The encoding format (PEM or DER).
            
        Returns:
            The public key as bytes.
            
        Raises:
            ValueError: If the public key is not set or the encoding is invalid.
        """
        if self._public_key is None:
            raise ValueError("Public key not generated")
        
        if encoding == Encoding.PEM:
            return self._public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        elif encoding == Encoding.DER:
            return self._public_key.public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    def get_private_key_bytes(self, password: Optional[bytes] = None,
                            encoding: Encoding = Encoding.PEM) -> bytes:
        """
        Get the private key in the specified encoding.
        
        Args:
            password: Optional password for encryption.
            encoding: The encoding format (PEM or DER).
            
        Returns:
            The private key as bytes.
            
        Raises:
            ValueError: If the private key is not set or the encoding is invalid.
        """
        if self._private_key is None:
            raise ValueError("Private key not generated")
        
        encryption_algorithm: KeySerializationEncryption
        if password:
            encryption_algorithm = BestAvailableEncryption(password)
        else:
            encryption_algorithm = NoEncryption()
        
        if encoding == Encoding.PEM:
            return self._private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        elif encoding == Encoding.DER:
            return self._private_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    def load_private_key(self, key_data: Union[bytes, str], 
                        password: Optional[bytes] = None) -> None:
        """
        Load a private key from PEM or DER encoded data.
        
        Args:
            key_data: The private key data as bytes or string.
            password: Optional password if the key is encrypted.
            
        Raises:
            ValueError: If the key data is invalid or cannot be loaded.
        """
        if isinstance(key_data, str):
            key_data = key_data.encode('utf-8')
        
        try:
            self._private_key = load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
            
            # Extract public key from private key
            if hasattr(self._private_key, 'public_key'):
                self._public_key = self._private_key.public_key()
            else:
                raise ValueError("Private key does not contain public key information")
                
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}") from e
    
    def clear(self) -> None:
        """Clear sensitive key material from memory."""
        if self._private_key is not None:
            # Overwrite the key in memory before deleting it
            if hasattr(self._private_key, 'private_bytes'):
                try:
                    # Try to get the key size and overwrite with random data
                    key_bytes = self.get_private_key_bytes()
                    self._private_key = None
                    if key_bytes:
                        os.urandom(len(key_bytes))
                except Exception:
                    pass
            else:
                self._private_key = None
        
        if self._shared_secret is not None:
            # Overwrite the shared secret in memory before deleting it
            os.urandom(len(self._shared_secret))
            self._shared_secret = None
        
        self._public_key = None
        self._peer_public_key = None
        
        self.logger.debug("Cleared all key material from memory")


class ECDHKeyExchange(KeyExchange):
    """Elliptic Curve Diffie-Hellman key exchange."""
    
    def __init__(self, curve=ec.SECP384R1(), **kwargs):
        """
        Initialize the ECDH key exchange.
        
        Args:
            curve: The elliptic curve to use (default: SECP384R1).
        """
        super().__init__(**kwargs)
        self.curve = curve
        self.logger.info(f"Initialized ECDH key exchange with curve {curve.name}")
    
    def generate_keypair(self) -> None:
        """Generate a new ECDH key pair."""
        try:
            self._private_key = ec.generate_private_key(
                curve=self.curve,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            self.logger.debug("Generated new ECDH key pair")
        except Exception as e:
            raise KeyExchangeError(f"Failed to generate ECDH key pair: {e}") from e
    
    def compute_shared_secret(self) -> bytes:
        """
        Compute the shared secret using the peer's public key.
        
        Returns:
            The shared secret as bytes.
            
        Raises:
            KeyExchangeError: If the shared secret cannot be computed.
        """
        if self._private_key is None:
            raise KeyExchangeError("Private key not generated")
        
        if self._peer_public_key is None:
            raise KeyExchangeError("Peer public key not set")
        
        try:
            self._shared_secret = self._private_key.exchange(
                algorithm=ec.ECDH(),
                peer_public_key=self._peer_public_key
            )
            
            self.logger.debug("Computed ECDH shared secret")
            return self._shared_secret
            
        except Exception as e:
            raise KeyExchangeError(f"Failed to compute ECDH shared secret: {e}") from e


class RSAKeyExchange(KeyExchange):
    """RSA-based key exchange (RSA-KEM)."""
    
    def __init__(self, key_size: int = 3072, **kwargs):
        """
        Initialize the RSA key exchange.
        
        Args:
            key_size: The RSA key size in bits (default: 3072).
        """
        super().__init__(**kwargs)
        self.key_size = key_size
        self.logger.info(f"Initialized RSA key exchange with {key_size}-bit keys")
    
    def generate_keypair(self) -> None:
        """Generate a new RSA key pair."""
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            self.logger.debug(f"Generated new {self.key_size}-bit RSA key pair")
        except Exception as e:
            raise KeyExchangeError(f"Failed to generate RSA key pair: {e}") from e
    
    def encrypt_shared_secret(self) -> Tuple[bytes, bytes]:
        """
        Generate a shared secret and encrypt it with the peer's public key.
        
        Returns:
            A tuple of (encrypted_shared_secret, shared_secret).
            
        Raises:
            KeyExchangeError: If the shared secret cannot be encrypted.
        """
        if self._peer_public_key is None:
            raise KeyExchangeError("Peer public key not set")
        
        if not isinstance(self._peer_public_key, rsa.RSAPublicKey):
            raise KeyExchangeError("Peer public key is not an RSA key")
        
        try:
            # Generate a random shared secret
            shared_secret = os.urandom(32)  # 256 bits
            
            # Encrypt the shared secret with the peer's public key
            encrypted = self._peer_public_key.encrypt(
                shared_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self._shared_secret = shared_secret
            self.logger.debug("Encrypted shared secret with peer's RSA public key")
            
            return encrypted, shared_secret
            
        except Exception as e:
            raise KeyExchangeError(f"Failed to encrypt shared secret: {e}") from e
    
    def decrypt_shared_secret(self, encrypted_shared_secret: bytes) -> bytes:
        """
        Decrypt a shared secret using the local private key.
        
        Args:
            encrypted_shared_secret: The encrypted shared secret.
            
        Returns:
            The decrypted shared secret.
            
        Raises:
            KeyExchangeError: If the shared secret cannot be decrypted.
        """
        if self._private_key is None:
            raise KeyExchangeError("Private key not generated")
        
        try:
            # Decrypt the shared secret with the local private key
            shared_secret = self._private_key.decrypt(
                encrypted_shared_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self._shared_secret = shared_secret
            self.logger.debug("Decrypted shared secret with local RSA private key")
            
            return shared_secret
            
        except Exception as e:
            raise KeyExchangeError(f"Failed to decrypt shared secret: {e}") from e
    
    def compute_shared_secret(self) -> bytes:
        """
        For RSA, this is a no-op since the shared secret is generated during encryption.
        
        Returns:
            The shared secret if available.
            
        Raises:
            KeyExchangeError: If the shared secret is not available.
        """
        if self._shared_secret is None:
            raise KeyExchangeError("Shared secret not available. Call encrypt_shared_secret() or decrypt_shared_secret() first.")
        
        return self._shared_secret


class X25519KeyExchange(KeyExchange):
    """X25519 key exchange (Elliptic Curve Diffie-Hellman over Curve25519)."""
    
    def __init__(self, **kwargs):
        """Initialize the X25519 key exchange."""
        super().__init__(**kwargs)
        self.logger.info("Initialized X25519 key exchange")
    
    def generate_keypair(self) -> None:
        """Generate a new X25519 key pair."""
        try:
            self._private_key = x25519.X25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()
            self.logger.debug("Generated new X25519 key pair")
        except Exception as e:
            raise KeyExchangeError(f"Failed to generate X25519 key pair: {e}") from e
    
    def compute_shared_secret(self) -> bytes:
        """
        Compute the shared secret using the peer's public key.
        
        Returns:
            The shared secret as bytes.
            
        Raises:
            KeyExchangeError: If the shared secret cannot be computed.
        """
        if self._private_key is None:
            raise KeyExchangeError("Private key not generated")
        
        if self._peer_public_key is None:
            raise KeyExchangeError("Peer public key not set")
        
        if not isinstance(self._peer_public_key, x25519.X25519PublicKey):
            raise KeyExchangeError("Peer public key is not an X25519 key")
        
        try:
            self._shared_secret = self._private_key.exchange(self._peer_public_key)
            self.logger.debug("Computed X25519 shared secret")
            return self._shared_secret
            
        except Exception as e:
            raise KeyExchangeError(f"Failed to compute X25519 shared secret: {e}") from e


def create_key_exchange(algorithm: str, **kwargs) -> KeyExchange:
    """
    Create a key exchange instance for the specified algorithm.
    
    Args:
        algorithm: The key exchange algorithm to use.
        **kwargs: Additional arguments to pass to the key exchange constructor.
        
    Returns:
        A KeyExchange instance.
        
    Raises:
        ValueError: If the algorithm is not supported.
    """
    algorithm = algorithm.lower()
    
    if algorithm in ['ecdh', 'ec', 'elliptic-curve']:
        curve = kwargs.pop('curve', ec.SECP384R1())
        return ECDHKeyExchange(curve=curve, **kwargs)
    
    elif algorithm in ['rsa', 'rsa-kem']:
        key_size = kwargs.pop('key_size', 3072)
        return RSAKeyExchange(key_size=key_size, **kwargs)
    
    elif algorithm in ['x25519', 'curve25519']:
        return X25519KeyExchange(**kwargs)
    
    else:
        raise ValueError(f"Unsupported key exchange algorithm: {algorithm}")


def generate_shared_secret(algorithm: str, peer_public_key: bytes, 
                         private_key: Optional[bytes] = None, 
                         password: Optional[bytes] = None, **kwargs) -> bytes:
    """
    Generate a shared secret using the specified key exchange algorithm.
    
    Args:
        algorithm: The key exchange algorithm to use.
        peer_public_key: The peer's public key in PEM or DER format.
        private_key: Optional private key in PEM or DER format. If not provided, a new one will be generated.
        password: Optional password for decrypting the private key.
        **kwargs: Additional arguments to pass to the key exchange constructor.
        
    Returns:
        A tuple of (shared_secret, public_key) where public_key is the local public key.
    """
    kex = create_key_exchange(algorithm, **kwargs)
    
    # Load or generate the private key
    if private_key is not None:
        kex.load_private_key(private_key, password=password)
    else:
        kex.generate_keypair()
    
    # Set the peer's public key
    kex.peer_public_key = peer_public_key
    
    # Compute the shared secret
    shared_secret = kex.compute_shared_secret()
    
    # Get the local public key
    public_key = kex.get_public_key_bytes()
    
    # Clear sensitive data
    kex.clear()
    
    return shared_secret, public_key
