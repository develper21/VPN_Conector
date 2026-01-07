"""
Security Module for VPN

This package provides security-related functionality for the VPN, including
encryption, key exchange, and certificate management.
"""

# Import key components to make them available at the package level
from .encryption import (
    EncryptionManager,
    CipherAlgorithm,
    HashAlgorithm,
    EncryptionError,
    DecryptionError,
    KeyDerivationError
)
from .key_exchange import (
    KeyExchange,
    KeyExchangeError,
    ECDHKeyExchange,
    RSAKeyExchange
)
from .certificate_manager import (
    CertificateManager,
    CertificateError,
    generate_self_signed_cert,
    generate_csr,
    sign_certificate
)

# Define what gets imported with 'from security import *'
__all__ = [
    'EncryptionManager',
    'CipherAlgorithm',
    'HashAlgorithm',
    'EncryptionError',
    'DecryptionError',
    'KeyDerivationError',
    'KeyExchange',
    'KeyExchangeError',
    'ECDHKeyExchange',
    'RSAKeyExchange',
    'CertificateManager',
    'CertificateError',
    'generate_self_signed_cert',
    'generate_csr',
    'sign_certificate'
]

# Package version
__version__ = '0.1.0'
