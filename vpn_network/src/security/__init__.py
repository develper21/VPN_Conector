"""
Security Module for VPN

This package provides security-related functionality for VPN, including
encryption, key exchange, certificate management, and security auditing.
"""

# Import key components to make them available at package level
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
from .security_auditing import (
    SecurityAuditor,
    VulnerabilityFinding,
    SecurityScore
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
    'sign_certificate',
    'SecurityAuditor',
    'VulnerabilityFinding',
    'SecurityScore'
]

# Package version
__version__ = '1.0.0'
