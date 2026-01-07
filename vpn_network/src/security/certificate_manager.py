"""
Certificate Manager for VPN

This module provides certificate management functionality for the VPN,
including certificate generation, signing, validation, and revocation.
"""
import os
import time
import logging
import hashlib
import datetime
from typing import Optional, Dict, Any, List, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum, auto

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption,
    KeySerializationEncryption
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes, CertificateIssuerPublicKeyTypes,
    CertificatePublicKeyTypes, PrivateKeyTypes
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

from utils.logger import LoggableMixin

# Type aliases
KeyPair = Tuple[PrivateKeyTypes, CertificatePublicKeyTypes]

class CertificateError(Exception):
    """Base exception for certificate-related errors."""
    pass

class KeyType(Enum):
    """Supported key types for certificates."""
    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"
    ED448 = "ed448"
    
    @classmethod
    def from_string(cls, key_type: str) -> 'KeyType':
        """Get the KeyType enum from a string representation."""
        key_type = key_type.lower()
        if key_type in ['rsa']:
            return cls.RSA
        elif key_type in ['ec', 'ecdsa']:
            return cls.ECDSA
        elif key_type == 'ed25519':
            return cls.ED25519
        elif key_type == 'ed448':
            return cls.ED448
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

class KeyUsage(Enum):
    """Key usage flags for X.509 certificates."""
    DIGITAL_SIGNATURE = "digital_signature"
    CONTENT_COMMITMENT = "content_commitment"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"
    
    @classmethod
    def from_string(cls, usage_str: str) -> 'KeyUsage':
        """Get the KeyUsage enum from a string representation."""
        usage_map = {
            'digital_signature': cls.DIGITAL_SIGNATURE,
            'content_commitment': cls.CONTENT_COMMITMENT,
            'key_encipherment': cls.KEY_ENCIPHERMENT,
            'data_encipherment': cls.DATA_ENCIPHERMENT,
            'key_agreement': cls.KEY_AGREEMENT,
            'key_cert_sign': cls.KEY_CERT_SIGN,
            'crl_sign': cls.CRL_SIGN,
            'encipher_only': cls.ENCIPHER_ONLY,
            'decipher_only': cls.DECIPHER_ONLY,
        }
        
        usage = usage_map.get(usage_str.lower())
        if not usage:
            raise ValueError(f"Unsupported key usage: {usage_str}")
        return usage

class ExtendedKeyUsage(Enum):
    """Extended key usage OIDs for X.509 certificates."""
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"
    CODE_SIGNING = "code_signing"
    EMAIL_PROTECTION = "email_protection"
    TIME_STAMPING = "time_stamping"
    OCSP_SIGNING = "ocsp_signing"
    ANY_EXTENDED_KEY_USAGE = "any_extended_key_usage"
    
    @classmethod
    def from_string(cls, eku_str: str) -> 'ExtendedKeyUsage':
        """Get the ExtendedKeyUsage enum from a string representation."""
        eku_map = {
            'server_auth': cls.SERVER_AUTH,
            'client_auth': cls.CLIENT_AUTH,
            'code_signing': cls.CODE_SIGNING,
            'email_protection': cls.EMAIL_PROTECTION,
            'time_stamping': cls.TIME_STAMPING,
            'ocsp_signing': cls.OCSP_SIGNING,
            'any_extended_key_usage': cls.ANY_EXTENDED_KEY_USAGE,
        }
        
        eku = eku_map.get(eku_str.lower())
        if not eku:
            raise ValueError(f"Unsupported extended key usage: {eku_str}")
        return eku
    
    def to_oid(self) -> ObjectIdentifier:
        """Get the OID for this extended key usage."""
        if self == self.SERVER_AUTH:
            return ExtensionOID.SERVER_AUTH
        elif self == self.CLIENT_AUTH:
            return ExtensionOID.CLIENT_AUTH
        elif self == self.CODE_SIGNING:
            return ExtensionOID.CODE_SIGNING
        elif self == self.EMAIL_PROTECTION:
            return ExtensionOID.EMAIL_PROTECTION
        elif self == self.TIME_STAMPING:
            return ExtensionOID.TIME_STAMPING
        elif self == self.OCSP_SIGNING:
            return ExtensionOID.OCSP_SIGNING
        elif self == self.ANY_EXTENDED_KEY_USAGE:
            return ExtensionOID.ANY_EXTENDED_KEY_USAGE
        else:
            raise ValueError(f"Unknown extended key usage: {self}")

@dataclass
class CertificateRequest:
    """Represents a certificate signing request (CSR)."""
    subject: Dict[str, str]
    key_type: KeyType = KeyType.RSA
    key_size: int = 2048
    key_curve: str = "secp256r1"
    key_usages: List[KeyUsage] = field(default_factory=lambda: [KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE])
    extended_key_usages: List[ExtendedKeyUsage] = field(default_factory=list)
    san_dns_names: List[str] = field(default_factory=list)
    san_ips: List[str] = field(default_factory=list)
    
    def to_csr(self, private_key: Optional[PrivateKeyTypes] = None) -> x509.CertificateSigningRequest:
        """
        Generate a certificate signing request (CSR) from this request.
        
        Args:
            private_key: Optional private key to use. If not provided, a new one will be generated.
            
        Returns:
            A tuple of (csr, private_key).
        """
        # Generate a private key if not provided
        if private_key is None:
            private_key, _ = generate_key_pair(self.key_type, self.key_size, self.key_curve)
        
        # Create a name object for the subject
        name_attributes = []
        for attr, value in self.subject.items():
            if attr.lower() == 'cn':
                name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
            elif attr.lower() == 'o':
                name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
            elif attr.lower() == 'ou':
                name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
            elif attr.lower() == 'c':
                name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
            elif attr.lower() == 'st':
                name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
            elif attr.lower() == 'l':
                name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, value))
            elif attr.lower() == 'email':
                name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, value))
        
        subject = x509.Name(name_attributes)
        
        # Create a CSR builder
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add subject alternative names if provided
        san_extensions = []
        if self.san_dns_names or self.san_ips:
            san = []
            for dns_name in self.san_dns_names:
                san.append(x509.DNSName(dns_name))
            for ip in self.san_ips:
                san.append(x509.IPAddress(ip))
            
            san_extension = x509.SubjectAlternativeName(san)
            builder = builder.add_extension(san_extension, critical=False)
        
        # Add key usage if specified
        if self.key_usages:
            key_usage = x509.KeyUsage(
                digital_signature=KeyUsage.DIGITAL_SIGNATURE in self.key_usages,
                content_commitment=KeyUsage.CONTENT_COMMITMENT in self.key_usages,
                key_encipherment=KeyUsage.KEY_ENCIPHERMENT in self.key_usages,
                data_encipherment=KeyUsage.DATA_ENCIPHERMENT in self.key_usages,
                key_agreement=KeyUsage.KEY_AGREEMENT in self.key_usages,
                key_cert_sign=KeyUsage.KEY_CERT_SIGN in self.key_usages,
                crl_sign=KeyUsage.CRL_SIGN in self.key_usages,
                encipher_only=KeyUsage.ENCIPHER_ONLY in self.key_usages,
                decipher_only=KeyUsage.DECIPHER_ONLY in self.key_usages,
            )
            builder = builder.add_extension(key_usage, critical=True)
        
        # Add extended key usage if specified
        if self.extended_key_usages:
            extended_key_usage = x509.ExtendedKeyUsage(
                [eku.to_oid() for eku in self.extended_key_usages]
            )
            builder = builder.add_extension(extended_key_usage, critical=False)
        
        # Sign the CSR with the private key
        csr = builder.sign(
            private_key,
            hashes.SHA256(),
            default_backend()
        )
        
        return csr, private_key

class CertificateManager(LoggableMixin):
    """
    Manages X.509 certificates for the VPN, including generation, signing, and validation.
    """
    
    def __init__(
        self,
        ca_cert_path: Optional[Union[str, Path]] = None,
        ca_key_path: Optional[Union[str, Path]] = None,
        ca_key_password: Optional[bytes] = None,
        certs_dir: Union[str, Path] = "certs",
        **kwargs
    ):
        """
        Initialize the certificate manager.
        
        Args:
            ca_cert_path: Path to the CA certificate file (PEM format).
            ca_key_path: Path to the CA private key file (PEM format).
            ca_key_password: Password for the CA private key, if encrypted.
            certs_dir: Directory to store certificates.
            **kwargs: Additional keyword arguments for LoggableMixin.
        """
        super().__init__(**kwargs)
        
        self.ca_cert = None
        self.ca_key = None
        self.ca_cert_path = Path(ca_cert_path) if ca_cert_path else None
        self.ca_key_path = Path(ca_key_path) if ca_key_path else None
        self.ca_key_password = ca_key_password
        
        # Ensure the certs directory exists
        self.certs_dir = Path(certs_dir)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        
        # Load CA certificate and key if provided
        if self.ca_cert_path and self.ca_key_path:
            self.load_ca(self.ca_cert_path, self.ca_key_path, self.ca_key_password)
        
        self.logger.info("Certificate manager initialized")
    
    def load_ca(
        self,
        cert_path: Union[str, Path],
        key_path: Optional[Union[str, Path]] = None,
        key_password: Optional[bytes] = None
    ) -> None:
        """
        Load a CA certificate and its private key.
        
        Args:
            cert_path: Path to the CA certificate file (PEM format).
            key_path: Path to the CA private key file (PEM format).
            key_password: Password for the private key, if encrypted.
            
        Raises:
            CertificateError: If the certificate or key cannot be loaded.
        """
        try:
            # Load the CA certificate
            with open(cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(
                    f.read(),
                    default_backend()
                )
            
            # Load the CA private key if provided
            if key_path:
                with open(key_path, 'rb') as f:
                    key_data = f.read()
                    self.ca_key = load_pem_private_key(
                        key_data,
                        password=key_password,
                        backend=default_backend()
                    )
            
            self.ca_cert_path = Path(cert_path)
            self.ca_key_path = Path(key_path) if key_path else None
            self.ca_key_password = key_password
            
            self.logger.info(f"Loaded CA certificate: {cert_path}")
            if key_path:
                self.logger.info(f"Loaded CA private key: {key_path}")
                
        except Exception as e:
            raise CertificateError(f"Failed to load CA: {e}") from e
    
    def create_self_signed_ca(
        self,
        subject: Dict[str, str],
        key_type: Union[str, KeyType] = KeyType.RSA,
        key_size: int = 4096,
        key_curve: str = "secp384r1",
        validity_days: int = 3650,
        output_dir: Optional[Union[str, Path]] = None,
        key_password: Optional[bytes] = None
    ) -> Tuple[x509.Certificate, PrivateKeyTypes]:
        """
        Create a self-signed CA certificate.
        
        Args:
            subject: Dictionary of subject attributes (e.g., {'CN': 'My CA', 'O': 'My Org'}).
            key_type: Type of key to generate (RSA, ECDSA, ED25519, ED448).
            key_size: Key size in bits for RSA keys.
            key_curve: Name of the elliptic curve for ECDSA keys.
            validity_days: Validity period in days.
            output_dir: Directory to save the certificate and key. If None, uses certs_dir.
            key_password: Password to encrypt the private key. If None, the key is not encrypted.
            
        Returns:
            A tuple of (certificate, private_key).
            
        Raises:
            CertificateError: If the CA certificate cannot be created.
        """
        try:
            # Generate a key pair
            private_key, public_key = generate_key_pair(key_type, key_size, key_curve)
            
            # Create a self-signed certificate
            subject_name = create_name(subject)
            
            # Set the certificate validity period
            valid_from = datetime.datetime.utcnow()
            valid_to = valid_from + datetime.timedelta(days=validity_days)
            
            # Create the certificate builder
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject_name)
            builder = builder.issuer_name(subject_name)  # Self-signed
            builder = builder.not_valid_before(valid_from)
            builder = builder.not_valid_after(valid_to)
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(public_key)
            
            # Add CA extensions
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False
            )
            
            # Sign the certificate with the private key
            cert = builder.sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            # Save the CA certificate and key
            if output_dir is None:
                output_dir = self.certs_dir
            else:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
            
            # Save the certificate
            cert_path = output_dir / "ca.crt"
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(Encoding.PEM))
            
            # Save the private key
            key_path = output_dir / "ca.key"
            key_encryption = (
                BestAvailableEncryption(key_password) 
                if key_password 
                else NoEncryption()
            )
            
            key_format = PrivateFormat.PKCS8
            if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
                key_format = PrivateFormat.PKCS8
            
            key_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=key_format,
                encryption_algorithm=key_encryption
            )
            
            with open(key_path, 'wb') as f:
                f.write(key_pem)
            
            # Update the CA certificate and key
            self.ca_cert = cert
            self.ca_key = private_key
            self.ca_cert_path = cert_path
            self.ca_key_path = key_path
            self.ca_key_password = key_password
            
            self.logger.info(f"Created self-signed CA certificate: {cert_path}")
            self.logger.info(f"CA private key saved to: {key_path}")
            
            return cert, private_key
            
        except Exception as e:
            raise CertificateError(f"Failed to create self-signed CA: {e}") from e
    
    def sign_certificate(
        self,
        csr: Union[x509.CertificateSigningRequest, bytes, str],
        subject: Optional[Dict[str, str]] = None,
        validity_days: int = 365,
        is_ca: bool = False,
        key_usage: Optional[List[KeyUsage]] = None,
        extended_key_usage: Optional[List[ExtendedKeyUsage]] = None,
        san_dns_names: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None
    ) -> x509.Certificate:
        """
        Sign a certificate signing request (CSR) with the CA.
        
        Args:
            csr: The certificate signing request as a CSR object, PEM-encoded bytes, or PEM string.
            subject: Optional subject to override the CSR subject.
            validity_days: Validity period in days.
            is_ca: Whether the certificate is a CA certificate.
            key_usage: List of key usage flags.
            extended_key_usage: List of extended key usage OIDs.
            san_dns_names: List of DNS names for the Subject Alternative Name extension.
            san_ips: List of IP addresses for the Subject Alternative Name extension.
            
        Returns:
            The signed certificate.
            
        Raises:
            CertificateError: If the CSR cannot be signed.
        """
        if self.ca_cert is None or self.ca_key is None:
            raise CertificateError("CA certificate or private key not loaded")
        
        try:
            # Parse the CSR if it's not already a CSR object
            if not isinstance(csr, x509.CertificateSigningRequest):
                if isinstance(csr, str):
                    csr = csr.encode('utf-8')
                csr = x509.load_pem_x509_csr(csr, default_backend())
            
            # Validate the CSR signature
            if not csr.is_signature_valid:
                raise CertificateError("Invalid CSR signature")
            
            # Create a certificate builder
            builder = x509.CertificateBuilder()
            
            # Set the subject (from CSR or override)
            if subject:
                builder = builder.subject_name(create_name(subject))
            else:
                builder = builder.subject_name(csr.subject)
            
            # Set the issuer (CA's subject)
            builder = builder.issuer_name(self.ca_cert.subject)
            
            # Set the validity period
            valid_from = datetime.datetime.utcnow()
            valid_to = valid_from + datetime.timedelta(days=validity_days)
            builder = builder.not_valid_before(valid_from)
            builder = builder.not_valid_after(valid_to)
            
            # Set the public key from the CSR
            builder = builder.public_key(csr.public_key())
            
            # Set a random serial number
            builder = builder.serial_number(x509.random_serial_number())
            
            # Copy extensions from the CSR
            for extension in csr.extensions:
                try:
                    builder = builder.add_extension(
                        extension.value,
                        critical=extension.critical
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to copy extension {extension.oid}: {e}")
            
            # Add basic constraints
            builder = builder.add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None),
                critical=True
            )
            
            # Add key usage if specified
            if key_usage is not None:
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=KeyUsage.DIGITAL_SIGNATURE in key_usage,
                        content_commitment=KeyUsage.CONTENT_COMMITMENT in key_usage,
                        key_encipherment=KeyUsage.KEY_ENCIPHERMENT in key_usage,
                        data_encipherment=KeyUsage.DATA_ENCIPHERMENT in key_usage,
                        key_agreement=KeyUsage.KEY_AGREEMENT in key_usage,
                        key_cert_sign=KeyUsage.KEY_CERT_SIGN in key_usage,
                        crl_sign=KeyUsage.CRL_SIGN in key_usage,
                        encipher_only=KeyUsage.ENCIPHER_ONLY in key_usage,
                        decipher_only=KeyUsage.DECIPHER_ONLY in key_usage,
                    ),
                    critical=True
                )
            
            # Add extended key usage if specified
            if extended_key_usage:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(
                        [eku.to_oid() for eku in extended_key_usage]
                    ),
                    critical=False
                )
            
            # Add subject alternative names if specified
            san_extensions = []
            if san_dns_names or san_ips:
                san = []
                for dns_name in (san_dns_names or []):
                    san.append(x509.DNSName(dns_name))
                for ip in (san_ips or []):
                    san.append(x509.IPAddress(ip))
                
                san_extension = x509.SubjectAlternativeName(san)
                builder = builder.add_extension(san_extension, critical=False)
            
            # Add subject key identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False
            )
            
            # Add authority key identifier
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False
            )
            
            # Sign the certificate with the CA's private key
            cert = builder.sign(
                private_key=self.ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            self.logger.info(f"Signed certificate with serial number: {cert.serial_number}")
            
            return cert
            
        except Exception as e:
            raise CertificateError(f"Failed to sign certificate: {e}") from e
    
    def generate_certificate(
        self,
        subject: Dict[str, str],
        key_type: Union[str, KeyType] = KeyType.RSA,
        key_size: int = 2048,
        key_curve: str = "secp256r1",
        validity_days: int = 365,
        is_ca: bool = False,
        key_usage: Optional[List[KeyUsage]] = None,
        extended_key_usage: Optional[List[ExtendedKeyUsage]] = None,
        san_dns_names: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        key_password: Optional[bytes] = None
    ) -> Tuple[x509.Certificate, PrivateKeyTypes]:
        """
        Generate a new certificate and private key, signed by the CA.
        
        Args:
            subject: Dictionary of subject attributes (e.g., {'CN': 'example.com', 'O': 'My Org'}).
            key_type: Type of key to generate (RSA, ECDSA, ED25519, ED448).
            key_size: Key size in bits for RSA keys.
            key_curve: Name of the elliptic curve for ECDSA keys.
            validity_days: Validity period in days.
            is_ca: Whether the certificate is a CA certificate.
            key_usage: List of key usage flags.
            extended_key_usage: List of extended key usage OIDs.
            san_dns_names: List of DNS names for the Subject Alternative Name extension.
            san_ips: List of IP addresses for the Subject Alternative Name extension.
            output_dir: Directory to save the certificate and key. If None, uses certs_dir.
            key_password: Password to encrypt the private key. If None, the key is not encrypted.
            
        Returns:
            A tuple of (certificate, private_key).
            
        Raises:
            CertificateError: If the certificate cannot be generated.
        """
        try:
            # Generate a key pair
            private_key, public_key = generate_key_pair(key_type, key_size, key_curve)
            
            # Create a CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(create_name(subject))
            
            # Add subject alternative names if provided
            if san_dns_names or san_ips:
                san = []
                for dns_name in (san_dns_names or []):
                    san.append(x509.DNSName(dns_name))
                for ip in (san_ips or []):
                    san.append(x509.IPAddress(ip))
                
                san_extension = x509.SubjectAlternativeName(san)
                csr_builder = csr_builder.add_extension(san_extension, critical=False)
            
            # Add key usage if specified
            if key_usage is not None:
                csr_builder = csr_builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=KeyUsage.DIGITAL_SIGNATURE in key_usage,
                        content_commitment=KeyUsage.CONTENT_COMMITMENT in key_usage,
                        key_encipherment=KeyUsage.KEY_ENCIPHERMENT in key_usage,
                        data_encipherment=KeyUsage.DATA_ENCIPHERMENT in key_usage,
                        key_agreement=KeyUsage.KEY_AGREEMENT in key_usage,
                        key_cert_sign=KeyUsage.KEY_CERT_SIGN in key_usage,
                        crl_sign=KeyUsage.CRL_SIGN in key_usage,
                        encipher_only=KeyUsage.ENCIPHER_ONLY in key_usage,
                        decipher_only=KeyUsage.DECIPHER_ONLY in key_usage,
                    ),
                    critical=True
                )
            
            # Add extended key usage if specified
            if extended_key_usage:
                csr_builder = csr_builder.add_extension(
                    x509.ExtendedKeyUsage(
                        [eku.to_oid() for eku in extended_key_usage]
                    ),
                    critical=False
                )
            
            # Sign the CSR with the private key
            csr = csr_builder.sign(
                private_key=private_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )
            
            # Sign the certificate with the CA
            cert = self.sign_certificate(
                csr=csr,
                subject=subject,
                validity_days=validity_days,
                is_ca=is_ca,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                san_dns_names=san_dns_names,
                san_ips=san_ips
            )
            
            # Save the certificate and key if output directory is provided
            if output_dir is not None:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Use the common name as the base filename
                cn = subject.get('CN', 'certificate')
                
                # Save the certificate
                cert_path = output_dir / f"{cn}.crt"
                with open(cert_path, 'wb') as f:
                    f.write(cert.public_bytes(Encoding.PEM))
                
                # Save the private key
                key_path = output_dir / f"{cn}.key"
                key_encryption = (
                    BestAvailableEncryption(key_password) 
                    if key_password 
                    else NoEncryption()
                )
                
                key_format = PrivateFormat.PKCS8
                if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
                    key_format = PrivateFormat.PKCS8
                
                key_pem = private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=key_format,
                    encryption_algorithm=key_encryption
                )
                
                with open(key_path, 'wb') as f:
                    f.write(key_pem)
                
                self.logger.info(f"Generated certificate: {cert_path}")
                self.logger.info(f"Private key saved to: {key_path}")
            
            return cert, private_key
            
        except Exception as e:
            raise CertificateError(f"Failed to generate certificate: {e}") from e
    
    def verify_certificate(
        self,
        cert: Union[x509.Certificate, bytes, str],
        check_revocation: bool = True
    ) -> bool:
        """
        Verify a certificate against the CA certificate.
        
        Args:
            cert: The certificate to verify as a Certificate object, PEM-encoded bytes, or PEM string.
            check_revocation: Whether to check if the certificate has been revoked.
            
        Returns:
            True if the certificate is valid, False otherwise.
        """
        try:
            # Parse the certificate if it's not already a Certificate object
            if not isinstance(cert, x509.Certificate):
                if isinstance(cert, str):
                    cert = cert.encode('utf-8')
                cert = x509.load_pem_x509_certificate(cert, default_backend())
            
            # Check if the certificate is self-signed
            if cert.issuer == cert.subject:
                # For self-signed certificates, verify the signature with its own public key
                public_key = cert.public_key()
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            else:
                # For non-self-signed certificates, verify with the CA's public key
                if self.ca_cert is None:
                    raise CertificateError("CA certificate not loaded")
                
                # Verify the certificate's signature
                public_key = self.ca_cert.public_key()
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                
                # Verify the certificate's validity period
                current_time = datetime.datetime.utcnow()
                if current_time < cert.not_valid_before or current_time > cert.not_valid_after:
                    raise CertificateError("Certificate is not valid at the current time")
                
                # Verify the certificate's issuer matches the CA's subject
                if cert.issuer != self.ca_cert.subject:
                    raise CertificateError("Certificate issuer does not match CA subject")
                
                # Check if the certificate has been revoked
                if check_revocation and self._is_certificate_revoked(cert):
                    raise CertificateError("Certificate has been revoked")
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Certificate verification failed: {e}")
            return False
    
    def revoke_certificate(
        self,
        cert: Union[x509.Certificate, bytes, str],
        reason: Optional[x509.ReasonFlags] = None
    ) -> None:
        """
        Revoke a certificate.
        
        Args:
            cert: The certificate to revoke as a Certificate object, PEM-encoded bytes, or PEM string.
            reason: The reason for revocation. If None, uses UNSPECIFIED.
        """
        # TODO: Implement certificate revocation list (CRL) functionality
        raise NotImplementedError("Certificate revocation is not yet implemented")
    
    def _is_certificate_revoked(self, cert: x509.Certificate) -> bool:
        """
        Check if a certificate has been revoked.
        
        Args:
            cert: The certificate to check.
            
        Returns:
            True if the certificate has been revoked, False otherwise.
        """
        # TODO: Implement CRL or OCSP checking
        return False

def generate_key_pair(
    key_type: Union[str, KeyType] = KeyType.RSA,
    key_size: int = 2048,
    curve_name: str = "secp256r1"
) -> Tuple[PrivateKeyTypes, CertificatePublicKeyTypes]:
    """
    Generate a key pair for use with X.509 certificates.
    
    Args:
        key_type: The type of key to generate (RSA, ECDSA, ED25519, ED448).
        key_size: The key size in bits (for RSA).
        curve_name: The name of the elliptic curve (for ECDSA).
        
    Returns:
        A tuple of (private_key, public_key).
        
    Raises:
        ValueError: If the key type is not supported.
    """
    if isinstance(key_type, str):
        key_type = KeyType.from_string(key_type)
    
    if key_type == KeyType.RSA:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
    elif key_type == KeyType.ECDSA:
        # Map common curve names to their corresponding curve class
        curve_map = {
            'secp192r1': ec.SECP192R1,
            'secp224r1': ec.SECP224R1,
            'secp256r1': ec.SECP256R1,
            'secp384r1': ec.SECP384R1,
            'secp521r1': ec.SECP521R1,
            'secp256k1': ec.SECP256K1,
            'brainpoolP256r1': ec.BrainpoolP256R1,
            'brainpoolP384r1': ec.BrainpoolP384R1,
            'brainpoolP512r1': ec.BrainpoolP512R1,
        }
        
        curve_class = curve_map.get(curve_name.lower())
        if not curve_class:
            raise ValueError(f"Unsupported curve: {curve_name}")
        
        private_key = ec.generate_private_key(
            curve=curve_class(),
            backend=default_backend()
        )
    elif key_type == KeyType.ED25519:
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == KeyType.ED448:
        private_key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    
    return private_key, private_key.public_key()

def create_name(attributes: Dict[str, str]) -> x509.Name:
    """
    Create an X.509 Name object from a dictionary of attributes.
    
    Args:
        attributes: Dictionary of name attributes (e.g., {'CN': 'example.com', 'O': 'My Org'}).
        
    Returns:
        An X.509 Name object.
    """
    name_attributes = []
    
    # Map of common attribute names to OIDs
    attr_map = {
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'CN': NameOID.COMMON_NAME,
        'email': NameOID.EMAIL_ADDRESS,
        'serialNumber': NameOID.SERIAL_NUMBER,
        'dnQualifier': NameOID.DN_QUALIFIER,
        'title': NameOID.TITLE,
        'surname': NameOID.SURNAME,
        'givenName': NameOID.GIVEN_NAME,
        'initials': NameOID.INITIALS,
        'pseudonym': NameOID.PSEUDONYM,
        'generationQualifier': NameOID.GENERATION_QUALIFIER,
        'dn': NameOID.DOMAIN_COMPONENT,
    }
    
    for attr, value in attributes.items():
        oid = attr_map.get(attr.upper())
        if oid:
            name_attributes.append(x509.NameAttribute(oid, value))
        else:
            # Try to use the attribute as an OID string
            try:
                oid = ObjectIdentifier(attr)
                name_attributes.append(x509.NameAttribute(oid, value))
            except Exception:
                raise ValueError(f"Unknown attribute: {attr}")
    
    return x509.Name(name_attributes)

def generate_self_signed_cert(
    subject: Dict[str, str],
    key_type: Union[str, KeyType] = KeyType.RSA,
    key_size: int = 2048,
    key_curve: str = "secp256r1",
    validity_days: int = 365,
    is_ca: bool = False,
    key_usage: Optional[List[KeyUsage]] = None,
    extended_key_usage: Optional[List[ExtendedKeyUsage]] = None,
    san_dns_names: Optional[List[str]] = None,
    san_ips: Optional[List[str]] = None,
    output_dir: Optional[Union[str, Path]] = None,
    key_password: Optional[bytes] = None
) -> Tuple[x509.Certificate, PrivateKeyTypes]:
    """
    Generate a self-signed certificate.
    
    This is a convenience function that creates a CertificateManager instance
    and generates a self-signed certificate.
    
    Args:
        subject: Dictionary of subject attributes (e.g., {'CN': 'example.com', 'O': 'My Org'}).
        key_type: Type of key to generate (RSA, ECDSA, ED25519, ED448).
        key_size: Key size in bits for RSA keys.
        key_curve: Name of the elliptic curve for ECDSA keys.
        validity_days: Validity period in days.
        is_ca: Whether the certificate is a CA certificate.
        key_usage: List of key usage flags.
        extended_key_usage: List of extended key usage OIDs.
        san_dns_names: List of DNS names for the Subject Alternative Name extension.
        san_ips: List of IP addresses for the Subject Alternative Name extension.
        output_dir: Directory to save the certificate and key. If None, the certificate is not saved.
        key_password: Password to encrypt the private key. If None, the key is not encrypted.
        
    Returns:
        A tuple of (certificate, private_key).
    """
    # Create a temporary CA to sign the certificate
    temp_ca = CertificateManager()
    
    # Create a self-signed CA certificate
    ca_cert, ca_key = temp_ca.create_self_signed_ca(
        subject=subject,
        key_type=key_type,
        key_size=key_size,
        key_curve=key_curve,
        validity_days=validity_days,
        output_dir=None  # Don't save the CA files
    )
    
    # Generate a certificate signed by the temporary CA
    cert, private_key = temp_ca.generate_certificate(
        subject=subject,
        key_type=key_type,
        key_size=key_size,
        key_curve=key_curve,
        validity_days=validity_days,
        is_ca=is_ca,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        san_dns_names=san_dns_names,
        san_ips=san_ips,
        output_dir=output_dir,
        key_password=key_password
    )
    
    return cert, private_key

def generate_csr(
    subject: Dict[str, str],
    key_type: Union[str, KeyType] = KeyType.RSA,
    key_size: int = 2048,
    key_curve: str = "secp256r1",
    key_usage: Optional[List[KeyUsage]] = None,
    extended_key_usage: Optional[List[ExtendedKeyUsage]] = None,
    san_dns_names: Optional[List[str]] = None,
    san_ips: Optional[List[str]] = None,
    output_dir: Optional[Union[str, Path]] = None,
    key_password: Optional[bytes] = None
) -> Tuple[x509.CertificateSigningRequest, PrivateKeyTypes]:
    """
    Generate a certificate signing request (CSR) and private key.
    
    Args:
        subject: Dictionary of subject attributes (e.g., {'CN': 'example.com', 'O': 'My Org'}).
        key_type: Type of key to generate (RSA, ECDSA, ED25519, ED448).
        key_size: Key size in bits for RSA keys.
        key_curve: Name of the elliptic curve for ECDSA keys.
        key_usage: List of key usage flags.
        extended_key_usage: List of extended key usage OIDs.
        san_dns_names: List of DNS names for the Subject Alternative Name extension.
        san_ips: List of IP addresses for the Subject Alternative Name extension.
        output_dir: Directory to save the CSR and key. If None, the files are not saved.
        key_password: Password to encrypt the private key. If None, the key is not encrypted.
        
    Returns:
        A tuple of (csr, private_key).
    """
    # Generate a key pair
    private_key, public_key = generate_key_pair(key_type, key_size, key_curve)
    
    # Create a CSR builder
    builder = x509.CertificateSigningRequestBuilder()
    
    # Set the subject
    builder = builder.subject_name(create_name(subject))
    
    # Add subject alternative names if provided
    if san_dns_names or san_ips:
        san = []
        for dns_name in (san_dns_names or []):
            san.append(x509.DNSName(dns_name))
        for ip in (san_ips or []):
            san.append(x509.IPAddress(ip))
        
        san_extension = x509.SubjectAlternativeName(san)
        builder = builder.add_extension(san_extension, critical=False)
    
    # Add key usage if specified
    if key_usage is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=KeyUsage.DIGITAL_SIGNATURE in key_usage,
                content_commitment=KeyUsage.CONTENT_COMMITMENT in key_usage,
                key_encipherment=KeyUsage.KEY_ENCIPHERMENT in key_usage,
                data_encipherment=KeyUsage.DATA_ENCIPHERMENT in key_usage,
                key_agreement=KeyUsage.KEY_AGREEMENT in key_usage,
                key_cert_sign=KeyUsage.KEY_CERT_SIGN in key_usage,
                crl_sign=KeyUsage.CRL_SIGN in key_usage,
                encipher_only=KeyUsage.ENCIPHER_ONLY in key_usage,
                decipher_only=KeyUsage.DECIPHER_ONLY in key_usage,
            ),
            critical=True
        )
    
    # Add extended key usage if specified
    if extended_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [eku.to_oid() for eku in extended_key_usage]
            ),
            critical=False
        )
    
    # Sign the CSR with the private key
    csr = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    # Save the CSR and key if output directory is provided
    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use the common name as the base filename
        cn = subject.get('CN', 'certificate')
        
        # Save the CSR
        csr_path = output_dir / f"{cn}.csr"
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(Encoding.PEM))
        
        # Save the private key
        key_path = output_dir / f"{cn}.key"
        key_encryption = (
            BestAvailableEncryption(key_password) 
            if key_password 
            else NoEncryption()
        )
        
        key_format = PrivateFormat.PKCS8
        if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            key_format = PrivateFormat.PKCS8
        
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=key_format,
            encryption_algorithm=key_encryption
        )
        
        with open(key_path, 'wb') as f:
            f.write(key_pem)
        
        logging.info(f"Generated CSR: {csr_path}")
        logging.info(f"Private key saved to: {key_path}")
    
    return csr, private_key

def sign_certificate(
    csr: Union[x509.CertificateSigningRequest, bytes, str],
    ca_cert_path: Union[str, Path],
    ca_key_path: Union[str, Path],
    ca_key_password: Optional[bytes] = None,
    validity_days: int = 365,
    is_ca: bool = False,
    key_usage: Optional[List[KeyUsage]] = None,
    extended_key_usage: Optional[List[ExtendedKeyUsage]] = None,
    san_dns_names: Optional[List[str]] = None,
    san_ips: Optional[List[str]] = None,
    output_path: Optional[Union[str, Path]] = None
) -> x509.Certificate:
    """
    Sign a certificate signing request (CSR) with a CA certificate.
    
    This is a convenience function that creates a CertificateManager instance
    and signs a CSR.
    
    Args:
        csr: The certificate signing request as a CSR object, PEM-encoded bytes, or PEM string.
        ca_cert_path: Path to the CA certificate file (PEM format).
        ca_key_path: Path to the CA private key file (PEM format).
        ca_key_password: Password for the CA private key, if encrypted.
        validity_days: Validity period in days.
        is_ca: Whether the certificate is a CA certificate.
        key_usage: List of key usage flags.
        extended_key_usage: List of extended key usage OIDs.
        san_dns_names: List of DNS names for the Subject Alternative Name extension.
        san_ips: List of IP addresses for the Subject Alternative Name extension.
        output_path: Path to save the signed certificate. If None, the certificate is not saved.
        
    Returns:
        The signed certificate.
    """
    # Create a certificate manager with the CA certificate and key
    cert_manager = CertificateManager(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_key_path,
        ca_key_password=ca_key_password
    )
    
    # Sign the CSR
    cert = cert_manager.sign_certificate(
        csr=csr,
        validity_days=validity_days,
        is_ca=is_ca,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        san_dns_names=san_dns_names,
        san_ips=san_ips
    )
    
    # Save the certificate if output path is provided
    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(cert.public_bytes(Encoding.PEM))
        
        logging.info(f"Signed certificate saved to: {output_path}")
    
    return cert
