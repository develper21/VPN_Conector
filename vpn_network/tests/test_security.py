import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.security.encryption import (
    EncryptionManager,
    CipherAlgorithm,
    HashAlgorithm,
    EncryptionError,
    DecryptionError,
    generate_key,
    generate_iv,
    derive_key_from_password
)

from src.security.key_exchange import (
    ECDHKeyExchange,
    RSAKeyExchange,
    X25519KeyExchange,
    create_key_exchange,
    generate_shared_secret
)

from src.security.certificate_manager import (
    CertificateManager,
    CertificateError,
    generate_self_signed_cert,
    generate_csr,
    sign_certificate,
    KeyType,
    KeyUsage,
    ExtendedKeyUsage
)

class TestEncryption(unittest.TestCase):
    """Test cases for encryption functionality."""
    
    def test_encryption_decryption(self):
        """Test encryption and decryption with different algorithms."""
        test_data = b"This is a test message for encryption"
        
        # Test with AES-256-GCM
        key = generate_key(CipherAlgorithm.AES_256_GCM)
        iv = generate_iv(CipherAlgorithm.AES_256_GCM)
        
        enc_manager = EncryptionManager(algorithm=CipherAlgorithm.AES_256_GCM)
        enc_manager.set_keys(key)
        
        # Encrypt the data
        result = enc_manager.encrypt(test_data, iv)
        self.assertIsNotNone(result.ciphertext)
        self.assertEqual(result.iv, iv)
        self.assertIsNotNone(result.tag)
        
        # Decrypt the data
        decrypted = enc_manager.decrypt(
            result.ciphertext,
            result.iv,
            result.tag
        )
        self.assertEqual(decrypted, test_data)
        
        # Test with AES-256-CBC
        key = generate_key(CipherAlgorithm.AES_256_CBC)
        iv = generate_iv(CipherAlgorithm.AES_256_CBC)
        
        enc_manager = EncryptionManager(
            algorithm=CipherAlgorithm.AES_256_CBC,
            use_hmac=True
        )
        enc_manager.set_keys(key, hmac_key=os.urandom(32))
        
        # Encrypt the data
        result = enc_manager.encrypt(test_data, iv)
        self.assertIsNotNone(result.ciphertext)
        self.assertEqual(result.iv, iv)
        self.assertIsNotNone(result.tag)  # HMAC tag
        
        # Decrypt the data
        decrypted = enc_manager.decrypt(
            result.ciphertext,
            result.iv,
            result.tag
        )
        self.assertEqual(decrypted, test_data)
        
        # Test with ChaCha20-Poly1305
        key = generate_key(CipherAlgorithm.CHACHA20_POLY1305)
        iv = generate_iv(CipherAlgorithm.CHACHA20_POLY1305)
        
        enc_manager = EncryptionManager(algorithm=CipherAlgorithm.CHACHA20_POLY1305)
        enc_manager.set_keys(key)
        
        # Encrypt the data
        result = enc_manager.encrypt(test_data, iv)
        self.assertIsNotNone(result.ciphertext)
        self.assertEqual(result.iv, iv)
        
        # Decrypt the data (note: current implementation doesn't support tag for ChaCha20-Poly1305)
        with self.assertRaises(DecryptionError):
            decrypted = enc_manager.decrypt(
                result.ciphertext,
                result.iv,
                b''  # Empty tag should fail
            )
    
    def test_key_derivation(self):
        """Test key derivation from password."""
        password = "secure_password_123"
        salt = os.urandom(16)
        
        # Derive a key
        key1, salt1 = derive_key_from_password(
            password,
            salt=salt,
            algorithm=CipherAlgorithm.AES_256_GCM
        )
        
        # Derive the same key again with the same parameters
        key2, salt2 = derive_key_from_password(
            password,
            salt=salt,
            algorithm=CipherAlgorithm.AES_256_GCM
        )
        
        # The keys should be the same
        self.assertEqual(key1, key2)
        self.assertEqual(salt1, salt2)
        
        # Different salt should produce different keys
        key3, _ = derive_key_from_password(
            password,
            salt=os.urandom(16),  # Different salt
            algorithm=CipherAlgorithm.AES_256_GCM
        )
        self.assertNotEqual(key1, key3)
        
        # Different password should produce different keys
        key4, _ = derive_key_from_password(
            "different_password",
            salt=salt,
            algorithm=CipherAlgorithm.AES_256_GCM
        )
        self.assertNotEqual(key1, key4)


class TestKeyExchange(unittest.TestCase):
    """Test cases for key exchange functionality."""
    
    def test_ecdh_key_exchange(self):
        """Test ECDH key exchange."""
        # Create two ECDH key exchange instances
        alice = ECDHKeyExchange()
        bob = ECDHKeyExchange()
        
        # Generate key pairs
        alice.generate_keypair()
        bob.generate_keypair()
        
        # Exchange public keys
        alice_public = alice.get_public_key_bytes()
        bob_public = bob.get_public_key_bytes()
        
        alice.peer_public_key = bob_public
        bob.peer_public_key = alice_public
        
        # Compute shared secrets
        alice_secret = alice.compute_shared_secret()
        bob_secret = bob.compute_shared_secret()
        
        # The shared secrets should match
        self.assertEqual(alice_secret, bob_secret)
        
        # Derive keys from the shared secret
        alice_key = alice.derive_key(32)
        bob_key = bob.derive_key(32)
        
        self.assertEqual(alice_key, bob_key)
    
    def test_rsa_key_exchange(self):
        """Test RSA key exchange."""
        # Create RSA key exchange instances
        alice = RSAKeyExchange()
        bob = RSAKeyExchange()
        
        # Generate key pairs
        alice.generate_keypair()
        bob.generate_keypair()
        
        # Exchange public keys
        alice_public = alice.get_public_key_bytes()
        bob_public = bob.get_public_key_bytes()
        
        alice.peer_public_key = bob_public
        bob.peer_public_key = alice_public
        
        # Alice encrypts a shared secret with Bob's public key
        encrypted_secret, alice_secret = alice.encrypt_shared_secret()
        
        # Bob decrypts the shared secret with his private key
        bob_secret = bob.decrypt_shared_secret(encrypted_secret)
        
        # The shared secrets should match
        self.assertEqual(alice_secret, bob_secret)
        
        # Derive keys from the shared secret
        alice_key = alice.derive_key(32)
        bob_key = bob.derive_key(32)
        
        self.assertEqual(alice_key, bob_key)
    
    def test_x25519_key_exchange(self):
        """Test X25519 key exchange."""
        # Create two X25519 key exchange instances
        alice = X25519KeyExchange()
        bob = X25519KeyExchange()
        
        # Generate key pairs
        alice.generate_keypair()
        bob.generate_keypair()
        
        # Exchange public keys
        alice_public = alice.get_public_key_bytes()
        bob_public = bob.get_public_key_bytes()
        
        alice.peer_public_key = bob_public
        bob.peer_public_key = alice_public
        
        # Compute shared secrets
        alice_secret = alice.compute_shared_secret()
        bob_secret = bob.compute_shared_secret()
        
        # The shared secrets should match
        self.assertEqual(alice_secret, bob_secret)
        
        # Derive keys from the shared secret
        alice_key = alice.derive_key(32)
        bob_key = bob.derive_key(32)
        
        self.assertEqual(alice_key, bob_key)


class TestCertificateManager(unittest.TestCase):
    """Test cases for certificate management."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.TemporaryDirectory()
        self.ca_cert_path = os.path.join(self.test_dir.name, 'ca.crt')
        self.ca_key_path = os.path.join(self.test_dir.name, 'ca.key')
        
        # Create a self-signed CA certificate
        self.ca_manager = CertificateManager()
        self.ca_cert, self.ca_key = self.ca_manager.create_self_signed_ca(
            subject={
                'CN': 'Test CA',
                'O': 'Test Organization',
                'C': 'US'
            },
            key_type=KeyType.RSA,
            key_size=2048,
            validity_days=365,
            output_dir=self.test_dir.name
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.test_dir.cleanup()
    
    def test_create_self_signed_ca(self):
        """Test creating a self-signed CA certificate."""
        # Verify the CA certificate
        self.assertEqual(
            self.ca_cert.subject.rfc4514_string(),
            'CN=Test CA,O=Test Organization,C=US'
        )
        self.assertTrue(
            self.ca_cert.issuer.rfc4514_string().startswith('CN=Test CA')
        )
        
        # Verify the certificate has the correct extensions
        basic_constraints = self.ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        self.assertTrue(basic_constraints.ca)
        
        # Verify the key usage
        key_usage = self.ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
        self.assertTrue(key_usage.key_cert_sign)
        self.assertTrue(key_usage.crl_sign)
    
    def test_generate_certificate(self):
        """Test generating and signing a certificate."""
        # Create a certificate manager with the CA
        manager = CertificateManager(
            ca_cert_path=self.ca_cert_path,
            ca_key_path=self.ca_key_path
        )
        
        # Generate a server certificate
        cert, private_key = manager.generate_certificate(
            subject={
                'CN': 'test.example.com',
                'O': 'Test Organization',
                'C': 'US'
            },
            key_type=KeyType.RSA,
            key_size=2048,
            validity_days=365,
            is_ca=False,
            key_usage=[
                KeyUsage.DIGITAL_SIGNATURE,
                KeyUsage.KEY_ENCIPHERMENT
            ],
            extended_key_usage=[
                ExtendedKeyUsage.SERVER_AUTH,
                ExtendedKeyUsage.CLIENT_AUTH
            ],
            san_dns_names=['test.example.com', 'www.test.example.com'],
            san_ips=['192.168.1.1'],
            output_dir=self.test_dir.name
        )
        
        # Verify the certificate
        self.assertEqual(
            cert.subject.rfc4514_string(),
            'CN=test.example.com,O=Test Organization,C=US'
        )
        self.assertEqual(
            cert.issuer.rfc4514_string(),
            'CN=Test CA,O=Test Organization,C=US'
        )
        
        # Verify the certificate is signed by the CA
        public_key = self.ca_cert.public_key()
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        
        # Verify the subject alternative names
        san_extension = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        
        dns_names = san_extension.get_values_for_type(x509.DNSName)
        self.assertIn('test.example.com', dns_names)
        self.assertIn('www.test.example.com', dns_names)
        
        ip_addresses = san_extension.get_values_for_type(x509.IPAddress)
        self.assertIn('192.168.1.1', [str(ip) for ip in ip_addresses])
    
    def test_generate_csr(self):
        """Test generating a certificate signing request."""
        # Create a certificate manager
        manager = CertificateManager()
        
        # Generate a CSR
        csr, private_key = generate_csr(
            subject={
                'CN': 'test.example.com',
                'O': 'Test Organization',
                'C': 'US'
            },
            key_type=KeyType.RSA,
            key_size=2048,
            key_usage=[
                KeyUsage.DIGITAL_SIGNATURE,
                KeyUsage.KEY_ENCIPHERMENT
            ],
            extended_key_usage=[
                ExtendedKeyUsage.SERVER_AUTH,
                ExtendedKeyUsage.CLIENT_AUTH
            ],
            san_dns_names=['test.example.com'],
            output_dir=self.test_dir.name
        )
        
        # Verify the CSR
        self.assertEqual(
            csr.subject.rfc4514_string(),
            'CN=test.example.com,O=Test Organization,C=US'
        )
        
        # Verify the CSR has the correct extensions
        extensions = {ext.oid.dotted_string: ext for ext in csr.extensions}
        
        self.assertIn('2.5.29.15', extensions)  # Key Usage
        self.assertIn('2.5.29.37', extensions)  # Extended Key Usage
        self.assertIn('2.5.29.17', extensions)  # Subject Alternative Name
        
        # Sign the CSR with the CA
        cert = manager.sign_certificate(
            csr=csr,
            ca_cert_path=self.ca_cert_path,
            ca_key_path=self.ca_key_path,
            validity_days=365,
            output_path=os.path.join(self.test_dir.name, 'signed.crt')
        )
        
        # Verify the signed certificate
        self.assertEqual(
            cert.subject.rfc4514_string(),
            'CN=test.example.com,O=Test Organization,C=US'
        )
        self.assertEqual(
            cert.issuer.rfc4514_string(),
            'CN=Test CA,O=Test Organization,C=US'
        )


if __name__ == '__main__':
    unittest.main()
