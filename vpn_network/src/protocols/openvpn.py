"""
OpenVPN Protocol Implementation

This module provides OpenVPN-compatible packet format, SSL/TLS handshake,
and configurable encryption ciphers for the VPN Security Project.
"""
import struct
import socket
import hashlib
import hmac
import time
import os
from typing import Optional, Dict, Any, Tuple, List, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ssl

from utils.logger import LoggableMixin
from utils.validator import validate_integer, validate_string, validate_dict


class OpenVPNPacketType(Enum):
    """OpenVPN packet types."""
    P_CONTROL_HARD_RESET_CLIENT_V1 = auto()
    P_CONTROL_HARD_RESET_SERVER_V1 = auto()
    P_CONTROL_HARD_RESET_CLIENT_V2 = auto()
    P_CONTROL_HARD_RESET_SERVER_V2 = auto()
    P_CONTROL_V1 = auto()
    P_ACK_V1 = auto()
    P_DATA_V1 = auto()
    P_DATA_V2 = auto()


class OpenVPNCipher(Enum):
    """Supported OpenVPN encryption ciphers."""
    AES_128_CBC = "AES-128-CBC"
    AES_192_CBC = "AES-192-CBC"
    AES_256_CBC = "AES-256-CBC"
    AES_128_GCM = "AES-128-GCM"
    AES_192_GCM = "AES-192-GCM"
    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "CHACHA20-POLY1305"


class OpenVPNAuth(Enum):
    """Supported OpenVPN authentication algorithms."""
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


@dataclass
class OpenVPNPacketHeader:
    """OpenVPN packet header structure."""
    opcode: int
    key_id: int = 0
    packet_id: int = 0
    timestamp: Optional[int] = None
    
    def to_bytes(self) -> bytes:
        """Convert header to bytes."""
        if self.opcode >= 0x80:
            # Hard reset packet format
            return struct.pack('!B', self.opcode)
        else:
            # Control packet format
            header = struct.pack('!BB', self.opcode, self.key_id)
            if self.packet_id is not None:
                header += struct.pack('!I', self.packet_id)
            return header
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'OpenVPNPacketHeader':
        """Parse header from bytes."""
        if len(data) < 1:
            raise ValueError("Invalid packet header")
        
        opcode = data[0]
        if opcode >= 0x80:
            return cls(opcode=opcode)
        
        if len(data) < 2:
            raise ValueError("Invalid control packet header")
        
        key_id = data[1]
        packet_id = None
        
        if len(data) >= 6:
            packet_id = struct.unpack('!I', data[2:6])[0]
        
        return cls(opcode=opcode, key_id=key_id, packet_id=packet_id)


@dataclass
class OpenVPNPacket:
    """OpenVPN packet structure."""
    header: OpenVPNPacketHeader
    payload: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Convert packet to bytes."""
        return self.header.to_bytes() + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'OpenVPNPacket':
        """Parse packet from bytes."""
        header = OpenVPNPacketHeader.from_bytes(data[:6])  # Max header size
        payload = data[len(header.to_bytes()):]
        return cls(header=header, payload=payload)


class OpenVPNCipherManager(LoggableMixin):
    """Manages OpenVPN encryption ciphers."""
    
    def __init__(self, cipher: OpenVPNCipher, auth: OpenVPNAuth):
        self.cipher = cipher
        self.auth = auth
        self._validate_cipher_auth()
    
    def _validate_cipher_auth(self):
        """Validate cipher and authentication combination."""
        valid_combinations = {
            OpenVPNCipher.AES_128_CBC: [OpenVPNAuth.SHA1, OpenVPNAuth.SHA256],
            OpenVPNCipher.AES_192_CBC: [OpenVPNAuth.SHA1, OpenVPNAuth.SHA256],
            OpenVPNCipher.AES_256_CBC: [OpenVPNAuth.SHA256, OpenVPNAuth.SHA512],
            OpenVPNCipher.AES_128_GCM: [OpenVPNAuth.SHA256],
            OpenVPNCipher.AES_192_GCM: [OpenVPNAuth.SHA256],
            OpenVPNCipher.AES_256_GCM: [OpenVPNAuth.SHA256],
            OpenVPNCipher.CHACHA20_POLY1305: [OpenVPNAuth.SHA256],
        }
        
        if self.auth not in valid_combinations.get(self.cipher, []):
            raise ValueError(f"Invalid cipher/auth combination: {self.cipher.value}/{self.auth.value}")
    
    def generate_key_data(self, password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Generate key data using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def create_encryptor(self, key: bytes, iv: Optional[bytes] = None) -> Any:
        """Create encryption cipher."""
        if self.cipher in [OpenVPNCipher.AES_128_CBC, OpenVPNCipher.AES_192_CBC, OpenVPNCipher.AES_256_CBC]:
            key_size = int(self.cipher.value.split('-')[1]) // 8
            if iv is None:
                iv = os.urandom(16)
            return Cipher(algorithms.AES(key[:key_size]), modes.CBC(iv), backend=default_backend())
        
        elif self.cipher in [OpenVPNCipher.AES_128_GCM, OpenVPNCipher.AES_192_GCM, OpenVPNCipher.AES_256_GCM]:
            key_size = int(self.cipher.value.split('-')[1]) // 8
            if iv is None:
                iv = os.urandom(12)  # GCM uses 12-byte IV
            return Cipher(algorithms.AES(key[:key_size]), modes.GCM(iv), backend=default_backend())
        
        elif self.cipher == OpenVPNCipher.CHACHA20_POLY1305:
            from cryptography.hazmat.primitives.ciphers import algorithms
            if iv is None:
                iv = os.urandom(12)
            return Cipher(algorithms.ChaCha20(key[:32], iv), mode=None, backend=default_backend())
        
        else:
            raise ValueError(f"Unsupported cipher: {self.cipher.value}")
    
    def encrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data with the configured cipher."""
        cipher = self.create_encryptor(key, iv)
        encryptor = cipher.encryptor()
        
        if self.cipher in [OpenVPNCipher.AES_128_GCM, OpenVPNCipher.AES_192_GCM, OpenVPNCipher.AES_256_GCM]:
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext, encryptor.tag
        else:
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext, b''
    
    def decrypt(self, data: bytes, key: bytes, iv: bytes, tag: bytes = b'') -> bytes:
        """Decrypt data with the configured cipher."""
        cipher = self.create_encryptor(key, iv)
        decryptor = cipher.decryptor()
        
        if self.cipher in [OpenVPNCipher.AES_128_GCM, OpenVPNCipher.AES_192_GCM, OpenVPNCipher.AES_256_GCM]:
            decryptor.authenticate_additional_data(b'')
            if tag:
                decryptor.tag = tag
            return decryptor.update(data) + decryptor.finalize()
        else:
            return decryptor.update(data) + decryptor.finalize()


class OpenVPNSSLHandshake(LoggableMixin):
    """Implements OpenVPN SSL/TLS handshake."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssl_context = None
        self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Setup SSL context for OpenVPN."""
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Configure TLS version
        tls_version = self.config.get('tls_version', 'TLSv1.3')
        if tls_version == 'TLSv1.2':
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Load certificates
        ca_cert = self.config.get('certificate_authority')
        if ca_cert:
            self.ssl_context.load_verify_locations(ca_cert)
        
        cert = self.config.get('certificate')
        key = self.config.get('private_key')
        if cert and key:
            self.ssl_context.load_cert_chain(cert, key)
        
        # Set cipher suites
        cipher_suites = self.config.get('cipher_suites', [
            'TLS_AES_256_GCM_SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256'
        ])
        self.ssl_context.set_ciphers(':'.join(cipher_suites))
    
    def create_client_ssl_socket(self, sock: socket.socket) -> ssl.SSLSocket:
        """Create SSL socket for client."""
        ssl_sock = self.ssl_context.wrap_socket(
            sock,
            server_hostname=self.config.get('server_hostname', 'localhost'),
            do_handshake_on_connect=False
        )
        return ssl_sock
    
    def create_server_ssl_socket(self, sock: socket.socket) -> ssl.SSLSocket:
        """Create SSL socket for server."""
        ssl_sock = self.ssl_context.wrap_socket(
            sock,
            server_side=True,
            do_handshake_on_connect=False
        )
        return ssl_sock
    
    def perform_handshake(self, ssl_sock: ssl.SSLSocket) -> bool:
        """Perform SSL/TLS handshake."""
        try:
            ssl_sock.do_handshake()
            self.logger.info("SSL/TLS handshake completed successfully")
            return True
        except ssl.SSLError as e:
            self.logger.error(f"SSL/TLS handshake failed: {e}")
            return False


class OpenVPNProtocol(LoggableMixin):
    """Main OpenVPN protocol implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cipher_manager = None
        self.ssl_handshake = None
        self.session_keys = {}
        self._setup_cipher()
        self._setup_ssl()
    
    def _setup_cipher(self):
        """Setup cipher manager."""
        cipher_str = self.config.get('cipher', 'AES-256-GCM')
        auth_str = self.config.get('auth', 'SHA256')
        
        try:
            cipher = OpenVPNCipher(cipher_str)
            auth = OpenVPNAuth(auth_str)
            self.cipher_manager = OpenVPNCipherManager(cipher, auth)
            self.logger.info(f"Cipher configured: {cipher_str}/{auth_str}")
        except ValueError as e:
            self.logger.error(f"Cipher setup failed: {e}")
            raise
    
    def _setup_ssl(self):
        """Setup SSL handshake."""
        self.ssl_handshake = OpenVPNSSLHandshake(self.config)
    
    def create_packet(self, packet_type: OpenVPNPacketType, payload: bytes = b'', 
                     packet_id: int = 0, key_id: int = 0) -> OpenVPNPacket:
        """Create OpenVPN packet."""
        header = OpenVPNPacketHeader(
            opcode=packet_type.value,
            key_id=key_id,
            packet_id=packet_id,
            timestamp=int(time.time())
        )
        return OpenVPNPacket(header=header, payload=payload)
    
    def parse_packet(self, data: bytes) -> Optional[OpenVPNPacket]:
        """Parse OpenVPN packet from bytes."""
        try:
            return OpenVPNPacket.from_bytes(data)
        except Exception as e:
            self.logger.error(f"Packet parsing failed: {e}")
            return None
    
    def encrypt_packet(self, packet: OpenVPNPacket, session_key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt OpenVPN packet."""
        iv = os.urandom(16)  # Generate IV
        packet_data = packet.to_bytes()
        
        ciphertext, tag = self.cipher_manager.encrypt(packet_data, session_key, iv)
        return iv + ciphertext, iv, tag
    
    def decrypt_packet(self, data: bytes, session_key: bytes, iv: bytes, tag: bytes = b'') -> Optional[OpenVPNPacket]:
        """Decrypt OpenVPN packet."""
        try:
            decrypted_data = self.cipher_manager.decrypt(data, session_key, iv, tag)
            return self.parse_packet(decrypted_data)
        except Exception as e:
            self.logger.error(f"Packet decryption failed: {e}")
            return None
    
    def generate_session_keys(self, pre_master_secret: bytes, client_random: bytes, 
                            server_random: bytes) -> Dict[str, bytes]:
        """Generate session keys from master secret."""
        # Simplified key derivation (OpenVPN uses more complex PRF)
        master_secret = self._derive_master_secret(pre_master_secret, client_random, server_random)
        
        key_material = self._expand_key_material(master_secret, client_random + server_random)
        
        return {
            'client_write_key': key_material[:32],
            'server_write_key': key_material[32:64],
            'client_write_iv': key_material[64:80],
            'server_write_iv': key_material[80:96],
            'client_mac_key': key_material[96:112],
            'server_mac_key': key_material[112:128]
        }
    
    def _derive_master_secret(self, pre_master: bytes, client_random: bytes, server_random: bytes) -> bytes:
        """Derive master secret from pre-master secret."""
        seed = b'master secret' + client_random + server_random
        return self._prf(pre_master, seed, 48)
    
    def _expand_key_material(self, master_secret: bytes, seed: bytes) -> bytes:
        """Expand key material from master secret."""
        return self._prf(master_secret, b'key expansion' + seed, 128)
    
    def _prf(self, secret: bytes, seed: bytes, output_length: int) -> bytes:
        """Pseudo-random function for key derivation."""
        # Simplified PRF using HMAC-SHA256
        hmac_func = hmac.new(secret, seed, hashlib.sha256)
        result = hmac_func.digest()
        
        while len(result) < output_length:
            hmac_func = hmac.new(secret, result + seed, hashlib.sha256)
            result += hmac_func.digest()
        
        return result[:output_length]
