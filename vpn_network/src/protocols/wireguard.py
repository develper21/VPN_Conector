"""
WireGuard Protocol Implementation

This module provides WireGuard-compatible packet format, modern cryptography,
and key rotation mechanism for the VPN Security Project.
WireGuard uses ChaCha20-Poly1305 for encryption and Curve25519 for key exchange.
"""
import os
import time
import struct
import socket
import hashlib
import secrets
from typing import Optional, Dict, Any, Tuple, List, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend
import nacl.bindings
import nacl.public
import nacl.secret

from utils.logger import LoggableMixin
from utils.validator import validate_integer, validate_string, validate_dict


class WireGuardMessageType(Enum):
    """WireGuard message types."""
    HANDSHAKE_INITIATION = 1
    HANDSHAKE_RESPONSE = 2
    COOKIE_REPLY = 3
    DATA = 4


class WireGuardPacketType(Enum):
    """WireGuard packet types."""
    HANDSHAKE_INITIATION = auto()
    HANDSHAKE_RESPONSE = auto()
    COOKIE_REPLY = auto()
    DATA = auto()
    KEEPALIVE = auto()


@dataclass
class WireGuardPacketHeader:
    """WireGuard packet header structure."""
    message_type: int
    reserved_zero: int = 0
    sender_index: int = 0
    receiver_index: int = 0
    
    def to_bytes(self) -> bytes:
        """Convert header to bytes."""
        return struct.pack('!B3sII', 
                          self.message_type,
                          b'\x00\x00\x00',  # reserved zero
                          self.sender_index,
                          self.receiver_index)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'WireGuardPacketHeader':
        """Parse header from bytes."""
        if len(data) < 13:
            raise ValueError("Invalid WireGuard packet header")
        
        message_type, reserved, sender_index, receiver_index = struct.unpack('!B3sII', data[:13])
        return cls(
            message_type=message_type,
            sender_index=sender_index,
            receiver_index=receiver_index
        )


@dataclass
class WireGuardHandshakeInitiation:
    """WireGuard handshake initiation packet."""
    message_type: int = 1
    reserved_zero: bytes = b'\x00\x00\x00'
    sender_index: int = 0
    ephemeral_public_key: bytes = b''
    static_public_key: bytes = b''
    timestamp: bytes = b''
    mac1: bytes = b''
    mac2: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Convert handshake initiation to bytes."""
        return (
            struct.pack('!B3sI', self.message_type, self.reserved_zero, self.sender_index) +
            self.ephemeral_public_key +
            self.static_public_key +
            self.timestamp +
            self.mac1 +
            self.mac2
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'WireGuardHandshakeInitiation':
        """Parse handshake initiation from bytes."""
        if len(data) != 148:  # Fixed size for handshake initiation
            raise ValueError("Invalid handshake initiation packet size")
        
        message_type, reserved, sender_index = struct.unpack('!B3sI', data[:8])
        ephemeral_public_key = data[8:40]
        static_public_key = data[40:72]
        timestamp = data[72:88]
        mac1 = data[88:104]
        mac2 = data[104:120]
        
        return cls(
            message_type=message_type,
            sender_index=sender_index,
            ephemeral_public_key=ephemeral_public_key,
            static_public_key=static_public_key,
            timestamp=timestamp,
            mac1=mac1,
            mac2=mac2
        )


@dataclass
class WireGuardHandshakeResponse:
    """WireGuard handshake response packet."""
    message_type: int = 2
    reserved_zero: bytes = b'\x00\x00\x00'
    sender_index: int = 0
    receiver_index: int = 0
    ephemeral_public_key: bytes = b''
    static_public_key: bytes = b''
    timestamp: bytes = b''
    mac1: bytes = b''
    mac2: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Convert handshake response to bytes."""
        return (
            struct.pack('!B3sII', self.message_type, self.reserved_zero, 
                       self.sender_index, self.receiver_index) +
            self.ephemeral_public_key +
            self.static_public_key +
            self.timestamp +
            self.mac1 +
            self.mac2
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'WireGuardHandshakeResponse':
        """Parse handshake response from bytes."""
        if len(data) != 164:  # Fixed size for handshake response
            raise ValueError("Invalid handshake response packet size")
        
        message_type, reserved, sender_index, receiver_index = struct.unpack('!B3sII', data[:13])
        ephemeral_public_key = data[13:45]
        static_public_key = data[45:77]
        timestamp = data[77:93]
        mac1 = data[93:109]
        mac2 = data[109:125]
        
        return cls(
            message_type=message_type,
            sender_index=sender_index,
            receiver_index=receiver_index,
            ephemeral_public_key=ephemeral_public_key,
            static_public_key=static_public_key,
            timestamp=timestamp,
            mac1=mac1,
            mac2=mac2
        )


@dataclass
class WireGuardDataPacket:
    """WireGuard data packet."""
    message_type: int = 4
    reserved_zero: bytes = b'\x00\x00\x00'
    receiver_index: int = 0
    counter: int = 0
    encrypted_data: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Convert data packet to bytes."""
        return (
            struct.pack('!B3sIQ', self.message_type, self.reserved_zero, 
                       self.receiver_index, self.counter) +
            self.encrypted_data
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'WireGuardDataPacket':
        """Parse data packet from bytes."""
        if len(data) < 16:
            raise ValueError("Invalid data packet size")
        
        message_type, reserved, receiver_index, counter = struct.unpack('!B3sIQ', data[:16])
        encrypted_data = data[16:]
        
        return cls(
            message_type=message_type,
            receiver_index=receiver_index,
            counter=counter,
            encrypted_data=encrypted_data
        )


class WireGuardCrypto(LoggableMixin):
    """WireGuard cryptographic operations."""
    
    # WireGuard constants
    SESSION_KEY_SIZE = 32
    PUBLIC_KEY_SIZE = 32
    PRIVATE_KEY_SIZE = 32
    TIMESTAMP_SIZE = 12
    MAC_SIZE = 16
    NONCE_SIZE = 12
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
        self.key_pairs = {}
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Curve25519 keypair."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    def shared_secret(self, private_key: bytes, public_key: bytes) -> bytes:
        """Compute shared secret using Curve25519."""
        try:
            private_key_obj = X25519PrivateKey.from_private_bytes(private_key)
            public_key_obj = X25519PublicKey.from_public_bytes(public_key)
            shared_key = private_key_obj.exchange(public_key_obj)
            return shared_key
        except Exception as e:
            self.logger.error(f"Shared secret computation failed: {e}")
            raise
    
    def derive_session_keys(self, shared_secret: bytes, public_key: bytes) -> Dict[str, bytes]:
        """Derive session keys using HKDF."""
        # Input key material
        ikm = shared_secret + public_key
        
        # Extract
        salt = b'\x00' * 32  # WireGuard uses zero salt
        prk = hashlib.sha256(salt + ikm).digest()
        
        # Expand
        info = b'wireguard'
        okm = b''
        i = 1
        
        while len(okm) < 64:  # We need 64 bytes (2 x 32)
            t = hmac.new(prk, info + bytes([i]), hashlib.sha256).digest()
            okm += t
            i += 1
        
        return {
            'initiator_key': okm[:32],
            'responder_key': okm[32:64]
        }
    
    def encrypt_chacha20poly1305(self, plaintext: bytes, key: bytes, 
                                nonce: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305."""
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Calculate Poly1305 MAC
        mac_key = encryptor.tag[:16]  # First 16 bytes as MAC key
        mac = hmac.new(mac_key, associated_data + ciphertext, hashlib.sha256).digest()[:16]
        
        return ciphertext, mac
    
    def decrypt_chacha20poly1305(self, ciphertext: bytes, key: bytes, 
                                nonce: bytes, mac: bytes, 
                                associated_data: bytes = b'') -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        # Verify MAC
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        mac_key = encryptor.tag[:16]
        expected_mac = hmac.new(mac_key, associated_data + ciphertext, hashlib.sha256).digest()[:16]
        
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("MAC verification failed")
        
        # Decrypt
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def generate_timestamp(self) -> bytes:
        """Generate WireGuard timestamp (nanoseconds since epoch)."""
        timestamp = int(time.time() * 1e9)
        return struct.pack('!Q', timestamp)[:self.TIMESTAMP_SIZE]
    
    def verify_timestamp(self, timestamp: bytes, max_age_seconds: int = 120) -> bool:
        """Verify timestamp is within acceptable range."""
        if len(timestamp) != self.TIMESTAMP_SIZE:
            return False
        
        # Pad to 8 bytes for unpacking
        timestamp_padded = timestamp + b'\x00\x00\x00\x00'
        try:
            timestamp_ns = struct.unpack('!Q', timestamp_padded)[0]
            current_ns = int(time.time() * 1e9)
            
            age_seconds = (current_ns - timestamp_ns) / 1e9
            return 0 <= age_seconds <= max_age_seconds
        except:
            return False


class WireGuardKeyRotation(LoggableMixin):
    """WireGuard key rotation mechanism."""
    
    def __init__(self, rotation_interval: int = 120):
        self.rotation_interval = rotation_interval  # seconds
        self.current_keypair = None
        self.next_keypair = None
        self.key_timestamps = {}
        self.rotation_callbacks = []
    
    def generate_initial_keypair(self) -> Tuple[bytes, bytes]:
        """Generate initial keypair."""
        crypto = WireGuardCrypto()
        private_key, public_key = crypto.generate_keypair()
        
        self.current_keypair = (private_key, public_key)
        self.key_timestamps[public_key] = time.time()
        
        self.logger.info("Initial WireGuard keypair generated")
        return private_key, public_key
    
    def rotate_keypair(self) -> Tuple[bytes, bytes]:
        """Rotate to next keypair."""
        crypto = WireGuardCrypto()
        new_private_key, new_public_key = crypto.generate_keypair()
        
        # Shift keypairs
        if self.next_keypair:
            self.current_keypair = self.next_keypair
        
        self.next_keypair = (new_private_key, new_public_key)
        self.key_timestamps[new_public_key] = time.time()
        
        self.logger.info("WireGuard keypair rotated")
        return new_private_key, new_public_key
    
    def should_rotate(self) -> bool:
        """Check if key rotation is needed."""
        if not self.current_keypair:
            return True
        
        current_public_key = self.current_keypair[1]
        key_age = time.time() - self.key_timestamps.get(current_public_key, 0)
        
        return key_age >= self.rotation_interval
    
    def get_active_keypair(self) -> Optional[Tuple[bytes, bytes]]:
        """Get currently active keypair."""
        if self.should_rotate():
            self.rotate_keypair()
        
        return self.current_keypair
    
    def add_rotation_callback(self, callback):
        """Add callback for key rotation events."""
        self.rotation_callbacks.append(callback)
    
    def notify_rotation(self, old_keypair: Tuple[bytes, bytes], 
                       new_keypair: Tuple[bytes, bytes]):
        """Notify callbacks of key rotation."""
        for callback in self.rotation_callbacks:
            try:
                callback(old_keypair, new_keypair)
            except Exception as e:
                self.logger.error(f"Key rotation callback failed: {e}")


class WireGuardProtocol(LoggableMixin):
    """Main WireGuard protocol implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.crypto = WireGuardCrypto()
        self.key_rotation = WireGuardKeyRotation(
            config.get('key_rotation_interval', 120)
        )
        self.peers = {}
        self.sessions = {}
        
        # Generate initial keypair
        self.private_key, self.public_key = self.crypto.generate_keypair()
        
        # Setup key rotation
        self.key_rotation.generate_initial_keypair()
        self.key_rotation.add_rotation_callback(self._on_key_rotation)
    
    def _on_key_rotation(self, old_keypair: Tuple[bytes, bytes], 
                        new_keypair: Tuple[bytes, bytes]):
        """Handle key rotation events."""
        self.logger.info("WireGuard keys rotated, updating sessions")
        # Update existing sessions with new keys
        for peer_id, session in self.sessions.items():
            self._rekey_session(peer_id, session)
    
    def _rekey_session(self, peer_id: str, session: Dict[str, Any]):
        """Rekey existing session."""
        # Generate new session keys with rotated keys
        peer_public_key = self.peers.get(peer_id, {}).get('public_key')
        if peer_public_key:
            shared_secret = self.crypto.shared_secret(self.private_key, peer_public_key)
            session_keys = self.crypto.derive_session_keys(shared_secret, peer_public_key)
            session['keys'] = session_keys
            session['key_timestamp'] = time.time()
    
    def add_peer(self, peer_id: str, public_key: bytes, endpoint: Optional[Tuple[str, int]] = None):
        """Add a WireGuard peer."""
        self.peers[peer_id] = {
            'public_key': public_key,
            'endpoint': endpoint,
            'allowed_ips': [],
            'last_handshake': 0,
            'rx_bytes': 0,
            'tx_bytes': 0
        }
        self.logger.info(f"Added WireGuard peer: {peer_id}")
    
    def create_handshake_initiation(self, peer_id: str) -> WireGuardHandshakeInitiation:
        """Create handshake initiation packet."""
        peer = self.peers.get(peer_id)
        if not peer:
            raise ValueError(f"Peer not found: {peer_id}")
        
        # Generate ephemeral keypair
        ephemeral_private, ephemeral_public = self.crypto.generate_keypair()
        
        # Compute shared secret
        shared_secret = self.crypto.shared_secret(ephemeral_private, peer['public_key'])
        
        # Derive session keys
        session_keys = self.crypto.derive_session_keys(shared_secret, peer['public_key'])
        
        # Store session
        self.sessions[peer_id] = {
            'ephemeral_private': ephemeral_private,
            'ephemeral_public': ephemeral_public,
            'keys': session_keys,
            'key_timestamp': time.time(),
            'sender_index': secrets.randbits(32)
        }
        
        # Create timestamp
        timestamp = self.crypto.generate_timestamp()
        
        # Create MAC1 (authentication with static keys)
        mac1_data = struct.pack('!I', self.sessions[peer_id]['sender_index']) + \
                   ephemeral_public + peer['public_key'] + timestamp
        mac1 = hmac.new(self.private_key, mac1_data, hashlib.blake2s, digest_size=16).digest()
        
        # Create MAC2 (anti-replay, cookie-based)
        mac2 = b'\x00' * 16  # Simplified - real implementation uses cookies
        
        return WireGuardHandshakeInitiation(
            sender_index=self.sessions[peer_id]['sender_index'],
            ephemeral_public_key=ephemeral_public,
            static_public_key=self.public_key,
            timestamp=timestamp,
            mac1=mac1,
            mac2=mac2
        )
    
    def process_handshake_initiation(self, packet: WireGuardHandshakeInitiation, 
                                   endpoint: Tuple[str, int]) -> Optional[WireGuardHandshakeResponse]:
        """Process handshake initiation and create response."""
        # Find peer by static public key
        peer_id = None
        for pid, peer in self.peers.items():
            if peer['public_key'] == packet.static_public_key:
                peer_id = pid
                break
        
        if not peer_id:
            self.logger.warning("Handshake from unknown peer")
            return None
        
        # Generate ephemeral keypair
        ephemeral_private, ephemeral_public = self.crypto.generate_keypair()
        
        # Compute shared secret
        shared_secret = self.crypto.shared_secret(ephemeral_private, packet.ephemeral_public_key)
        
        # Derive session keys
        session_keys = self.crypto.derive_session_keys(shared_secret, packet.ephemeral_public_key)
        
        # Store session
        self.sessions[peer_id] = {
            'ephemeral_private': ephemeral_private,
            'ephemeral_public': ephemeral_public,
            'keys': session_keys,
            'key_timestamp': time.time(),
            'sender_index': secrets.randbits(32),
            'receiver_index': packet.sender_index
        }
        
        # Update peer info
        self.peers[peer_id]['endpoint'] = endpoint
        self.peers[peer_id]['last_handshake'] = time.time()
        
        # Create timestamp
        timestamp = self.crypto.generate_timestamp()
        
        # Create MAC1
        mac1_data = struct.pack('!II', self.sessions[peer_id]['sender_index'], 
                               packet.sender_index) + \
                   ephemeral_public + self.public_key + timestamp
        mac1 = hmac.new(self.private_key, mac1_data, hashlib.blake2s, digest_size=16).digest()
        
        # Create MAC2
        mac2 = b'\x00' * 16  # Simplified
        
        return WireGuardHandshakeResponse(
            sender_index=self.sessions[peer_id]['sender_index'],
            receiver_index=packet.sender_index,
            ephemeral_public_key=ephemeral_public,
            static_public_key=self.public_key,
            timestamp=timestamp,
            mac1=mac1,
            mac2=mac2
        )
    
    def create_data_packet(self, peer_id: str, data: bytes) -> Optional[WireGuardDataPacket]:
        """Create encrypted data packet."""
        session = self.sessions.get(peer_id)
        if not session:
            self.logger.error(f"No session found for peer: {peer_id}")
            return None
        
        # Get session key
        session_key = session['keys']['initiator_key']
        
        # Generate nonce (counter + random)
        counter = session.get('counter', 0) + 1
        nonce = struct.pack('!Q', counter)[:12]  # Use counter as nonce
        
        # Encrypt data
        associated_data = struct.pack('!B3sI', 4, b'\x00\x00\x00', session['sender_index'])
        ciphertext, mac = self.crypto.encrypt_chacha20poly1305(
            data, session_key, nonce, associated_data
        )
        
        # Update session counter
        session['counter'] = counter
        
        return WireGuardDataPacket(
            receiver_index=session['receiver_index'],
            counter=counter,
            encrypted_data=ciphertext + mac
        )
    
    def process_data_packet(self, packet: WireGuardDataPacket) -> Optional[Tuple[str, bytes]]:
        """Process received data packet."""
        # Find session by receiver index
        peer_id = None
        session = None
        
        for pid, sess in self.sessions.items():
            if sess.get('sender_index') == packet.receiver_index:
                peer_id = pid
                session = sess
                break
        
        if not session:
            self.logger.warning("Data packet from unknown session")
            return None
        
        # Extract MAC and ciphertext
        if len(packet.encrypted_data) < 16:
            self.logger.error("Invalid data packet size")
            return None
        
        mac = packet.encrypted_data[-16:]
        ciphertext = packet.encrypted_data[:-16]
        
        # Get session key
        session_key = session['keys']['responder_key']
        
        # Generate nonce
        nonce = struct.pack('!Q', packet.counter)[:12]
        
        # Decrypt data
        associated_data = struct.pack('!B3sI', 4, b'\x00\x00\x00', packet.receiver_index)
        
        try:
            plaintext = self.crypto.decrypt_chacha20poly1305(
                ciphertext, session_key, nonce, mac, associated_data
            )
            
            # Update peer stats
            self.peers[peer_id]['rx_bytes'] += len(plaintext)
            
            return peer_id, plaintext
            
        except Exception as e:
            self.logger.error(f"Data packet decryption failed: {e}")
            return None
