"""
Packet handling for the VPN Security Project.

This module provides functionality for creating, parsing, and processing
VPN protocol packets, including encapsulation, encryption, and fragmentation.
"""
import struct
import zlib
import logging
from typing import Optional, Tuple, Dict, List, Any, Union, Callable, TypeVar
from dataclasses import dataclass
from enum import IntEnum, auto

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

from utils.logger import LoggableMixin
from utils.validator import (
    validate_bytes, validate_integer, validate_boolean,
    validate_enum, validate_dict, validate_string,
    ValidationError
)

# Type aliases
BytesLike = Union[bytes, bytearray, memoryview]

# Constants
MAX_PACKET_SIZE = 65535  # Maximum UDP packet size
MAX_FRAGMENT_SIZE = 1400  # Conservative MTU for VPN packets
HEADER_SIZE = 24  # Size of the packet header in bytes
MAGIC = b'VPNS'  # Magic number for packet identification
VERSION = 1      # Protocol version

class PacketType(IntEnum):
    """Types of VPN packets."""
    DATA = 0x01           # Encapsulated data packet
    CONTROL = 0x02        # Control message (handshake, keepalive, etc.)
    FRAGMENT = 0x04       # Fragment of a larger packet
    HANDSHAKE_INIT = 0x10 # Initial handshake
    HANDSHAKE_RESP = 0x11 # Handshake response
    HANDSHAKE_FIN = 0x12  # Handshake finalization
    KEEPALIVE = 0x20      # Keepalive packet
    ERROR = 0xFF          # Error notification

class EncryptionMethod(IntEnum):
    """Supported encryption methods."""
    NONE = 0x00
    AES_256_GCM = 0x01
    CHACHA20_POLY1305 = 0x02

class CompressionMethod(IntEnum):
    """Supported compression methods."""
    NONE = 0x00
    DEFLATE = 0x01
    LZ4 = 0x02

class PacketError(Exception):
    """Base exception for packet-related errors."""
    pass

class InvalidPacketError(PacketError):
    """Raised when a packet is malformed or invalid."""
    pass

class DecryptionError(PacketError):
    """Raised when packet decryption fails."""
    pass

@dataclass
class PacketHeader:
    """VPN packet header structure."""
    magic: bytes = MAGIC
    version: int = VERSION
    packet_type: int = PacketType.DATA
    flags: int = 0
    packet_id: int = 0
    payload_length: int = 0
    
    # Header format: magic(4B) + version(1B) + type(1B) + flags(2B) + packet_id(8B) + length(8B)
    FORMAT = '!4sBBHIQ'
    SIZE = struct.calcsize(FORMAT)
    
    def pack(self) -> bytes:
        """Pack the header into bytes."""
        return struct.pack(
            self.FORMAT,
            self.magic,
            self.version,
            self.packet_type,
            self.flags,
            self.packet_id,
            self.payload_length
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> 'PacketHeader':
        """Unpack a header from bytes."""
        if len(data) < cls.SIZE:
            raise InvalidPacketError(f"Header too short: {len(data)} < {cls.SIZE}")
        
        magic, version, ptype, flags, pkt_id, length = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        
        if magic != MAGIC:
            raise InvalidPacketError(f"Invalid magic number: {magic!r} != {MAGIC!r}")
        
        if version != VERSION:
            raise InvalidPacketError(f"Unsupported protocol version: {version}")
        
        return cls(magic, version, ptype, flags, pkt_id, length)

@dataclass
class Packet:
    """VPN packet with header and payload."""
    header: PacketHeader
    payload: bytes
    
    def __post_init__(self):
        """Validate the packet after initialization."""
        if len(self.payload) != self.header.payload_length:
            raise ValueError("Payload length does not match header")
    
    def pack(self) -> bytes:
        """Pack the entire packet into bytes."""
        return self.header.pack() + self.payload
    
    @classmethod
    def unpack(cls, data: bytes) -> 'Packet':
        """Unpack a packet from bytes."""
        header = PacketHeader.unpack(data)
        payload = data[header.SIZE:header.SIZE + header.payload_length]
        return cls(header, payload)
    
    def __len__(self) -> int:
        """Get the total packet length."""
        return self.header.SIZE + len(self.payload)

class PacketProcessor(LoggableMixin):
    """
    Handles packet creation, encryption, and processing.
    
    This class provides methods for creating different types of packets,
    encrypting/decrypting them, and processing incoming packets.
    """
    
    def __init__(
        self,
        encryption_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
        compression: bool = False,
        **kwargs
    ):
        """
        Initialize the packet processor.
        
        Args:
            encryption_key: Key for packet encryption.
            hmac_key: Key for HMAC verification.
            compression: Whether to enable compression.
            **kwargs: Additional arguments for LoggableMixin.
        """
        super().__init__(**kwargs)
        
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key
        self.compression = compression
        self.packet_counter = 0
        self.fragments: Dict[int, Dict[int, bytes]] = {}
        
        # Initialize crypto primitives
        self.cipher = None
        self.hmac_ctx = None
        
        if self.encryption_key:
            self._init_crypto()
    
    def _init_crypto(self) -> None:
        """Initialize cryptographic primitives."""
        if not self.encryption_key:
            return
            
        # Initialize AES-256-GCM cipher
        iv = self.encryption_key[:12]  # 96-bit IV for GCM
        self.cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(iv)
        )
        
        # Initialize HMAC-SHA256 for packet authentication
        if self.hmac_key:
            self.hmac_ctx = hmac.HMAC(
                self.hmac_key,
                hashes.SHA256()
            )
    
    def create_packet(
        self,
        payload: bytes,
        packet_type: int = PacketType.DATA,
        flags: int = 0,
        packet_id: Optional[int] = None,
        encrypt: bool = True,
        compress: Optional[bool] = None
    ) -> bytes:
        """
        Create a new packet with the given payload.
        
        Args:
            payload: The payload data.
            packet_type: The type of packet.
            flags: Packet flags.
            packet_id: Optional packet ID. If None, a new one is generated.
            encrypt: Whether to encrypt the payload.
            compress: Whether to compress the payload. If None, uses instance default.
            
        Returns:
            The packed packet as bytes.
        """
        if compress is None:
            compress = self.compression
        
        # Compress the payload if requested
        if compress and payload:
            payload = self._compress(payload)
            flags |= 0x01  # Set compression flag
        
        # Encrypt the payload if requested and we have a key
        if encrypt and self.encryption_key and payload:
            payload = self._encrypt(payload)
            flags |= 0x02  # Set encryption flag
        
        # Generate a new packet ID if none was provided
        if packet_id is None:
            self.packet_counter = (self.packet_counter + 1) & 0xFFFFFFFF
            packet_id = self.packet_counter
        
        # Create and pack the header
        header = PacketHeader(
            packet_type=packet_type,
            flags=flags,
            packet_id=packet_id,
            payload_length=len(payload)
        )
        
        # Create the packet
        packet = Packet(header, payload)
        
        # Add HMAC if we have an HMAC key
        if self.hmac_key:
            packet = self._add_hmac(packet)
        
        return packet.pack()
    
    def process_packet(self, data: bytes) -> Optional[Packet]:
        """
        Process an incoming packet.
        
        Args:
            data: The raw packet data.
            
        Returns:
            The processed Packet object, or None if the packet is a fragment
            that hasn't been fully reassembled yet.
            
        Raises:
            PacketError: If the packet is invalid or processing fails.
        """
        try:
            # Verify HMAC if we have an HMAC key
            if self.hmac_key:
                data = self._verify_hmac(data)
            
            # Parse the packet
            packet = Packet.unpack(data)
            
            # Handle packet types
            if packet.header.packet_type == PacketType.FRAGMENT:
                return self._handle_fragment(packet)
            
            # Decrypt the payload if needed
            if packet.header.flags & 0x02 and self.encryption_key:
                try:
                    packet.payload = self._decrypt(packet.payload)
                except Exception as e:
                    raise DecryptionError(f"Failed to decrypt packet: {e}") from e
            
            # Decompress the payload if needed
            if packet.header.flags & 0x01:
                try:
                    packet.payload = self._decompress(packet.payload)
                except Exception as e:
                    raise PacketError(f"Failed to decompress packet: {e}") from e
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}", exc_info=True)
            raise
    
    def _handle_fragment(self, packet: Packet) -> Optional[Packet]:
        """
        Handle a packet fragment.
        
        Args:
            packet: The fragment packet.
            
        Returns:
            The reassembled packet if all fragments are received, None otherwise.
        """
        # Extract fragment info from flags
        is_first = bool(packet.header.flags & 0x10)
        is_last = bool(packet.header.flags & 0x20)
        fragment_id = (packet.header.flags >> 8) & 0xFFFF
        
        # Initialize fragment storage if needed
        if fragment_id not in self.fragments:
            self.fragments[fragment_id] = {}
        
        # Store the fragment
        self.fragments[fragment_id][packet.header.packet_id] = packet.payload
        
        # Check if we have all fragments
        if is_first and is_last:
            # Single fragment packet
            return self._reassemble_packet(fragment_id, [packet.payload])
        
        # Wait for all fragments
        if is_last:
            # Get the expected number of fragments from the last fragment's payload
            try:
                total_fragments = int.from_bytes(packet.payload[:4], 'big')
                fragment_ids = sorted(self.fragments[fragment_id].keys())
                
                # Check if we have all fragments
                if len(fragment_ids) == total_fragments and fragment_ids[-1] - fragment_ids[0] + 1 == total_fragments:
                    # Reassemble the packet
                    fragments = [self.fragments[fragment_id][fid] for fid in fragment_ids]
                    return self._reassemble_packet(fragment_id, fragments)
            except Exception as e:
                self.logger.error(f"Error reassembling fragments: {e}")
                del self.fragments[fragment_id]
        
        return None
    
    def _reassemble_packet(self, fragment_id: int, fragments: List[bytes]) -> Packet:
        """
        Reassemble a packet from fragments.
        
        Args:
            fragment_id: The fragment group ID.
            fragments: List of fragment payloads in order.
            
        Returns:
            The reassembled packet.
        """
        try:
            # The first fragment contains the original packet header
            header = PacketHeader.unpack(fragments[0])
            
            # Reassemble the payload
            payload = b''.join(fragments[1:] if len(fragments) > 1 else [])
            
            # Clean up
            if fragment_id in self.fragments:
                del self.fragments[fragment_id]
            
            return Packet(header, payload)
            
        except Exception as e:
            # Clean up on error
            if fragment_id in self.fragments:
                del self.fragments[fragment_id]
            raise PacketError(f"Failed to reassemble packet: {e}") from e
    
    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data."""
        if not self.cipher:
            raise ValueError("Encryption not initialized")
        
        # Pad the data if needed
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt the data
        encryptor = self.cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return the encrypted data with the auth tag
        return encrypted + encryptor.tag
    
    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data."""
        if not self.cipher:
            raise ValueError("Encryption not initialized")
        
        # Split the data and auth tag
        if len(data) < 16:  # GCM tag is 16 bytes
            raise DecryptionError("Data too short to contain auth tag")
        
        encrypted = data[:-16]
        tag = data[-16:]
        
        # Decrypt the data
        try:
            decryptor = self.cipher.decryptor()
            padded_data = decryptor.update(encrypted) + decryptor.finalize_with_tag(tag)
            
            # Unpad the data
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
            
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def _compress(self, data: bytes) -> bytes:
        """Compress data using zlib."""
        return zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
    
    def _decompress(self, data: bytes) -> bytes:
        """Decompress data using zlib."""
        try:
            return zlib.decompress(data)
        except zlib.error as e:
            raise PacketError(f"Decompression failed: {e}") from e
    
    def _add_hmac(self, packet: Packet) -> Packet:
        """Add an HMAC to the packet."""
        if not self.hmac_ctx:
            return packet
        
        # Create a copy of the HMAC context
        hmac_ctx = self.hmac_ctx.copy()
        
        # Update with the packet data
        hmac_ctx.update(packet.header.pack())
        hmac_ctx.update(packet.payload)
        
        # Get the HMAC and append it to the payload
        hmac_value = hmac_ctx.finalize()
        packet.payload += hmac_value
        packet.header.payload_length = len(packet.payload)
        
        return packet
    
    def _verify_hmac(self, data: bytes) -> bytes:
        """Verify and remove an HMAC from packet data."""
        if not self.hmac_ctx or len(data) < 32:  # SHA-256 HMAC is 32 bytes
            return data
        
        # Split the data and HMAC
        packet_data = data[:-32]
        received_hmac = data[-32:]
        
        # Calculate the expected HMAC
        hmac_ctx = self.hmac_ctx.copy()
        hmac_ctx.update(packet_data)
        expected_hmac = hmac_ctx.finalize()
        
        # Compare the HMACs
        if not hmac.compare_digest(received_hmac, expected_hmac):
            raise PacketError("HMAC verification failed")
        
        return packet_data
    
    def create_handshake_init(self, client_public_key: bytes) -> bytes:
        """Create a handshake initialization packet."""
        return self.create_packet(
            payload=client_public_key,
            packet_type=PacketType.HANDSHAKE_INIT,
            encrypt=False,
            compress=False
        )
    
    def create_handshake_response(self, server_public_key: bytes, encrypted_data: bytes) -> bytes:
        """Create a handshake response packet."""
        payload = server_public_key + encrypted_data
        return self.create_packet(
            payload=payload,
            packet_type=PacketType.HANDSHAKE_RESP,
            encrypt=False,
            compress=False
        )
    
    def create_handshake_finish(self) -> bytes:
        """Create a handshake finish packet."""
        return self.create_packet(
            payload=b'',
            packet_type=PacketType.HANDSHAKE_FIN,
            encrypt=True,
            compress=False
        )
    
    def create_keepalive(self) -> bytes:
        """Create a keepalive packet."""
        return self.create_packet(
            payload=b'\x00',
            packet_type=PacketType.KEEPALIVE,
            encrypt=False,
            compress=False
        )
    
    def create_error(self, message: str) -> bytes:
        """Create an error packet."""
        return self.create_packet(
            payload=message.encode('utf-8'),
            packet_type=PacketType.ERROR,
            encrypt=False,
            compress=False
        )

# Example usage
if __name__ == "__main__":
    import os
    
    # Generate random keys for testing
    enc_key = os.urandom(32)  # 256-bit key
    hmac_key = os.urandom(32)  # 256-bit HMAC key
    
    # Create a packet processor
    processor = PacketProcessor(
        encryption_key=enc_key,
        hmac_key=hmac_key,
        compression=True
    )
    
    # Create a test packet
    test_data = b"This is a test message for the VPN packet handler." * 10
    packet = processor.create_packet(test_data, encrypt=True, compress=True)
    
    print(f"Original size: {len(test_data)} bytes")
    print(f"Packet size: {len(packet)} bytes")
    
    # Process the packet
    processed = processor.process_packet(packet)
    
    if processed and processed.payload == test_data:
        print("Packet processed successfully!")
    else:
        print("Packet processing failed!")
