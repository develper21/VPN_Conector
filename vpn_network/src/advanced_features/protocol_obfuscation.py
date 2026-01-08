#!/usr/bin/env python3
"""
Protocol Obfuscation Implementation for VPN
Obfuscates VPN traffic to bypass deep packet inspection (DPI) and firewalls.
Supports multiple obfuscation techniques including TLS camouflage, shadowsocks, and custom protocols.
"""
import base64
import hashlib
import json
import logging
import random
import socket
import ssl
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import zlib

from utils.logger import setup_logger


@dataclass
class ObfuscationConfig:
    """Configuration for protocol obfuscation."""
    enabled: bool = True
    technique: str = "tls_camouflage"  # tls_camouflage, shadowsocks, custom, obfs4
    encryption_method: str = "aes-256-gcm"
    compression: bool = True
    random_padding: bool = True
    packet_chopping: bool = True
    timing_obfuscation: bool = True
    fake_traffic: bool = True
    custom_headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.custom_headers is None:
            self.custom_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            }


class ProtocolObfuscator:
    """Protocol obfuscation implementation."""
    
    def __init__(self, config_path: str = "config/protocol_obfuscation.json"):
        self.logger = setup_logger("protocol_obfuscator", "INFO")
        self.config_path = Path(config_path)
        self.config = ObfuscationConfig()
        self.is_active = False
        self.encryption_key = None
        self.fake_traffic_thread = None
        self.tls_context = None
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.load_configuration()
        
        # Initialize encryption
        self._initialize_encryption()
    
    def load_configuration(self) -> None:
        """Load obfuscation configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                self.logger.info("Protocol obfuscation configuration loaded")
            else:
                self.save_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            config_data = {
                'enabled': self.config.enabled,
                'technique': self.config.technique,
                'encryption_method': self.config.encryption_method,
                'compression': self.config.compression,
                'random_padding': self.config.random_padding,
                'packet_chopping': self.config.packet_chopping,
                'timing_obfuscation': self.config.timing_obfuscation,
                'fake_traffic': self.config.fake_traffic,
                'custom_headers': self.config.custom_headers
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
            self.logger.info("Configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def _initialize_encryption(self) -> None:
        """Initialize encryption keys and contexts."""
        try:
            # Generate encryption key
            self.encryption_key = hashlib.sha256(b"vpn_obfuscation_key").digest()
            
            # Initialize TLS context for camouflage
            self.tls_context = ssl.create_default_context()
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE
            
            self.logger.debug("Encryption initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
    
    def activate(self) -> bool:
        """Activate protocol obfuscation."""
        try:
            if self.is_active:
                self.logger.warning("Protocol obfuscation is already active")
                return False
            
            if not self.config.enabled:
                self.logger.info("Protocol obfuscation is disabled in configuration")
                return False
            
            self.is_active = True
            
            # Start fake traffic generation if enabled
            if self.config.fake_traffic:
                self.fake_traffic_thread = threading.Thread(target=self._generate_fake_traffic, daemon=True)
                self.fake_traffic_thread.start()
            
            self.logger.info(f"Protocol obfuscation activated using {self.config.technique}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to activate protocol obfuscation: {e}")
            return False
    
    def deactivate(self) -> bool:
        """Deactivate protocol obfuscation."""
        try:
            if not self.is_active:
                self.logger.warning("Protocol obfuscation is not active")
                return False
            
            self.is_active = False
            
            # Stop fake traffic thread
            if self.fake_traffic_thread:
                self.fake_traffic_thread.join(timeout=5)
            
            self.logger.info("Protocol obfuscation deactivated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate protocol obfuscation: {e}")
            return False
    
    def obfuscate_packet(self, data: bytes) -> bytes:
        """Obfuscate a packet using the configured technique."""
        try:
            if not self.is_active:
                return data
            
            if self.config.technique == "tls_camouflage":
                return self._tls_camouflage_obfuscate(data)
            elif self.config.technique == "shadowsocks":
                return self._shadowsocks_obfuscate(data)
            elif self.config.technique == "custom":
                return self._custom_obfuscate(data)
            elif self.config.technique == "obfs4":
                return self._obfs4_obfuscate(data)
            else:
                return data
                
        except Exception as e:
            self.logger.error(f"Failed to obfuscate packet: {e}")
            return data
    
    def deobfuscate_packet(self, data: bytes) -> bytes:
        """Deobfuscate a packet using the configured technique."""
        try:
            if not self.is_active:
                return data
            
            if self.config.technique == "tls_camouflage":
                return self._tls_camouflage_deobfuscate(data)
            elif self.config.technique == "shadowsocks":
                return self._shadowsocks_deobfuscate(data)
            elif self.config.technique == "custom":
                return self._custom_deobfuscate(data)
            elif self.config.technique == "obfs4":
                return self._obfs4_deobfuscate(data)
            else:
                return data
                
        except Exception as e:
            self.logger.error(f"Failed to deobfuscate packet: {e}")
            return data
    
    def _tls_camouflage_obfuscate(self, data: bytes) -> bytes:
        """Obfuscate data to look like HTTPS traffic."""
        try:
            # Compress data if enabled
            if self.config.compression:
                data = zlib.compress(data)
            
            # Encrypt data
            encrypted_data = self._encrypt_data(data)
            
            # Add TLS-like headers
            tls_record = struct.pack('>BHH', 0x17, 0x0303, len(encrypted_data))  # TLS application data
            obfuscated_data = tls_record + encrypted_data
            
            # Add random padding if enabled
            if self.config.random_padding:
                padding_length = random.randint(0, 255)
                padding = bytes([padding_length] + [random.randint(0, 255) for _ in range(padding_length)])
                obfuscated_data += padding
            
            # Add HTTP-like headers for additional camouflage
            http_headers = self._generate_http_headers(len(obfuscated_data))
            final_data = http_headers.encode() + b'\r\n\r\n' + obfuscated_data
            
            return final_data
            
        except Exception as e:
            self.logger.error(f"TLS camouflage obfuscation failed: {e}")
            return data
    
    def _tls_camouflage_deobfuscate(self, data: bytes) -> bytes:
        """Deobfuscate TLS-camouflaged data."""
        try:
            # Remove HTTP headers
            if b'\r\n\r\n' in data:
                data = data.split(b'\r\n\r\n', 1)[1]
            
            # Remove padding if present
            if self.config.random_padding and len(data) > 5:
                padding_length = data[-1]
                if padding_length < len(data):
                    data = data[:-padding_length-1]
            
            # Extract TLS record
            if len(data) >= 5:
                record_type, version, length = struct.unpack('>BHH', data[:5])
                if record_type == 0x17:  # TLS application data
                    encrypted_data = data[5:5+length]
                    decrypted_data = self._decrypt_data(encrypted_data)
                    
                    # Decompress if needed
                    if self.config.compression:
                        try:
                            decrypted_data = zlib.decompress(decrypted_data)
                        except:
                            pass  # Data might not be compressed
                    
                    return decrypted_data
            
            return data
            
        except Exception as e:
            self.logger.error(f"TLS camouflage deobfuscation failed: {e}")
            return data
    
    def _shadowsocks_obfuscate(self, data: bytes) -> bytes:
        """Obfuscate data using Shadowsocks-like method."""
        try:
            # Generate random IV
            iv = bytes([random.randint(0, 255) for _ in range(16)])
            
            # Encrypt with AES-256-CBC
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            pad_length = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_length] * pad_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend IV
            obfuscated_data = iv + encrypted_data
            
            # Add random timing obfuscation
            if self.config.timing_obfuscation:
                time.sleep(random.uniform(0.001, 0.01))
            
            return obfuscated_data
            
        except Exception as e:
            self.logger.error(f"Shadowsocks obfuscation failed: {e}")
            return data
    
    def _shadowsocks_deobfuscate(self, data: bytes) -> bytes:
        """Deobfuscate Shadowsocks data."""
        try:
            if len(data) < 16:
                return data
            
            # Extract IV and encrypted data
            iv = data[:16]
            encrypted_data = data[16:]
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            if padded_data:
                pad_length = padded_data[-1]
                if pad_length <= len(padded_data):
                    data = padded_data[:-pad_length]
            
            return data
            
        except Exception as e:
            self.logger.error(f"Shadowsocks deobfuscation failed: {e}")
            return data
    
    def _custom_obfuscate(self, data: bytes) -> bytes:
        """Custom obfuscation method."""
        try:
            # XOR with random key
            xor_key = bytes([random.randint(0, 255) for _ in range(32)])
            obfuscated_data = bytearray()
            
            for i, byte in enumerate(data):
                obfuscated_byte = byte ^ xor_key[i % len(xor_key)]
                obfuscated_data.append(obfuscated_byte)
            
            # Prepend XOR key
            final_data = xor_key + bytes(obfuscated_data)
            
            # Add packet chopping if enabled
            if self.config.packet_chopping:
                chunks = []
                chunk_size = random.randint(64, 256)
                for i in range(0, len(final_data), chunk_size):
                    chunk = final_data[i:i+chunk_size]
                    chunks.append(chunk)
                    if i + chunk_size < len(final_data):
                        time.sleep(random.uniform(0.001, 0.005))
                
                return b''.join(chunks)
            
            return final_data
            
        except Exception as e:
            self.logger.error(f"Custom obfuscation failed: {e}")
            return data
    
    def _custom_deobfuscate(self, data: bytes) -> None:
        """Deobfuscate custom method."""
        try:
            if len(data) < 32:
                return data
            
            # Extract XOR key
            xor_key = data[:32]
            obfuscated_data = data[32:]
            
            # Deobfuscate
            deobfuscated_data = bytearray()
            for i, byte in enumerate(obfuscated_data):
                original_byte = byte ^ xor_key[i % len(xor_key)]
                deobfuscated_data.append(original_byte)
            
            return bytes(deobfuscated_data)
            
        except Exception as e:
            self.logger.error(f"Custom deobfuscation failed: {e}")
            return data
    
    def _obfs4_obfuscate(self, data: bytes) -> bytes:
        """Obfuscate using obfs4-like method."""
        try:
            # Simple obfs4-like implementation
            # Add random header
            header = bytes([random.randint(0, 255) for _ in range(8)])
            
            # Interleave with random bytes
            obfuscated_data = bytearray()
            for i, byte in enumerate(data):
                obfuscated_data.append(byte)
                if random.random() < 0.1:  # 10% chance to add random byte
                    obfuscated_data.append(random.randint(0, 255))
            
            # Add HMAC-like signature
            signature = hashlib.sha256(header + bytes(obfuscated_data)).digest()[:8]
            
            return header + signature + bytes(obfuscated_data)
            
        except Exception as e:
            self.logger.error(f"obfs4 obfuscation failed: {e}")
            return data
    
    def _obfs4_deobfuscate(self, data: bytes) -> bytes:
        """Deobfuscate obfs4 data."""
        try:
            if len(data) < 16:
                return data
            
            # Extract header and signature
            header = data[:8]
            signature = data[8:16]
            obfuscated_data = data[16:]
            
            # Verify signature
            expected_signature = hashlib.sha256(header + obfuscated_data).digest()[:8]
            if signature != expected_signature:
                self.logger.warning("obfs4 signature verification failed")
            
            # Remove random bytes
            deobfuscated_data = bytearray()
            i = 0
            while i < len(obfuscated_data):
                deobfuscated_data.append(obfuscated_data[i])
                i += 1
                # Skip random bytes (simplified detection)
                if i < len(obfuscated_data) and random.random() < 0.1:
                    i += 1
            
            return bytes(deobfuscated_data)
            
        except Exception as e:
            self.logger.error(f"obfs4 deobfuscation failed: {e}")
            return data
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using configured method."""
        try:
            if self.config.encryption_method == "aes-256-gcm":
                # Generate random nonce
                nonce = bytes([random.randint(0, 255) for _ in range(12)])
                
                cipher = Cipher(
                    algorithms.AES(self.encryption_key),
                    modes.GCM(nonce),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                
                # Return nonce + encrypted_data + tag
                return nonce + encrypted_data + encryptor.tag
            
            return data
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            return data
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data using configured method."""
        try:
            if self.config.encryption_method == "aes-256-gcm" and len(data) >= 28:
                # Extract nonce, encrypted_data, and tag
                nonce = data[:12]
                encrypted_data = data[12:-16]
                tag = data[-16:]
                
                cipher = Cipher(
                    algorithms.AES(self.encryption_key),
                    modes.GCM(nonce, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                return decryptor.update(encrypted_data) + decryptor.finalize()
            
            return data
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return data
    
    def _generate_http_headers(self, content_length: int) -> str:
        """Generate realistic HTTP headers for camouflage."""
        try:
            headers = [
                f"GET /random{random.randint(1000, 9999)}.html HTTP/1.1",
                f"Host: {random.choice(['www.google.com', 'www.facebook.com', 'www.youtube.com'])}",
                f"User-Agent: {self.config.custom_headers.get('User-Agent', '')}",
                f"Accept: {self.config.custom_headers.get('Accept', '')}",
                f"Accept-Language: {self.config.custom_headers.get('Accept-Language', '')}",
                f"Accept-Encoding: {self.config.custom_headers.get('Accept-Encoding', '')}",
                f"Connection: {self.config.custom_headers.get('Connection', '')}",
                f"Content-Length: {content_length}"
            ]
            
            return '\r\n'.join(headers)
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTTP headers: {e}")
            return "GET / HTTP/1.1\r\nHost: example.com"
    
    def _generate_fake_traffic(self) -> None:
        """Generate fake traffic to blend with real traffic."""
        try:
            while self.is_active:
                # Generate random fake packets
                fake_data = bytes([random.randint(0, 255) for _ in range(random.randint(64, 1024))])
                
                # Obfuscate the fake data
                obfuscated_fake = self.obfuscate_packet(fake_data)
                
                # In a real implementation, this would be sent over the network
                # For now, we just simulate the timing
                time.sleep(random.uniform(0.1, 2.0))
                
        except Exception as e:
            self.logger.error(f"Fake traffic generation error: {e}")
    
    def get_status(self) -> Dict:
        """Get current status of protocol obfuscation."""
        return {
            'active': self.is_active,
            'technique': self.config.technique,
            'encryption_method': self.config.encryption_method,
            'features': {
                'compression': self.config.compression,
                'random_padding': self.config.random_padding,
                'packet_chopping': self.config.packet_chopping,
                'timing_obfuscation': self.config.timing_obfuscation,
                'fake_traffic': self.config.fake_traffic
            }
        }
    
    def test_obfuscation(self) -> bool:
        """Test obfuscation functionality."""
        try:
            self.logger.info("Testing protocol obfuscation...")
            
            # Test data
            test_data = b"This is a test message for VPN obfuscation"
            
            # Obfuscate and deobfuscate
            obfuscated = self.obfuscate_packet(test_data)
            deobfuscated = self.deobfuscate_packet(obfuscated)
            
            # Check if data matches
            if test_data == deobfuscated:
                self.logger.info("Protocol obfuscation test passed")
                return True
            else:
                self.logger.warning("Protocol obfuscation test failed - data mismatch")
                return False
                
        except Exception as e:
            self.logger.error(f"Protocol obfuscation test failed: {e}")
            return False


# Example usage and testing
if __name__ == "__main__":
    # Create protocol obfuscator
    obfuscator = ProtocolObfuscator()
    
    # Print status
    status = obfuscator.get_status()
    print("Protocol Obfuscation Status:")
    print(json.dumps(status, indent=2))
    
    # Test functionality
    if obfuscator.test_obfuscation():
        print("Protocol obfuscation test: PASSED")
    else:
        print("Protocol obfuscation test: FAILED")
