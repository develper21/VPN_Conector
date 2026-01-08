"""
Integration module for OpenVPN protocol with existing VPN client.
"""
import socket
import threading
import time
from typing import Optional, Dict, Any, Tuple

from protocols.openvpn import OpenVPNProtocol, OpenVPNPacketType, OpenVPNPacket
from performance.packet_processor import FastPacketProcessor, MemoryPool
from utils.logger import LoggableMixin


class OpenVPNClient(LoggableMixin):
    """OpenVPN client implementation with performance optimizations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.protocol = OpenVPNProtocol(config.get('openvpn', {}))
        self.socket = None
        self.ssl_socket = None
        self.is_connected = False
        self.session_keys = {}
        
        # Performance optimizations
        self.use_cython = config.get('performance', {}).get('use_cython', True)
        if self.use_cython:
            self.fast_processor = FastPacketProcessor(
                config.get('openvpn', {}).get('cipher', 'AES-256-GCM'),
                b'test_key_123456789012345678901234'  # Will be replaced with actual key
            )
            self.memory_pool = MemoryPool(
                config.get('performance', {}).get('packet_buffer_size', 1500),
                config.get('performance', {}).get('memory_pool_size', 1000)
            )
        
        # Connection state
        self.packet_id = 0
        self.received_packets = {}
        
    def connect(self, server_host: str, server_port: int) -> bool:
        """Connect to OpenVPN server."""
        try:
            self.logger.info(f"Connecting to OpenVPN server {server_host}:{server_port}")
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(30)
            
            # Perform hard reset to initiate connection
            if self._perform_hard_reset(server_host, server_port):
                # Perform TLS handshake
                if self._perform_tls_handshake():
                    self.is_connected = True
                    self.logger.info("OpenVPN connection established successfully")
                    return True
            
            self.logger.error("Failed to establish OpenVPN connection")
            return False
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False
    
    def _perform_hard_reset(self, server_host: str, server_port: int) -> bool:
        """Perform OpenVPN hard reset to initiate connection."""
        try:
            # Create hard reset packet
            reset_packet = self.protocol.create_packet(
                OpenVPNPacketType.P_CONTROL_HARD_RESET_CLIENT_V1
            )
            
            # Send packet
            packet_data = reset_packet.to_bytes()
            self.socket.sendto(packet_data, (server_host, server_port))
            
            # Wait for response
            response_data, addr = self.socket.recvfrom(2048)
            response_packet = self.protocol.parse_packet(response_data)
            
            if response_packet and response_packet.header.opcode == OpenVPNPacketType.P_CONTROL_HARD_RESET_SERVER_V1.value:
                self.logger.info("Hard reset completed successfully")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Hard reset failed: {e}")
            return False
    
    def _perform_tls_handshake(self) -> bool:
        """Perform TLS handshake with the server."""
        try:
            # Create SSL socket
            self.ssl_socket = self.protocol.ssl_handshake.create_client_ssl_socket(self.socket)
            
            # Perform handshake
            if self.protocol.ssl_handshake.perform_handshake(self.ssl_socket):
                # Generate session keys
                self._generate_session_keys()
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"TLS handshake failed: {e}")
            return False
    
    def _generate_session_keys(self):
        """Generate session keys after TLS handshake."""
        # Simplified key generation (real implementation would use TLS master secret)
        pre_master_secret = os.urandom(48)
        client_random = os.urandom(32)
        server_random = os.urandom(32)
        
        self.session_keys = self.protocol.generate_session_keys(
            pre_master_secret, client_random, server_random
        )
        
        self.logger.info("Session keys generated successfully")
    
    def send_data(self, data: bytes) -> bool:
        """Send data through OpenVPN tunnel."""
        if not self.is_connected:
            return False
        
        try:
            self.packet_id += 1
            
            # Create data packet
            data_packet = self.protocol.create_packet(
                OpenVPNPacketType.P_DATA_V2,
                data,
                packet_id=self.packet_id
            )
            
            # Encrypt packet
            if self.use_cython:
                # Use Cython for fast encryption
                encrypted_data = self.fast_processor.encrypt_fast(data_packet.to_bytes())
            else:
                # Use standard encryption
                session_key = self.session_keys.get('client_write_key')
                iv = self.session_keys.get('client_write_iv')
                encrypted_data, _, _ = self.protocol.encrypt_packet(data_packet, session_key)
            
            # Send packet
            self.socket.send(encrypted_data)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")
            return False
    
    def receive_data(self) -> Optional[bytes]:
        """Receive data from OpenVPN tunnel."""
        if not self.is_connected:
            return None
        
        try:
            # Receive encrypted packet
            encrypted_data = self.socket.recv(2048)
            
            # Decrypt packet
            if self.use_cython:
                # Use Cython for fast decryption
                decrypted_data = self.fast_processor.decrypt_fast(encrypted_data)
            else:
                # Use standard decryption
                session_key = self.session_keys.get('server_write_key')
                iv = self.session_keys.get('server_write_iv')
                packet = self.protocol.decrypt_packet(encrypted_data, session_key, iv)
                if not packet:
                    return None
                decrypted_data = packet.payload
            
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}")
            return None
    
    def disconnect(self):
        """Disconnect from OpenVPN server."""
        try:
            if self.is_connected:
                # Send disconnect packet
                disconnect_packet = self.protocol.create_packet(
                    OpenVPNPacketType.P_CONTROL_V1,
                    b'disconnect'
                )
                
                if self.socket:
                    self.socket.send(disconnect_packet.to_bytes())
            
            self.is_connected = False
            
            if self.ssl_socket:
                self.ssl_socket.close()
            if self.socket:
                self.socket.close()
                
            self.logger.info("OpenVPN connection closed")
            
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")


class OpenVPNServer(LoggableMixin):
    """OpenVPN server implementation."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.protocol = OpenVPNProtocol(config.get('openvpn', {}))
        self.socket = None
        self.clients = {}
        self.is_running = False
        
        # Performance optimizations
        self.use_cython = config.get('performance', {}).get('use_cython', True)
        if self.use_cython:
            self.fast_processor = FastPacketProcessor(
                config.get('openvpn', {}).get('cipher', 'AES-256-GCM'),
                b'test_key_123456789012345678901234'
            )
            self.memory_pool = MemoryPool(
                config.get('performance', {}).get('packet_buffer_size', 1500),
                config.get('performance', {}).get('memory_pool_size', 1000)
            )
    
    def start(self, host: str = "0.0.0.0", port: int = 1194):
        """Start OpenVPN server."""
        try:
            self.logger.info(f"Starting OpenVPN server on {host}:{port}")
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((host, port))
            self.is_running = True
            
            # Start server loop
            self._server_loop()
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            self.is_running = False
    
    def _server_loop(self):
        """Main server loop."""
        while self.is_running:
            try:
                # Receive packet
                data, addr = self.socket.recvfrom(2048)
                
                # Parse packet
                packet = self.protocol.parse_packet(data)
                if not packet:
                    continue
                
                # Handle packet based on type
                self._handle_packet(packet, addr)
                
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Server loop error: {e}")
    
    def _handle_packet(self, packet: OpenVPNPacket, addr: Tuple[str, int]):
        """Handle incoming packet."""
        try:
            packet_type = OpenVPNPacketType(packet.header.opcode)
            
            if packet_type == OpenVPNPacketType.P_CONTROL_HARD_RESET_CLIENT_V1:
                self._handle_hard_reset(packet, addr)
            elif packet_type == OpenVPNPacketType.P_DATA_V2:
                self._handle_data_packet(packet, addr)
            elif packet_type == OpenVPNPacketType.P_CONTROL_V1:
                self._handle_control_packet(packet, addr)
                
        except Exception as e:
            self.logger.error(f"Packet handling error: {e}")
    
    def _handle_hard_reset(self, packet: OpenVPNPacket, addr: Tuple[str, int]):
        """Handle client hard reset."""
        try:
            # Send hard reset response
            response_packet = self.protocol.create_packet(
                OpenVPNPacketType.P_CONTROL_HARD_RESET_SERVER_V1
            )
            
            self.socket.sendto(response_packet.to_bytes(), addr)
            self.logger.info(f"Sent hard reset response to {addr}")
            
        except Exception as e:
            self.logger.error(f"Hard reset handling error: {e}")
    
    def _handle_data_packet(self, packet: OpenVPNPacket, addr: Tuple[str, int]):
        """Handle data packet."""
        try:
            # Process data packet
            self.logger.debug(f"Received data packet from {addr}: {len(packet.payload)} bytes")
            
            # Here you would typically route the data to the appropriate destination
            
        except Exception as e:
            self.logger.error(f"Data packet handling error: {e}")
    
    def _handle_control_packet(self, packet: OpenVPNPacket, addr: Tuple[str, int]):
        """Handle control packet."""
        try:
            self.logger.debug(f"Received control packet from {addr}")
            
        except Exception as e:
            self.logger.error(f"Control packet handling error: {e}")
    
    def stop(self):
        """Stop OpenVPN server."""
        self.is_running = False
        if self.socket:
            self.socket.close()
        self.logger.info("OpenVPN server stopped")
