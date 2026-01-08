"""
WireGuard UDP Protocol Handler

This module provides UDP-only protocol handling for WireGuard,
including packet routing, NAT traversal, and connection management.
"""
import socket
import select
import time
import threading
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass
from enum import Enum, auto

from protocols.wireguard import (
    WireGuardProtocol, WireGuardHandshakeInitiation, 
    WireGuardHandshakeResponse, WireGuardDataPacket,
    WireGuardMessageType
)
from utils.logger import LoggableMixin


class WireGuardConnectionState(Enum):
    """WireGuard connection states."""
    DISCONNECTED = auto()
    HANDSHAKE_INITIATED = auto()
    HANDSHAKE_COMPLETED = auto()
    CONNECTED = auto()
    REKEYING = auto()


@dataclass
class WireGuardPeer:
    """WireGuard peer information."""
    peer_id: str
    public_key: bytes
    endpoint: Optional[Tuple[str, int]]
    allowed_ips: List[str]
    state: WireGuardConnectionState = WireGuardConnectionState.DISCONNECTED
    last_seen: float = 0
    persistent_keepalive: int = 25
    rx_bytes: int = 0
    tx_bytes: int = 0


class WireGuardUDPHandler(LoggableMixin):
    """WireGuard UDP protocol handler."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.protocol = WireGuardProtocol(config)
        self.socket = None
        self.peers: Dict[str, WireGuardPeer] = {}
        self.endpoints: Dict[Tuple[str, int], str] = {}  # endpoint -> peer_id mapping
        self.is_running = False
        self.receive_thread = None
        self.keepalive_thread = None
        
        # Callbacks
        self.data_callback: Optional[Callable[[str, bytes], None]] = None
        self.connection_callback: Optional[Callable[[str, WireGuardConnectionState], None]] = None
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'handshakes_completed': 0,
            'active_sessions': 0
        }
    
    def start_server(self, host: str = "0.0.0.0", port: int = 51820):
        """Start WireGuard UDP server."""
        try:
            self.logger.info(f"Starting WireGuard UDP server on {host}:{port}")
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((host, port))
            self.socket.settimeout(1.0)  # Non-blocking with timeout
            
            self.is_running = True
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            # Start keepalive thread
            self.keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            self.keepalive_thread.start()
            
            self.logger.info("WireGuard UDP server started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start WireGuard server: {e}")
            self.is_running = False
            raise
    
    def stop(self):
        """Stop WireGuard UDP server."""
        self.is_running = False
        
        if self.socket:
            self.socket.close()
        
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=2)
        
        if self.keepalive_thread and self.keepalive_thread.is_alive():
            self.keepalive_thread.join(timeout=2)
        
        self.logger.info("WireGuard UDP server stopped")
    
    def add_peer(self, peer_id: str, public_key: bytes, 
                 endpoint: Optional[Tuple[str, int]] = None,
                 allowed_ips: List[str] = None,
                 persistent_keepalive: int = 25):
        """Add a WireGuard peer."""
        peer = WireGuardPeer(
            peer_id=peer_id,
            public_key=public_key,
            endpoint=endpoint,
            allowed_ips=allowed_ips or [],
            persistent_keepalive=persistent_keepalive
        )
        
        self.peers[peer_id] = peer
        
        # Add to protocol
        self.protocol.add_peer(peer_id, public_key, endpoint)
        
        # Map endpoint to peer if provided
        if endpoint:
            self.endpoints[endpoint] = peer_id
        
        self.logger.info(f"Added WireGuard peer: {peer_id}")
    
    def initiate_handshake(self, peer_id: str) -> bool:
        """Initiate handshake with peer."""
        peer = self.peers.get(peer_id)
        if not peer or not peer.endpoint:
            self.logger.error(f"Cannot initiate handshake with {peer_id}: no endpoint")
            return False
        
        try:
            # Create handshake initiation
            handshake_init = self.protocol.create_handshake_initiation(peer_id)
            packet_data = handshake_init.to_bytes()
            
            # Send packet
            self.socket.sendto(packet_data, peer.endpoint)
            
            # Update peer state
            peer.state = WireGuardConnectionState.HANDSHAKE_INITIATED
            peer.last_seen = time.time()
            
            # Update statistics
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(packet_data)
            
            self.logger.info(f"Handshake initiated with {peer_id}")
            
            # Notify callback
            if self.connection_callback:
                self.connection_callback(peer_id, peer.state)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Handshake initiation failed for {peer_id}: {e}")
            return False
    
    def send_data(self, peer_id: str, data: bytes) -> bool:
        """Send data to peer."""
        peer = self.peers.get(peer_id)
        if not peer or peer.state != WireGuardConnectionState.CONNECTED:
            self.logger.error(f"Cannot send data to {peer_id}: not connected")
            return False
        
        try:
            # Create data packet
            data_packet = self.protocol.create_data_packet(peer_id, data)
            if not data_packet:
                return False
            
            packet_data = data_packet.to_bytes()
            
            # Send packet
            self.socket.sendto(packet_data, peer.endpoint)
            
            # Update peer statistics
            peer.tx_bytes += len(data)
            peer.last_seen = time.time()
            
            # Update global statistics
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(packet_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send data to {peer_id}: {e}")
            return False
    
    def _receive_loop(self):
        """Main receive loop for incoming packets."""
        while self.is_running:
            try:
                # Wait for data with timeout
                ready = select.select([self.socket], [], [], 1.0)
                if not ready[0]:
                    continue
                
                # Receive packet
                packet_data, endpoint = self.socket.recvfrom(2048)
                
                # Process packet
                self._process_packet(packet_data, endpoint)
                
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Receive loop error: {e}")
                continue
    
    def _process_packet(self, packet_data: bytes, endpoint: Tuple[str, int]):
        """Process incoming packet."""
        try:
            # Update statistics
            self.stats['packets_received'] += 1
            self.stats['bytes_received'] += len(packet_data)
            
            # Parse message type
            if len(packet_data) < 1:
                return
            
            message_type = packet_data[0]
            
            # Find peer by endpoint or public key
            peer_id = self.endpoints.get(endpoint)
            
            if message_type == WireGuardMessageType.HANDSHAKE_INITIATION.value:
                self._process_handshake_initiation(packet_data, endpoint)
            elif message_type == WireGuardMessageType.HANDSHAKE_RESPONSE.value:
                self._process_handshake_response(packet_data, endpoint)
            elif message_type == WireGuardMessageType.DATA.value:
                self._process_data_packet(packet_data, endpoint)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            self.logger.error(f"Packet processing error: {e}")
    
    def _process_handshake_initiation(self, packet_data: bytes, endpoint: Tuple[str, int]):
        """Process handshake initiation packet."""
        try:
            handshake_init = WireGuardHandshakeInitiation.from_bytes(packet_data)
            
            # Create response
            response = self.protocol.process_handshake_initiation(handshake_init, endpoint)
            if not response:
                return
            
            # Send response
            response_data = response.to_bytes()
            self.socket.sendto(response_data, endpoint)
            
            # Update statistics
            self.stats['packets_sent'] += 1
            self.stats['bytes_sent'] += len(response_data)
            
            # Find peer and update state
            peer_id = None
            for pid, peer in self.peers.items():
                if peer.public_key == handshake_init.static_public_key:
                    peer_id = pid
                    peer.state = WireGuardConnectionState.CONNECTED
                    peer.last_seen = time.time()
                    peer.endpoint = endpoint
                    self.endpoints[endpoint] = pid
                    break
            
            if peer_id:
                self.stats['handshakes_completed'] += 1
                self.stats['active_sessions'] += 1
                
                self.logger.info(f"Handshake completed with {peer_id}")
                
                # Notify callback
                if self.connection_callback:
                    self.connection_callback(peer_id, peer.state)
            
        except Exception as e:
            self.logger.error(f"Handshake initiation processing failed: {e}")
    
    def _process_handshake_response(self, packet_data: bytes, endpoint: Tuple[str, int]):
        """Process handshake response packet."""
        try:
            handshake_response = WireGuardHandshakeResponse.from_bytes(packet_data)
            
            # Find peer by receiver index
            peer_id = None
            for pid, session in self.protocol.sessions.items():
                if session.get('sender_index') == handshake_response.receiver_index:
                    peer_id = pid
                    break
            
            if not peer_id:
                self.logger.warning("Handshake response from unknown session")
                return
            
            # Update peer state
            peer = self.peers.get(peer_id)
            if peer:
                peer.state = WireGuardConnectionState.CONNECTED
                peer.last_seen = time.time()
                peer.endpoint = endpoint
                
                self.stats['handshakes_completed'] += 1
                self.stats['active_sessions'] += 1
                
                self.logger.info(f"Handshake completed with {peer_id}")
                
                # Notify callback
                if self.connection_callback:
                    self.connection_callback(peer_id, peer.state)
            
        except Exception as e:
            self.logger.error(f"Handshake response processing failed: {e}")
    
    def _process_data_packet(self, packet_data: bytes, endpoint: Tuple[str, int]):
        """Process data packet."""
        try:
            data_packet = WireGuardDataPacket.from_bytes(packet_data)
            
            # Decrypt and process data
            result = self.protocol.process_data_packet(data_packet)
            if result:
                peer_id, plaintext = result
                
                # Update peer
                peer = self.peers.get(peer_id)
                if peer:
                    peer.rx_bytes += len(plaintext)
                    peer.last_seen = time.time()
                
                # Forward data to callback
                if self.data_callback:
                    self.data_callback(peer_id, plaintext)
            
        except Exception as e:
            self.logger.error(f"Data packet processing failed: {e}")
    
    def _keepalive_loop(self):
        """Send periodic keepalive packets."""
        while self.is_running:
            try:
                current_time = time.time()
                
                for peer_id, peer in self.peers.items():
                    if (peer.state == WireGuardConnectionState.CONNECTED and 
                        peer.persistent_keepalive > 0):
                        
                        time_since_last = current_time - peer.last_seen
                        if time_since_last >= peer.persistent_keepalive:
                            # Send empty data packet as keepalive
                            self.send_data(peer_id, b'')
                
                # Sleep for a short interval
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Keepalive loop error: {e}")
                time.sleep(5)
    
    def set_data_callback(self, callback: Callable[[str, bytes], None]):
        """Set callback for received data."""
        self.data_callback = callback
    
    def set_connection_callback(self, callback: Callable[[str, WireGuardConnectionState], None]):
        """Set callback for connection state changes."""
        self.connection_callback = callback
    
    def get_peer_status(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Get peer status information."""
        peer = self.peers.get(peer_id)
        if not peer:
            return None
        
        return {
            'peer_id': peer.peer_id,
            'state': peer.state.name,
            'endpoint': peer.endpoint,
            'last_seen': peer.last_seen,
            'rx_bytes': peer.rx_bytes,
            'tx_bytes': peer.tx_bytes,
            'allowed_ips': peer.allowed_ips
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get handler statistics."""
        return {
            **self.stats,
            'total_peers': len(self.peers),
            'connected_peers': sum(1 for p in self.peers.values() 
                                  if p.state == WireGuardConnectionState.CONNECTED)
        }
