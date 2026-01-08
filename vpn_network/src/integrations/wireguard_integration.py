"""
WireGuard integration module for VPN Security Project.
Provides WireGuard client and server implementations with UDP protocol support.
"""
import os
import time
import threading
from typing import Optional, Dict, Any, Tuple, List, Callable

from protocols.wireguard import WireGuardProtocol, WireGuardConnectionState
from protocols.wireguard_udp import WireGuardUDPHandler
from utils.logger import LoggableMixin


class WireGuardClient(LoggableMixin):
    """WireGuard client implementation with UDP protocol support."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.udp_handler = WireGuardUDPHandler(config)
        self.is_connected = False
        self.server_endpoint = None
        self.server_public_key = None
        
        # Set callbacks
        self.udp_handler.set_data_callback(self._on_data_received)
        self.udp_handler.set_connection_callback(self._on_connection_state_change)
        
        # Client state
        self.connection_attempts = 0
        self.max_connection_attempts = 5
        self.reconnect_interval = 10
        
        # Statistics
        self.stats = {
            'connection_time': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'connection_attempts': 0
        }
    
    def connect(self, server_host: str, server_port: int, server_public_key: bytes) -> bool:
        """Connect to WireGuard server."""
        try:
            self.logger.info(f"Connecting to WireGuard server {server_host}:{server_port}")
            
            self.server_endpoint = (server_host, server_port)
            self.server_public_key = server_public_key
            
            # Add server as peer
            self.udp_handler.add_peer(
                peer_id="server",
                public_key=server_public_key,
                endpoint=self.server_endpoint,
                allowed_ips=["0.0.0.0/0"],
                persistent_keepalive=25
            )
            
            # Start UDP client (bind to random port)
            self.udp_handler.start_server("0.0.0.0", 0)  # Port 0 for random assignment
            
            # Initiate handshake
            if self.udp_handler.initiate_handshake("server"):
                self.connection_attempts += 1
                self.stats['connection_attempts'] = self.connection_attempts
                
                # Wait for connection
                return self._wait_for_connection()
            
            return False
            
        except Exception as e:
            self.logger.error(f"WireGuard connection failed: {e}")
            return False
    
    def _wait_for_connection(self, timeout: int = 30) -> bool:
        """Wait for connection to be established."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.is_connected:
                self.stats['connection_time'] = time.time() - start_time
                self.logger.info(f"WireGuard connected in {self.stats['connection_time']:.2f}s")
                return True
            
            time.sleep(0.1)
        
        self.logger.error("WireGuard connection timeout")
        return False
    
    def _on_data_received(self, peer_id: str, data: bytes):
        """Handle received data from server."""
        if peer_id == "server":
            self.logger.debug(f"Received {len(data)} bytes from server")
            self.stats['total_bytes_received'] += len(data)
            
            # Here you would typically route the data to the TUN interface
            # or process it according to your application logic
    
    def _on_connection_state_change(self, peer_id: str, state: WireGuardConnectionState):
        """Handle connection state changes."""
        if peer_id == "server":
            old_state = self.is_connected
            self.is_connected = (state == WireGuardConnectionState.CONNECTED)
            
            if self.is_connected and not old_state:
                self.logger.info("WireGuard connection established")
            elif not self.is_connected and old_state:
                self.logger.warning("WireGuard connection lost")
                
                # Attempt reconnection
                self._attempt_reconnection()
    
    def _attempt_reconnection(self):
        """Attempt to reconnect to server."""
        if self.connection_attempts >= self.max_connection_attempts:
            self.logger.error("Max connection attempts reached")
            return
        
        self.logger.info(f"Attempting reconnection ({self.connection_attempts + 1}/{self.max_connection_attempts})")
        
        def reconnect():
            time.sleep(self.reconnect_interval)
            if self.server_endpoint and self.server_public_key:
                self.connect(
                    self.server_endpoint[0], 
                    self.server_endpoint[1], 
                    self.server_public_key
                )
        
        # Start reconnection in background thread
        threading.Thread(target=reconnect, daemon=True).start()
    
    def send_data(self, data: bytes) -> bool:
        """Send data to WireGuard server."""
        if not self.is_connected:
            self.logger.warning("Cannot send data: not connected")
            return False
        
        try:
            success = self.udp_handler.send_data("server", data)
            if success:
                self.stats['total_bytes_sent'] += len(data)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from WireGuard server."""
        try:
            self.is_connected = False
            self.udp_handler.stop()
            self.logger.info("WireGuard client disconnected")
            
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get client status."""
        peer_status = self.udp_handler.get_peer_status("server")
        handler_stats = self.udp_handler.get_statistics()
        
        return {
            'connected': self.is_connected,
            'server_endpoint': self.server_endpoint,
            'connection_attempts': self.connection_attempts,
            'peer_status': peer_status,
            'client_stats': self.stats,
            'handler_stats': handler_stats
        }


class WireGuardServer(LoggableMixin):
    """WireGuard server implementation with UDP protocol support."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.udp_handler = WireGuardUDPHandler(config)
        self.clients = {}  # client_id -> client_info
        self.is_running = False
        
        # Set callbacks
        self.udp_handler.set_data_callback(self._on_data_received)
        self.udp_handler.set_connection_callback(self._on_connection_state_change)
        
        # Server configuration
        self.allowed_clients = {}  # public_key -> client_info
        self.default_allowed_ips = ["10.0.0.0/24"]
        
        # Statistics
        self.stats = {
            'start_time': time.time(),
            'total_clients_connected': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0
        }
    
    def start(self, host: str = "0.0.0.0", port: int = 51820):
        """Start WireGuard server."""
        try:
            self.logger.info(f"Starting WireGuard server on {host}:{port}")
            
            # Start UDP server
            self.udp_handler.start_server(host, port)
            self.is_running = True
            
            self.logger.info("WireGuard server started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start WireGuard server: {e}")
            self.is_running = False
            raise
    
    def stop(self):
        """Stop WireGuard server."""
        try:
            self.is_running = False
            self.udp_handler.stop()
            self.logger.info("WireGuard server stopped")
            
        except Exception as e:
            self.logger.error(f"Error during server stop: {e}")
    
    def add_client(self, client_id: str, public_key: bytes, 
                   allowed_ips: List[str] = None,
                   persistent_keepalive: int = 25):
        """Add authorized client."""
        client_info = {
            'client_id': client_id,
            'public_key': public_key,
            'allowed_ips': allowed_ips or self.default_allowed_ips,
            'persistent_keepalive': persistent_keepalive,
            'added_time': time.time()
        }
        
        self.allowed_clients[public_key.hex()] = client_info
        
        self.logger.info(f"Added authorized client: {client_id}")
    
    def _on_data_received(self, peer_id: str, data: bytes):
        """Handle received data from client."""
        if peer_id in self.clients:
            self.logger.debug(f"Received {len(data)} bytes from {peer_id}")
            self.stats['total_bytes_received'] += len(data)
            
            # Here you would typically route the data to the internet
            # or forward it to other clients based on routing rules
            
            # Echo back for testing
            self.udp_handler.send_data(peer_id, b"Echo: " + data)
    
    def _on_connection_state_change(self, peer_id: str, state: WireGuardConnectionState):
        """Handle client connection state changes."""
        if state == WireGuardConnectionState.CONNECTED:
            if peer_id not in self.clients:
                self.clients[peer_id] = {
                    'connect_time': time.time(),
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
                self.stats['total_clients_connected'] += 1
                
            self.logger.info(f"Client connected: {peer_id}")
            
        elif state == WireGuardConnectionState.DISCONNECTED:
            if peer_id in self.clients:
                del self.clients[peer_id]
            
            self.logger.info(f"Client disconnected: {peer_id}")
    
    def send_data(self, client_id: str, data: bytes) -> bool:
        """Send data to specific client."""
        if client_id not in self.clients:
            self.logger.warning(f"Client not connected: {client_id}")
            return False
        
        try:
            success = self.udp_handler.send_data(client_id, data)
            if success:
                self.stats['total_bytes_sent'] += len(data)
                if client_id in self.clients:
                    self.clients[client_id]['bytes_sent'] += len(data)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send data to {client_id}: {e}")
            return False
    
    def broadcast_data(self, data: bytes) -> int:
        """Broadcast data to all connected clients."""
        success_count = 0
        
        for client_id in self.clients:
            if self.send_data(client_id, data):
                success_count += 1
        
        self.logger.info(f"Broadcasted data to {success_count}/{len(self.clients)} clients")
        return success_count
    
    def get_status(self) -> Dict[str, Any]:
        """Get server status."""
        handler_stats = self.udp_handler.get_statistics()
        uptime = time.time() - self.stats['start_time']
        
        return {
            'running': self.is_running,
            'uptime': uptime,
            'connected_clients': len(self.clients),
            'authorized_clients': len(self.allowed_clients),
            'server_stats': self.stats,
            'handler_stats': handler_stats,
            'clients': {
                client_id: {
                    'connect_time': client_info['connect_time'],
                    'bytes_sent': client_info['bytes_sent'],
                    'bytes_received': client_info['bytes_received'],
                    'status': self.udp_handler.get_peer_status(client_id)
                }
                for client_id, client_info in self.clients.items()
            }
        }


class WireGuardManager(LoggableMixin):
    """High-level WireGuard manager for both client and server operations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None
        self.server = None
        self.mode = None
    
    def start_client(self, server_host: str, server_port: int, server_public_key: bytes) -> bool:
        """Start WireGuard client."""
        try:
            self.mode = "client"
            self.client = WireGuardClient(self.config)
            
            success = self.client.connect(server_host, server_port, server_public_key)
            
            if success:
                self.logger.info("WireGuard client started successfully")
            else:
                self.logger.error("Failed to start WireGuard client")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Client start error: {e}")
            return False
    
    def start_server(self, host: str = "0.0.0.0", port: int = 51820) -> bool:
        """Start WireGuard server."""
        try:
            self.mode = "server"
            self.server = WireGuardServer(self.config)
            
            self.server.start(host, port)
            self.logger.info("WireGuard server started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Server start error: {e}")
            return False
    
    def stop(self):
        """Stop WireGuard client or server."""
        if self.client:
            self.client.disconnect()
            self.client = None
        
        if self.server:
            self.server.stop()
            self.server = None
        
        self.mode = None
        self.logger.info("WireGuard manager stopped")
    
    def send_data(self, data: bytes, target: str = None) -> bool:
        """Send data (client mode only)."""
        if self.client:
            return self.client.send_data(data)
        elif self.server and target:
            return self.server.send_data(target, data)
        else:
            self.logger.warning("Cannot send data: not connected or no target specified")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status."""
        status = {
            'mode': self.mode,
            'running': self.client is not None or self.server is not None
        }
        
        if self.client:
            status['client'] = self.client.get_status()
        elif self.server:
            status['server'] = self.server.get_status()
        
        return status
