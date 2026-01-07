"""
VPN Client Implementation

This module provides the main VPN client class that handles the VPN connection,
packet processing, and interaction with the VPN server.
"""
import os
import sys
import time
import json
import socket
import select
import signal
import logging
import threading
import ipaddress
import subprocess
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

from utils.logger import LoggableMixin
from utils.validator import validate_ip_address, validate_port
from network.interface import TunInterface, UDPSocket, NetworkInterface
from network.packet_handler import (
    Packet, PacketType, PacketProcessor, DataPacket,
    KeepalivePacket, ErrorPacket, PacketHeader, PacketProcessor
)
from .connection_manager import ConnectionManager
from .authentication import ClientAuthenticator

class VPNClientError(Exception):
    """Base exception for VPN client errors."""
    pass

class ConnectionError(VPNClientError):
    """Raised when there's an error connecting to the VPN server."""
    pass

class AuthenticationError(VPNClientError):
    """Raised when authentication with the server fails."""
    pass

class ConfigurationError(VPNClientError):
    """Raised when there's an error in the client configuration."""
    pass

@dataclass
class ClientConfig:
    """Configuration for the VPN client."""
    server_host: str
    server_port: int
    username: str
    password: str
    protocol: str = "udp"
    interface_name: str = "tun0"
    mtu: int = 1500
    reconnect: bool = True
    reconnect_delay: int = 5
    keepalive_interval: int = 30
    max_reconnect_attempts: int = 5
    cipher: str = "AES-256-GCM"
    auth: str = "SHA512"
    tls_version: str = "TLSv1.3"
    verify_cert: bool = True
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    routes: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    
    def validate(self) -> None:
        """Validate the configuration."""
        if not self.server_host:
            raise ConfigurationError("Server host is required")
        
        if not (1 <= self.server_port <= 65535):
            raise ConfigurationError("Invalid server port")
        
        if not self.username:
            raise ConfigurationError("Username is required")
        
        if not self.password:
            raise ConfigurationError("Password is required")
        
        if self.protocol.lower() not in ["udp", "tcp"]:
            raise ConfigurationError("Protocol must be either 'udp' or 'tcp'")
        
        if self.mtu < 576 or self.mtu > 65535:
            raise ConfigurationError("MTU must be between 576 and 65535")
        
        if self.reconnect_delay < 1:
            raise ConfigurationError("Reconnect delay must be at least 1 second")
        
        if self.keepalive_interval < 5:
            raise ConfigurationError("Keepalive interval must be at least 5 seconds")
        
        if self.max_reconnect_attempts < 0:
            raise ConfigurationError("Max reconnect attempts cannot be negative")
        
        # Validate IP addresses in routes
        for route in self.routes:
            try:
                ipaddress.ip_network(route, strict=False)
            except ValueError as e:
                raise ConfigurationError(f"Invalid route: {route}") from e
        
        # Validate DNS servers
        for dns in self.dns_servers:
            try:
                ipaddress.ip_address(dns)
            except ValueError as e:
                raise ConfigurationError(f"Invalid DNS server: {dns}") from e

class VPNClient(LoggableMixin):
    """
    VPN Client implementation that handles the VPN connection to the server.
    """
    
    def __init__(self, config: ClientConfig):
        """
        Initialize the VPN client with the given configuration.
        
        Args:
            config: The client configuration.
        """
        super().__init__()
        
        # Configuration
        self.config = config
        
        # State
        self._running = False
        self._connected = False
        self._reconnect_attempts = 0
        self._last_keepalive = 0
        self._last_received = 0
        self._session_id = None
        self._session_key = None
        self._packet_processor = None
        
        # Network interfaces
        self._tun_interface = None
        self._socket = None
        
        # Threads and events
        self._receive_thread = None
        self._keepalive_thread = None
        self._stop_event = threading.Event()
        self._handshake_complete = threading.Event()
        
        # Connection manager
        self._connection_manager = ConnectionManager(self.config)
        
        # Authenticator
        self._authenticator = ClientAuthenticator(self.config)
        
        # Callbacks
        self._on_connect_callbacks = []
        self._on_disconnect_callbacks = []
        self._on_error_callbacks = []
        
        self.logger.info("VPN client initialized")
    
    def add_connect_callback(self, callback: Callable[['VPNClient'], None]) -> None:
        """
        Add a callback to be called when the client connects to the server.
        
        Args:
            callback: The callback function.
        """
        self._on_connect_callbacks.append(callback)
    
    def add_disconnect_callback(self, callback: Callable[['VPNClient', Optional[Exception]]]) -> None:
        """
        Add a callback to be called when the client disconnects from the server.
        
        Args:
            callback: The callback function.
        """
        self._on_disconnect_callbacks.append(callback)
    
    def add_error_callback(self, callback: Callable[['VPNClient', Exception]]) -> None:
        """
        Add a callback to be called when an error occurs.
        
        Args:
            callback: The callback function.
        """
        self._on_error_callbacks.append(callback)
    
    def _notify_connect(self) -> None:
        """Notify all connect callbacks."""
        for callback in self._on_connect_callbacks:
            try:
                callback(self)
            except Exception as e:
                self.logger.error("Error in connect callback: %s", e, exc_info=True)
    
    def _notify_disconnect(self, error: Optional[Exception] = None) -> None:
        """Notify all disconnect callbacks."""
        for callback in self._on_disconnect_callbacks:
            try:
                callback(self, error)
            except Exception as e:
                self.logger.error("Error in disconnect callback: %s", e, exc_info=True)
    
    def _notify_error(self, error: Exception) -> None:
        """Notify all error callbacks."""
        for callback in self._on_error_callbacks:
            try:
                callback(self, error)
            except Exception as e:
                self.logger.error("Error in error callback: %s", e, exc_info=True)
    
    def connect(self) -> bool:
        """
        Connect to the VPN server.
        
        Returns:
            bool: True if the connection was successful, False otherwise.
        """
        if self._running:
            self.logger.warning("Client is already running")
            return True
        
        self._running = True
        self._stop_event.clear()
        
        try:
            # Validate configuration
            self.config.validate()
            
            # Set up network interfaces
            self._setup_network_interfaces()
            
            # Connect to the server
            self._connect_to_server()
            
            # Start the receive thread
            self._receive_thread = threading.Thread(
                target=self._receive_loop,
                name="VPNClient-Receive",
                daemon=True
            )
            self._receive_thread.start()
            
            # Start the keepalive thread
            self._keepalive_thread = threading.Thread(
                target=self._keepalive_loop,
                name="VPNClient-Keepalive",
                daemon=True
            )
            self._keepalive_thread.start()
            
            # Wait for handshake to complete
            if not self._handshake_complete.wait(timeout=30):
                raise ConnectionError("Handshake timed out")
            
            self._connected = True
            self._reconnect_attempts = 0
            
            # Notify listeners
            self._notify_connect()
            
            self.logger.info("VPN client connected successfully")
            return True
            
        except Exception as e:
            self.logger.error("Failed to connect: %s", e, exc_info=True)
            self._notify_error(e)
            self._cleanup()
            return False
    
    def disconnect(self, error: Optional[Exception] = None) -> None:
        """
        Disconnect from the VPN server.
        
        Args:
            error: Optional error that caused the disconnection.
        """
        if not self._running:
            return
        
        self.logger.info("Disconnecting from VPN server...")
        
        # Set flags to stop threads
        self._running = False
        self._connected = False
        self._stop_event.set()
        
        # Notify listeners
        self._notify_disconnect(error)
        
        # Clean up resources
        self._cleanup()
        
        self.logger.info("Disconnected from VPN server")
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        # Close network interfaces
        if self._tun_interface:
            try:
                self._tun_interface.close()
            except Exception as e:
                self.logger.error("Error closing TUN interface: %s", e)
            self._tun_interface = None
        
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                self.logger.error("Error closing socket: %s", e)
            self._socket = None
        
        # Reset state
        self._session_id = None
        self._session_key = None
        self._packet_processor = None
        
        # Wait for threads to stop
        if self._receive_thread and self._receive_thread.is_alive():
            self._receive_thread.join(timeout=5)
        
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            self._keepalive_thread.join(timeout=5)
        
        self._receive_thread = None
        self._keepalive_thread = None
        self._stop_event.clear()
        self._handshake_complete.clear()
    
    def _setup_network_interfaces(self) -> None:
        """Set up the TUN/TAP interface and socket."""
        try:
            # Create TUN interface
            self._tun_interface = TunInterface(
                name=self.config.interface_name,
                mtu=self.config.mtu,
                logger=self.logger
            )
            
            # Create UDP socket
            self._socket = UDPSocket(
                local_addr=('0.0.0.0', 0),  # Use any available port
                remote_addr=(self.config.server_host, self.config.server_port),
                logger=self.logger
            )
            
            self.logger.info("Network interfaces set up successfully")
            
        except Exception as e:
            self.logger.error("Failed to set up network interfaces: %s", e, exc_info=True)
            self._cleanup()
            raise ConnectionError(f"Failed to set up network interfaces: {e}") from e
    
    def _connect_to_server(self) -> None:
        """Establish a connection to the VPN server."""
        try:
            # Connect the socket
            self._socket.connect()
            
            # Perform authentication and key exchange
            self._authenticate()
            
            # Initialize packet processor with session key
            self._packet_processor = PacketProcessor(self._session_key)
            
            # Send handshake
            self._send_handshake()
            
        except Exception as e:
            self.logger.error("Failed to connect to server: %s", e, exc_info=True)
            self._cleanup()
            raise ConnectionError(f"Failed to connect to server: {e}") from e
    
    def _authenticate(self) -> None:
        """Authenticate with the server and establish a session."""
        try:
            # Use the authenticator to get session credentials
            result = self._authenticator.authenticate(
                self.config.server_host,
                self.config.server_port,
                self.config.username,
                self.config.password
            )
            
            if not result.success:
                raise AuthenticationError(result.error or "Authentication failed")
            
            self._session_id = result.session_id
            self._session_key = result.session_key
            
            self.logger.info("Authentication successful, session ID: %s", self._session_id)
            
        except Exception as e:
            self.logger.error("Authentication failed: %s", e, exc_info=True)
            raise AuthenticationError(f"Authentication failed: {e}") from e
    
    def _send_handshake(self) -> None:
        """Send a handshake packet to the server."""
        handshake = HandshakePacket(
            session_id=self._session_id,
            client_version="1.0",
            timestamp=time.time(),
            cipher=self.config.cipher,
            auth=self.config.auth,
            tls_version=self.config.tls_version
        )
        
        # Encrypt the handshake
        encrypted = self._packet_processor.encrypt(handshake.serialize())
        
        # Send the handshake
        self._socket.send(encrypted)
        
        self.logger.debug("Sent handshake to server")
    
    def _receive_loop(self) -> None:
        """Main receive loop for incoming packets."""
        while self._running and not self._stop_event.is_set():
            try:
                # Wait for data on either the TUN interface or the socket
                rlist, _, _ = select.select(
                    [self._tun_interface, self._socket],
                    [],
                    [],
                    1.0  # 1 second timeout
                )
                
                current_time = time.time()
                
                # Check for timeout
                if not rlist:
                    # Check for connection timeout
                    if self._connected and (current_time - self._last_received) > 60:
                        self.logger.warning("Connection timeout, no data received for 60 seconds")
                        self.disconnect(ConnectionError("Connection timeout"))
                    continue
                
                # Handle incoming data
                for sock in rlist:
                    if sock == self._tun_interface:
                        # Data from the TUN interface (to be sent to the server)
                        self._handle_tun_data()
                    elif sock == self._socket:
                        # Data from the socket (from the server)
                        self._handle_socket_data()
                
            except (OSError, select.error) as e:
                if not self._stop_event.is_set():
                    self.logger.error("Error in receive loop: %s", e, exc_info=True)
                    self.disconnect(e)
            except Exception as e:
                self.logger.error("Unexpected error in receive loop: %s", e, exc_info=True)
                self.disconnect(e)
    
    def _handle_tun_data(self) -> None:
        """Handle data received from the TUN interface."""
        try:
            # Read data from the TUN interface
            data = self._tun_interface.read()
            if not data:
                return
            
            # Create a data packet
            packet = DataPacket(data)
            
            # Encrypt the packet
            encrypted = self._packet_processor.encrypt(packet.serialize())
            
            # Send the packet to the server
            self._socket.send(encrypted)
            
            self.logger.debug("Sent %d bytes to server", len(data))
            
        except Exception as e:
            self.logger.error("Error handling TUN data: %s", e, exc_info=True)
            raise
    
    def _handle_socket_data(self) -> None:
        """Handle data received from the socket."""
        try:
            # Receive data from the socket
            data, addr = self._socket.recv()
            if not data:
                return
            
            # Update last received time
            self._last_received = time.time()
            
            # Decrypt the packet
            try:
                decrypted = self._packet_processor.decrypt(data)
                packet = Packet.deserialize(decrypted)
            except Exception as e:
                self.logger.error("Failed to decrypt/deserialize packet: %s", e)
                return
            
            # Handle the packet based on its type
            if isinstance(packet, HandshakePacket):
                self._handle_handshake(packet)
            elif isinstance(packet, DataPacket):
                self._handle_data_packet(packet)
            elif isinstance(packet, KeepalivePacket):
                self._handle_keepalive(packet)
            elif isinstance(packet, ErrorPacket):
                self._handle_error_packet(packet)
            else:
                self.logger.warning("Received unknown packet type: %s", type(packet).__name__)
            
        except Exception as e:
            self.logger.error("Error handling socket data: %s", e, exc_info=True)
            raise
    
    def _handle_handshake(self, packet: HandshakePacket) -> None:
        """Handle a handshake packet from the server."""
        if not self._handshake_complete.is_set():
            self.logger.info("Handshake completed with server")
            self._handshake_complete.set()
        
        # TODO: Process handshake response (e.g., update session parameters)
    
    def _handle_data_packet(self, packet: DataPacket) -> None:
        """Handle a data packet from the server."""
        if not self._handshake_complete.is_set():
            self.logger.warning("Received data packet before handshake completed")
            return
        
        # Write the data to the TUN interface
        try:
            self._tun_interface.write(packet.payload)
            self.logger.debug("Wrote %d bytes to TUN interface", len(packet.payload))
        except Exception as e:
            self.logger.error("Failed to write to TUN interface: %s", e, exc_info=True)
    
    def _handle_keepalive(self, packet: KeepalivePacket) -> None:
        """Handle a keepalive packet from the server."""
        self.logger.debug("Received keepalive from server")
        self._last_keepalive = time.time()
    
    def _handle_error_packet(self, packet: ErrorPacket) -> None:
        """Handle an error packet from the server."""
        self.logger.error("Received error from server: %s", packet.message)
        
        # If this is a fatal error, disconnect
        if packet.fatal:
            self.disconnect(ConnectionError(f"Server error: {packet.message}"))
    
    def _keepalive_loop(self) -> None:
        """Send keepalive packets to the server."""
        while self._running and not self._stop_event.is_set():
            try:
                # Check if we need to send a keepalive
                current_time = time.time()
                
                if self._connected and (current_time - self._last_keepalive) >= self.config.keepalive_interval:
                    self._send_keepalive()
                
                # Sleep for a short time to avoid busy-waiting
                self._stop_event.wait(1)
                
            except Exception as e:
                self.logger.error("Error in keepalive loop: %s", e, exc_info=True)
                self.disconnect(e)
    
    def _send_keepalive(self) -> None:
        """Send a keepalive packet to the server."""
        if not self._connected or not self._packet_processor:
            return
        
        try:
            # Create a keepalive packet
            keepalive = KeepalivePacket(timestamp=time.time())
            
            # Encrypt the keepalive
            encrypted = self._packet_processor.encrypt(keepalive.serialize())
            
            # Send the keepalive
            self._socket.send(encrypted)
            
            self._last_keepalive = time.time()
            self.logger.debug("Sent keepalive to server")
            
        except Exception as e:
            self.logger.error("Failed to send keepalive: %s", e, exc_info=True)
            raise
    
    def run(self) -> None:
        """Run the VPN client in the current thread."""
        if not self._running:
            if not self.connect():
                return
        
        try:
            # Keep the main thread alive
            while self._running and not self._stop_event.is_set():
                try:
                    # Check if we need to reconnect
                    if not self._connected and self.config.reconnect:
                        if self._reconnect_attempts < self.config.max_reconnect_attempts:
                            self._reconnect_attempts += 1
                            self.logger.info("Attempting to reconnect (attempt %d/%d)",
                                           self._reconnect_attempts,
                                           self.config.max_reconnect_attempts)
                            
                            if self.connect():
                                self.logger.info("Reconnected successfully")
                            else:
                                self.logger.warning("Reconnection failed, will retry in %d seconds",
                                                  self.config.reconnect_delay)
                                time.sleep(self.config.reconnect_delay)
                        else:
                            self.logger.error("Max reconnection attempts reached, giving up")
                            break
                    
                    # Sleep for a short time to avoid busy-waiting
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    self.logger.info("Received keyboard interrupt, shutting down...")
                    break
                except Exception as e:
                    self.logger.error("Error in main loop: %s", e, exc_info=True)
                    time.sleep(1)  # Prevent tight loop on repeated errors
        
        finally:
            self.disconnect()
    
    def stop(self) -> None:
        """Stop the VPN client."""
        self.disconnect()
    
    def is_connected(self) -> bool:
        """Check if the client is connected to the server."""
        return self._connected and self._running and not self._stop_event.is_set()


def main():
    """Main entry point for the VPN client."""
    import argparse
    import json
    import signal
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="VPN Client")
    parser.add_argument("-c", "--config", required=True, help="Path to configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load configuration
    try:
        with open(args.config, 'r') as f:
            config_data = json.load(f)
        
        config = ClientConfig(**config_data)
        
    except Exception as e:
        logging.error("Failed to load configuration: %s", e, exc_info=True)
        return 1
    
    # Create and run the VPN client
    client = VPNClient(config)
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logging.info("Received signal %s, shutting down...", signal.Signals(sig).name)
        client.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the client
    try:
        client.run()
    except Exception as e:
        logging.error("Fatal error: %s", e, exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
