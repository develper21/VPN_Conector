"""
Connection Manager for the VPN Client

This module handles the management of connections to the VPN server, including
connection pooling, reconnection logic, and connection state management.
"""
import os
import time
import socket
import select
import logging
import random
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable, Set
from enum import Enum, auto

from utils.logger import LoggableMixin
from utils.validator import validate_ip_address, validate_port
from network.interface import UDPSocket, NetworkError

class ConnectionState(Enum):
    """Represents the state of a connection."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    ERROR = auto()

@dataclass
class ConnectionStats:
    """Statistics for a connection."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connect_time: Optional[float] = None
    disconnect_time: Optional[float] = None
    last_activity: Optional[float] = None
    errors: int = 0
    reconnects: int = 0

@dataclass
class ConnectionConfig:
    """Configuration for a connection."""
    server_host: str
    server_port: int
    protocol: str = "udp"
    timeout: int = 10
    retry_attempts: int = 3
    retry_delay: float = 1.0
    max_reconnect_attempts: int = 5
    reconnect_delay: float = 5.0
    keepalive_interval: int = 30
    buffer_size: int = 65535
    mtu: int = 1500
    use_compression: bool = False
    compression_level: int = 6
    use_encryption: bool = True
    encryption_key: Optional[bytes] = None
    
    def validate(self) -> None:
        """Validate the configuration."""
        if not self.server_host:
            raise ValueError("Server host is required")
        
        if not (1 <= self.server_port <= 65535):
            raise ValueError("Invalid server port")
        
        if self.protocol.lower() not in ["udp", "tcp"]:
            raise ValueError("Protocol must be either 'udp' or 'tcp'")
        
        if self.timeout < 1:
            raise ValueError("Timeout must be at least 1 second")
        
        if self.retry_attempts < 0:
            raise ValueError("Retry attempts cannot be negative")
        
        if self.retry_delay < 0:
            raise ValueError("Retry delay cannot be negative")
        
        if self.max_reconnect_attempts < 0:
            raise ValueError("Max reconnect attempts cannot be negative")
        
        if self.reconnect_delay < 0:
            raise ValueError("Reconnect delay cannot be negative")
        
        if self.keepalive_interval < 5:
            raise ValueError("Keepalive interval must be at least 5 seconds")
        
        if self.buffer_size < 1024 or self.buffer_size > 65535:
            raise ValueError("Buffer size must be between 1024 and 65535")
        
        if self.mtu < 576 or self.mtu > 65535:
            raise ValueError("MTU must be between 576 and 65535")
        
        if not (0 <= self.compression_level <= 9):
            raise ValueError("Compression level must be between 0 and 9")

class Connection(LoggableMixin):
    """
    Represents a connection to a VPN server.
    """
    
    def __init__(self, config: ConnectionConfig):
        """
        Initialize the connection.
        
        Args:
            config: The connection configuration.
        """
        super().__init__()
        
        # Configuration
        self.config = config
        
        # State
        self._state = ConnectionState.DISCONNECTED
        self._socket = None
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        
        # Statistics
        self.stats = ConnectionStats()
        
        # Callbacks
        self._on_connect_callbacks = []
        self._on_disconnect_callbacks = []
        self._on_data_callbacks = []
        self._on_error_callbacks = []
        
        self.logger.info(f"Connection initialized to {self.config.server_host}:{self.config.server_port}")
    
    @property
    def state(self) -> ConnectionState:
        """Get the current connection state."""
        with self._lock:
            return self._state
    
    @state.setter
    def state(self, value: ConnectionState) -> None:
        """Set the connection state and trigger appropriate callbacks."""
        with self._lock:
            old_state = self._state
            self._state = value
            
            # Log state change
            self.logger.debug(f"Connection state changed: {old_state.name} -> {value.name}")
            
            # Trigger callbacks
            if value == ConnectionState.CONNECTED and old_state != ConnectionState.CONNECTED:
                self._notify_connect()
            elif value == ConnectionState.DISCONNECTED and old_state != ConnectionState.DISCONNECTED:
                self._notify_disconnect()
    
    def connect(self) -> bool:
        """
        Connect to the server.
        
        Returns:
            bool: True if the connection was successful, False otherwise.
        """
        with self._lock:
            if self.state in [ConnectionState.CONNECTING, ConnectionState.CONNECTED]:
                self.logger.warning("Already connected or connecting")
                return self.state == ConnectionState.CONNECTED
            
            self.state = ConnectionState.CONNECTING
            self._stop_event.clear()
            
            try:
                # Create and configure the socket
                if self.config.protocol.lower() == "udp":
                    self._socket = UDPSocket(
                        local_addr=('0.0.0.0', 0),  # Use any available port
                        remote_addr=(self.config.server_host, self.config.server_port),
                        timeout=self.config.timeout,
                        logger=self.logger
                    )
                else:
                    # TCP would be implemented here
                    raise NotImplementedError("TCP protocol not yet implemented")
                
                # Connect the socket
                self._socket.connect()
                
                # Update state and statistics
                self.state = ConnectionState.CONNECTED
                self.stats.connect_time = time.time()
                self.stats.last_activity = time.time()
                
                self.logger.info(f"Connected to {self.config.server_host}:{self.config.server_port}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to connect: {e}", exc_info=True)
                self.state = ConnectionState.ERROR
                self._cleanup()
                return False
    
    def disconnect(self) -> None:
        """Disconnect from the server."""
        with self._lock:
            if self.state in [ConnectionState.DISCONNECTED, ConnectionState.DISCONNECTING]:
                return
            
            self.state = ConnectionState.DISCONNECTING
            self._stop_event.set()
            
            try:
                self._cleanup()
                self.logger.info("Disconnected from server")
            except Exception as e:
                self.logger.error(f"Error during disconnection: {e}", exc_info=True)
            finally:
                self.state = ConnectionState.DISCONNECTED
    
    def send(self, data: bytes) -> bool:
        """
        Send data to the server.
        
        Args:
            data: The data to send.
            
        Returns:
            bool: True if the data was sent successfully, False otherwise.
        """
        if self.state != ConnectionState.CONNECTED or not self._socket:
            self.logger.warning("Cannot send data: not connected")
            return False
        
        try:
            with self._lock:
                # In a real implementation, we would handle encryption, compression, etc. here
                self._socket.send(data)
                
                # Update statistics
                self.stats.bytes_sent += len(data)
                self.stats.packets_sent += 1
                self.stats.last_activity = time.time()
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}", exc_info=True)
            self._handle_error(e)
            return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive data from the server.
        
        Args:
            timeout: Maximum time to wait for data, in seconds.
            
        Returns:
            The received data, or None if no data was received.
        """
        if self.state != ConnectionState.CONNECTED or not self._socket:
            self.logger.warning("Cannot receive data: not connected")
            return None
        
        try:
            # Set the socket timeout
            old_timeout = self._socket.gettimeout()
            self._socket.settimeout(timeout)
            
            # Receive data
            data = self._socket.recv()
            
            # Restore the original timeout
            self._socket.settimeout(old_timeout)
            
            if data:
                # Update statistics
                with self._lock:
                    self.stats.bytes_received += len(data)
                    self.stats.packets_received += 1
                    self.stats.last_activity = time.time()
                
                # Notify data callbacks
                self._notify_data(data)
                
                return data
                
            return None
            
        except socket.timeout:
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}", exc_info=True)
            self._handle_error(e)
            return None
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        with self._lock:
            if self._socket:
                try:
                    self._socket.close()
                except Exception as e:
                    self.logger.error(f"Error closing socket: {e}", exc_info=True)
                finally:
                    self._socket = None
            
            # Update statistics
            if self.state == ConnectionState.CONNECTED:
                self.stats.disconnect_time = time.time()
    
    def _handle_error(self, error: Exception) -> None:
        """Handle an error."""
        with self._lock:
            self.stats.errors += 1
            self._notify_error(error)
            
            # If we're connected, try to reconnect
            if self.state == ConnectionState.CONNECTED:
                self.logger.warning("Connection error, attempting to reconnect...")
                self.disconnect()
    
    def add_connect_callback(self, callback: Callable[['Connection'], None]) -> None:
        """
        Add a callback to be called when the connection is established.
        
        Args:
            callback: The callback function.
        """
        with self._lock:
            self._on_connect_callbacks.append(callback)
    
    def add_disconnect_callback(self, callback: Callable[['Connection'], None]) -> None:
        """
        Add a callback to be called when the connection is closed.
        
        Args:
            callback: The callback function.
        """
        with self._lock:
            self._on_disconnect_callbacks.append(callback)
    
    def add_data_callback(self, callback: Callable[['Connection', bytes], None]) -> None:
        """
        Add a callback to be called when data is received.
        
        Args:
            callback: The callback function.
        """
        with self._lock:
            self._on_data_callbacks.append(callback)
    
    def add_error_callback(self, callback: Callable[['Connection', Exception], None]) -> None:
        """
        Add a callback to be called when an error occurs.
        
        Args:
            callback: The callback function.
        """
        with self._lock:
            self._on_error_callbacks.append(callback)
    
    def _notify_connect(self) -> None:
        """Notify all connect callbacks."""
        callbacks = []
        with self._lock:
            callbacks = list(self._on_connect_callbacks)
        
        for callback in callbacks:
            try:
                callback(self)
            except Exception as e:
                self.logger.error(f"Error in connect callback: {e}", exc_info=True)
    
    def _notify_disconnect(self) -> None:
        """Notify all disconnect callbacks."""
        callbacks = []
        with self._lock:
            callbacks = list(self._on_disconnect_callbacks)
        
        for callback in callbacks:
            try:
                callback(self)
            except Exception as e:
                self.logger.error(f"Error in disconnect callback: {e}", exc_info=True)
    
    def _notify_data(self, data: bytes) -> None:
        """Notify all data callbacks."""
        callbacks = []
        with self._lock:
            callbacks = list(self._on_data_callbacks)
        
        for callback in callbacks:
            try:
                callback(self, data)
            except Exception as e:
                self.logger.error(f"Error in data callback: {e}", exc_info=True)
    
    def _notify_error(self, error: Exception) -> None:
        """Notify all error callbacks."""
        callbacks = []
        with self._lock:
            callbacks = list(self._on_error_callbacks)
        
        for callback in callbacks:
            try:
                callback(self, error)
            except Exception as e:
                self.logger.error(f"Error in error callback: {e}", exc_info=True)

class ConnectionPool(LoggableMixin):
    """
    Manages a pool of connections to multiple servers for load balancing and failover.
    """
    
    def __init__(self, configs: List[ConnectionConfig], pool_size: int = 3):
        """
        Initialize the connection pool.
        
        Args:
            configs: List of connection configurations.
            pool_size: Maximum number of connections to maintain in the pool.
        """
        super().__init__()
        
        if not configs:
            raise ValueError("At least one connection configuration is required")
        
        self.configs = configs
        self.pool_size = min(pool_size, len(configs))
        self.connections: List[Connection] = []
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        
        # Initialize the connection pool
        self._init_pool()
    
    def _init_pool(self) -> None:
        """Initialize the connection pool with initial connections."""
        with self._lock:
            # Shuffle the configurations to distribute load
            configs = list(self.configs)
            random.shuffle(configs)
            
            # Create initial connections
            for i in range(min(self.pool_size, len(configs))):
                conn = Connection(configs[i])
                self.connections.append(conn)
                
                # Set up callbacks
                conn.add_connect_callback(self._on_connect)
                conn.add_disconnect_callback(self._on_disconnect)
                conn.add_error_callback(self._on_error)
    
    def get_connection(self) -> Optional[Connection]:
        """
        Get an active connection from the pool.
        
        Returns:
            An active connection, or None if no connections are available.
        """
        with self._lock:
            # Try to find a connected connection
            for conn in self.connections:
                if conn.state == ConnectionState.CONNECTED:
                    return conn
            
            # If no connected connections, try to connect one
            for conn in self.connections:
                if conn.state == ConnectionState.DISCONNECTED:
                    if conn.connect():
                        return conn
            
            # If all else fails, try to create a new connection
            if len(self.connections) < len(self.configs):
                # Find a config that's not in use
                used_configs = {c.config for c in self.connections}
                for config in self.configs:
                    if config not in used_configs:
                        conn = Connection(config)
                        conn.add_connect_callback(self._on_connect)
                        conn.add_disconnect_callback(self._on_disconnect)
                        conn.add_error_callback(self._on_error)
                        
                        if conn.connect():
                            self.connections.append(conn)
                            return conn
            
            return None
    
    def broadcast(self, data: bytes) -> int:
        """
        Send data to all connected connections.
        
        Args:
            data: The data to send.
            
        Returns:
            The number of connections the data was sent to.
        """
        count = 0
        with self._lock:
            for conn in self.connections:
                if conn.state == ConnectionState.CONNECTED:
                    if conn.send(data):
                        count += 1
        return count
    
    def close(self) -> None:
        """Close all connections in the pool."""
        with self._lock:
            for conn in self.connections:
                try:
                    conn.disconnect()
                except Exception as e:
                    self.logger.error(f"Error disconnecting connection: {e}", exc_info=True)
            
            self.connections.clear()
    
    def _on_connect(self, conn: Connection) -> None:
        """Handle connection established event."""
        self.logger.info(f"Connection established to {conn.config.server_host}:{conn.config.server_port}")
    
    def _on_disconnect(self, conn: Connection) -> None:
        """Handle connection closed event."""
        self.logger.info(f"Connection closed to {conn.config.server_host}:{conn.config.server_port}")
    
    def _on_error(self, conn: Connection, error: Exception) -> None:
        """Handle connection error event."""
        self.logger.error(
            f"Connection error with {conn.config.server_host}:{conn.config.server_port}: {error}",
            exc_info=True
        )

class ConnectionManager(LoggableMixin):
    """
    Manages connections to VPN servers, including connection pooling, failover, and reconnection.
    """
    
    def __init__(self, config):
        """
        Initialize the connection manager.
        
        Args:
            config: The client configuration.
        """
        super().__init__()
        
        # Parse server addresses
        self.servers = self._parse_servers(config.server_host, config.server_port)
        if not self.servers:
            raise ValueError("No valid server addresses provided")
        
        # Create connection configurations
        self.configs = [
            ConnectionConfig(
                server_host=host,
                server_port=port,
                protocol=config.protocol,
                timeout=10,  # Default timeout of 10 seconds
                retry_attempts=3,
                retry_delay=1.0,
                max_reconnect_attempts=config.max_reconnect_attempts,
                reconnect_delay=config.reconnect_delay,
                keepalive_interval=config.keepalive_interval,
                buffer_size=65535,
                mtu=config.mtu,
                use_compression=True,
                compression_level=6,
                use_encryption=True,
                encryption_key=None  # Will be set during authentication
            )
            for host, port in self.servers
        ]
        
        # Create connection pool
        self.pool = ConnectionPool(self.configs, pool_size=min(3, len(self.configs)))
        
        # Active connection
        self.active_connection = None
        self._lock = threading.RLock()
        
        self.logger.info(f"Connection manager initialized with {len(self.servers)} servers")
    
    def _parse_servers(self, server_str: str, port: int) -> List[Tuple[str, int]]:
        """
        Parse server addresses from a string.
        
        Args:
            server_str: Comma-separated list of server addresses.
            port: Default port to use if not specified in the address.
            
        Returns:
            List of (host, port) tuples.
        """
        servers = []
        
        for addr in server_str.split(','):
            addr = addr.strip()
            if not addr:
                continue
                
            # Check if port is specified in the address (e.g., "example.com:1194")
            if ':' in addr:
                host, port_str = addr.rsplit(':', 1)
                try:
                    server_port = int(port_str)
                    if not (1 <= server_port <= 65535):
                        self.logger.warning(f"Invalid port in server address: {addr}")
                        continue
                except ValueError:
                    self.logger.warning(f"Invalid port in server address: {addr}")
                    continue
            else:
                host = addr
                server_port = port
            
            servers.append((host, server_port))
        
        return servers
    
    def connect(self) -> bool:
        """
        Establish a connection to a VPN server.
        
        Returns:
            bool: True if a connection was established, False otherwise.
        """
        with self._lock:
            if self.active_connection and self.active_connection.state == ConnectionState.CONNECTED:
                return True
            
            # Get a connection from the pool
            conn = self.pool.get_connection()
            if not conn:
                self.logger.error("Failed to establish a connection to any server")
                return False
            
            self.active_connection = conn
            return True
    
    def disconnect(self) -> None:
        """Close the active connection."""
        with self._lock:
            if self.active_connection:
                self.active_connection.disconnect()
                self.active_connection = None
    
    def send(self, data: bytes) -> bool:
        """
        Send data through the active connection.
        
        Args:
            data: The data to send.
            
        Returns:
            bool: True if the data was sent successfully, False otherwise.
        """
        with self._lock:
            if not self.active_connection or self.active_connection.state != ConnectionState.CONNECTED:
                if not self.connect():
                    return False
            
            try:
                return self.active_connection.send(data)
            except Exception as e:
                self.logger.error(f"Failed to send data: {e}", exc_info=True)
                self.active_connection = None
                return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive data from the active connection.
        
        Args:
            timeout: Maximum time to wait for data, in seconds.
            
        Returns:
            The received data, or None if no data was received.
        """
        with self._lock:
            if not self.active_connection or self.active_connection.state != ConnectionState.CONNECTED:
                if not self.connect():
                    return None
            
            try:
                return self.active_connection.receive(timeout)
            except Exception as e:
                self.logger.error(f"Failed to receive data: {e}", exc_info=True)
                self.active_connection = None
                return None
    
    def is_connected(self) -> bool:
        """
        Check if there is an active connection.
        
        Returns:
            bool: True if connected, False otherwise.
        """
        with self._lock:
            return (self.active_connection is not None and 
                    self.active_connection.state == ConnectionState.CONNECTED)
    
    def close(self) -> None:
        """Close all connections and clean up resources."""
        with self._lock:
            self.disconnect()
            self.pool.close()


def main():
    """Example usage of the ConnectionManager."""
    import argparse
    import json
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="VPN Connection Manager")
    parser.add_argument("-c", "--config", required=True, help="Path to configuration file")
    args = parser.parse_args()
    
    # Load configuration
    try:
        with open(args.config, 'r') as f:
            config_data = json.load(f)
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        return 1
    
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and use the connection manager
    try:
        # Create a dummy config object
        class Config:
            def __init__(self, data):
                self.server_host = data.get('server_host', 'localhost')
                self.server_port = data.get('server_port', 1194)
                self.protocol = data.get('protocol', 'udp')
                self.max_reconnect_attempts = data.get('max_reconnect_attempts', 5)
                self.reconnect_delay = data.get('reconnect_delay', 5.0)
                self.keepalive_interval = data.get('keepalive_interval', 30)
                self.mtu = data.get('mtu', 1500)
        
        config = Config(config_data)
        
        # Create the connection manager
        manager = ConnectionManager(config)
        
        # Connect to a server
        if manager.connect():
            print("Successfully connected to a server!")
            
            # Example: Send some data
            if manager.send(b"Hello, server!"):
                print("Sent data to server")
            
            # Example: Receive data (with timeout)
            data = manager.receive(timeout=5.0)
            if data:
                print(f"Received data: {data}")
            else:
                print("No data received (timeout)")
            
            # Disconnect
            manager.disconnect()
            print("Disconnected from server")
        else:
            print("Failed to connect to any server")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
