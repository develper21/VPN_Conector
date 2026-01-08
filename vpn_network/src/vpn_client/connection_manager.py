"""
Connection Manager for the VPN Client

This module handles the management of connections to the VPN server, including
connection pooling, reconnection logic, and connection state management.
"""
import os
import sys
import time
import socket
import select
import logging
import random
import threading
import asyncio
import subprocess
import platform
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable, Set
from enum import Enum, auto
from collections import deque, defaultdict
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import LoggableMixin
from utils.validator import validate_ip_address, validate_port
from network.interface import UDPSocket, NetworkError
from discovery import (
    AdvancedLoadBalancer, LoadBalanceAlgorithm, VPNServer, ServerStatus,
    FailoverManager, FailoverTrigger
)
from discovery.server_registry import ServerRegistry
from discovery.health_checker import HealthChecker

class ConnectionState(Enum):
    """Represents state of a connection."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    ERROR = auto()
    RECONNECTING = auto()
    SWITCHING_SERVER = auto()
    FAILED = auto()
    SUSPENDED = auto()

class NetworkStatus(Enum):
    """Network status enumeration."""
    UNKNOWN = auto()
    HEALTHY = auto()
    DEGRADED = auto()
    UNSTABLE = auto()
    OFFLINE = auto()

class FailureType(Enum):
    """Types of connection failures."""
    NETWORK_UNREACHABLE = auto()
    DNS_FAILURE = auto()
    SERVER_UNREACHABLE = auto()
    AUTHENTICATION_FAILURE = auto()
    PROTOCOL_ERROR = auto()
    TIMEOUT = auto()
    CONNECTION_RESET = auto()
    QUALITY_DEGRADED = auto()
    MANUAL_DISCONNECT = auto()

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
    
    # Enhanced resilience stats
    uptime: float = 0.0
    quality_score: float = 0.0
    latency_ms: float = 0.0
    packet_loss: float = 0.0
    server_switches: int = 0
    network_failures: int = 0
    
    def update_uptime(self):
        """Update uptime based on current time."""
        if self.connect_time and self.connect_time > 0:
            self.uptime = time.time() - self.connect_time

@dataclass
class ConnectionMetrics:
    """Connection quality metrics."""
    timestamp: float
    latency_ms: float
    packet_loss: float
    jitter_ms: float
    bandwidth_mbps: float
    connection_stability: float  # 0-1 scale
    error_rate: float
    uptime_percentage: float
    reconnection_count: int
    server_switches: int
    
    def quality_score(self) -> float:
        """Calculate overall connection quality score."""
        # Weight different metrics
        weights = {
            'latency': 0.25,
            'packet_loss': 0.20,
            'jitter': 0.15,
            'bandwidth': 0.15,
            'stability': 0.15,
            'error_rate': 0.10
        }
        
        # Normalize metrics (lower is better for some, higher for others)
        latency_score = max(0, 1 - (self.latency_ms / 1000))  # 1000ms = 0 score
        packet_loss_score = max(0, 1 - self.packet_loss)
        jitter_score = max(0, 1 - (self.jitter_ms / 100))  # 100ms = 0 score
        bandwidth_score = min(1, self.bandwidth_mbps / 100)  # 100Mbps = 1 score
        stability_score = self.connection_stability
        error_score = max(0, 1 - self.error_rate)
        
        return (latency_score * weights['latency'] +
                packet_loss_score * weights['packet_loss'] +
                jitter_score * weights['jitter'] +
                bandwidth_score * weights['bandwidth'] +
                stability_score * weights['stability'] +
                error_score * weights['error_rate'])

@dataclass
class ReconnectionConfig:
    """Reconnection configuration."""
    max_attempts: int = 5
    initial_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    enable_exponential_backoff: bool = True
    enable_server_switching: bool = True
    server_switch_threshold: int = 3
    quality_threshold: float = 0.3
    network_check_interval: float = 5.0
    connection_timeout: float = 30.0
    keepalive_interval: float = 30.0
    keepalive_timeout: float = 10.0

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
    Represents a connection to a VPN server with resilience features.
    """
    
    def __init__(self, config: ConnectionConfig, resilience_config: Optional[Dict[str, Any]] = None):
        """
        Initialize connection.
        
        Args:
            config: The connection configuration.
            resilience_config: Optional resilience configuration.
        """
        super().__init__()
        
        # Configuration
        self.config = config
        
        # Resilience configuration
        if resilience_config:
            self.reconnect_config = ReconnectionConfig(**resilience_config.get('reconnection', {}))
        else:
            self.reconnect_config = ReconnectionConfig()
        
        # State
        self._state = ConnectionState.DISCONNECTED
        self._socket = None
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        
        # Enhanced statistics
        self.stats = ConnectionStats()
        
        # Resilience state
        self.reconnection_attempts = 0
        self.last_reconnection_time = 0.0
        self.server_switch_count = 0
        self.network_status = NetworkStatus.UNKNOWN
        self.connection_metrics: deque = deque(maxlen=1000)
        self.failure_history: deque = deque(maxlen=100)
        self.failure_counts: Dict[FailureType, int] = defaultdict(int)
        
        # Background tasks
        self.monitor_thread = None
        self.keepalive_thread = None
        self.running = False
        
        # Callbacks
        self._on_connect_callbacks = []
        self._on_disconnect_callbacks = []
        self._on_data_callbacks = []
        self._on_error_callbacks = []
        self._on_reconnect_callbacks = []
        self._on_server_switch_callbacks = []
        self._on_quality_degraded_callbacks = []
        
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
        """Handle an error with resilience features."""
        with self._lock:
            self.stats.errors += 1
            self._notify_error(error)
            
            # Record failure type
            failure_type = self._classify_error(error)
            self._record_failure(failure_type, str(error))
            
            # If we're connected, try to reconnect
            if self._state == ConnectionState.CONNECTED:
                self.logger.warning("Connection error, attempting to reconnect...")
                self._start_auto_reconnection()
    
    def _classify_error(self, error: Exception) -> FailureType:
        """Classify error type for resilience handling."""
        error_str = str(error).lower()
        
        if "network" in error_str or "unreachable" in error_str:
            return FailureType.NETWORK_UNREACHABLE
        elif "dns" in error_str or "host" in error_str:
            return FailureType.DNS_FAILURE
        elif "timeout" in error_str:
            return FailureType.TIMEOUT
        elif "connection reset" in error_str:
            return FailureType.CONNECTION_RESET
        elif "auth" in error_str or "login" in error_str:
            return FailureType.AUTHENTICATION_FAILURE
        else:
            return FailureType.PROTOCOL_ERROR
    
    def _record_failure(self, failure_type: FailureType, message: str = None):
        """Record a connection failure."""
        current_time = time.time()
        
        # Update failure counts
        self.failure_counts[failure_type] += 1
        
        # Record failure in history
        failure_record = {
            'timestamp': current_time,
            'type': failure_type.name,
            'message': message,
            'server': f"{self.config.server_host}:{self.config.server_port}"
        }
        
        self.failure_history.append(failure_record)
        
        # Update statistics
        if failure_type in [FailureType.NETWORK_UNREACHABLE, FailureType.DNS_FAILURE]:
            self.stats.network_failures += 1
        
        self.logger.warning(f"Connection failure recorded: {failure_type.name} - {message}")
    
    def _start_auto_reconnection(self):
        """Start automatic reconnection process."""
        if self._state in [ConnectionState.RECONNECTING, ConnectionState.CONNECTING]:
            return
        
        self._state = ConnectionState.RECONNECTING
        self.reconnection_attempts += 1
        self.last_reconnection_time = time.time()
        
        # Trigger reconnection callbacks
        self._notify_reconnect({
            'attempt': self.reconnection_attempts,
            'max_attempts': self.reconnect_config.max_attempts
        })
        
        # Start reconnection in background
        threading.Thread(target=self._reconnection_loop, daemon=True).start()
    
    def _reconnection_loop(self):
        """Main reconnection loop with exponential backoff."""
        try:
            for attempt in range(self.reconnection_attempts, 
                               self.reconnect_config.max_attempts + 1):
                
                self.logger.info(f"Reconnection attempt {attempt}/{self.reconnect_config.max_attempts}")
                
                # Calculate delay
                delay = self._calculate_reconnection_delay(attempt)
                
                if delay > 0:
                    time.sleep(delay)
                
                # Check network connectivity first
                if not self._check_network_connectivity():
                    self.logger.warning("Network not ready, waiting...")
                    continue
                
                # Attempt reconnection
                success = self._attempt_reconnection()
                
                if success:
                    self.logger.info(f"Reconnection successful on attempt {attempt}")
                    self.stats.reconnects += 1
                    self.reconnection_attempts = 0
                    return
                else:
                    self.logger.warning(f"Reconnection attempt {attempt} failed")
            
            # All attempts failed
            self._state = ConnectionState.FAILED
            self.logger.error("All reconnection attempts failed")
            
        except Exception as e:
            self.logger.error(f"Reconnection loop error: {e}")
            self._state = ConnectionState.FAILED
    
    def _calculate_reconnection_delay(self, attempt: int) -> float:
        """Calculate reconnection delay with exponential backoff."""
        try:
            if self.reconnect_config.enable_exponential_backoff:
                delay = self.reconnect_config.initial_delay * (
                    self.reconnect_config.backoff_multiplier ** (attempt - 1)
                )
                delay = min(delay, self.reconnect_config.max_delay)
            else:
                delay = self.reconnect_config.initial_delay
            
            # Add jitter if enabled
            if self.reconnect_config.jitter:
                jitter = random.uniform(0.1, 0.3) * delay
                delay += jitter
            
            return delay
            
        except Exception as e:
            self.logger.error(f"Failed to calculate reconnection delay: {e}")
            return self.reconnect_config.initial_delay
    
    def _attempt_reconnection(self) -> bool:
        """Attempt to reconnect to the server."""
        try:
            # Disconnect first if connected
            if self._socket:
                self._cleanup()
            
            # Attempt connection
            return self.connect()
            
        except Exception as e:
            self.logger.error(f"Reconnection attempt failed: {e}")
            return False
    
    def _check_network_connectivity(self) -> bool:
        """Check network connectivity status."""
        try:
            # Test DNS resolution
            socket.gethostbyname('google.com')
            
            # Test internet connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            
            if result == 0:
                self.network_status = NetworkStatus.HEALTHY
                return True
            else:
                self.network_status = NetworkStatus.DEGRADED
                return False
                
        except Exception as e:
            self.network_status = NetworkStatus.OFFLINE
            self.logger.error(f"Network connectivity check failed: {e}")
            return False
    
    def _monitor_connection_quality(self):
        """Monitor connection quality and trigger actions if needed."""
        try:
            if self._state != ConnectionState.CONNECTED:
                return
            
            # Measure current quality metrics
            metrics = self._measure_connection_quality()
            
            if metrics:
                self.connection_metrics.append(metrics)
                
                # Check if quality has degraded significantly
                if metrics.quality_score() < self.reconnect_config.quality_threshold:
                    self.logger.warning(f"Connection quality degraded: {metrics.quality_score():.2f}")
                    
                    # Trigger quality degraded callbacks
                    self._notify_quality_degraded({
                        'current_score': metrics.quality_score(),
                        'threshold': self.reconnect_config.quality_threshold,
                        'metrics': metrics
                    })
                    
                    # Consider server switching if enabled
                    if self.reconnect_config.enable_server_switching:
                        self._initiate_server_switch()
            
        except Exception as e:
            self.logger.error(f"Connection quality monitoring failed: {e}")
    
    def _measure_connection_quality(self) -> Optional[ConnectionMetrics]:
        """Measure current connection quality metrics."""
        try:
            if not self._socket:
                return None
            
            # Measure latency
            start_time = time.time()
            
            # Simple ping test
            test_data = b'PING'
            if hasattr(self._socket, 'send'):
                self._socket.send(test_data)
                # In a real implementation, we would wait for response
                # For now, simulate response time
                time.sleep(0.01)
                latency = (time.time() - start_time) * 1000
            else:
                latency = 0.0
            
            # Create metrics
            metrics = ConnectionMetrics(
                timestamp=time.time(),
                latency_ms=latency,
                packet_loss=0.0,  # Would measure actual packet loss
                jitter_ms=0.0,   # Would measure actual jitter
                bandwidth_mbps=0.0,  # Would measure actual bandwidth
                connection_stability=1.0,
                error_rate=0.0,
                uptime_percentage=100.0,
                reconnection_count=self.reconnection_attempts,
                server_switches=self.server_switch_count
            )
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to measure connection quality: {e}")
            return None
    
    def _initiate_server_switch(self):
        """Initiate server switching (placeholder for integration)."""
        self.logger.info("Server switching initiated due to quality degradation")
        self.server_switch_count += 1
        self.stats.server_switches = self.server_switch_count
        
        # Trigger server switch callbacks
        self._notify_server_switch({
            'reason': 'quality_degradation',
            'current_quality': self.stats.quality_score,
            'switch_count': self.server_switch_count
        })
    
    def _start_monitoring(self):
        """Start background monitoring threads."""
        if self.running:
            return
        
        self.running = True
        
        # Start quality monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitor_thread.start()
        
        # Start keepalive thread
        self.keepalive_thread = threading.Thread(target=self._keepalive_worker, daemon=True)
        self.keepalive_thread.start()
        
        self.logger.info("Started connection monitoring")
    
    def _monitoring_worker(self):
        """Background worker for connection monitoring."""
        while self.running:
            try:
                self._monitor_connection_quality()
                time.sleep(10)  # Monitor every 10 seconds
            except Exception as e:
                self.logger.error(f"Monitoring thread error: {e}")
                time.sleep(5)
    
    def _keepalive_worker(self):
        """Background worker for keepalive packets."""
        while self.running:
            try:
                if self._state == ConnectionState.CONNECTED and self._socket:
                    self._send_keepalive()
                
                time.sleep(self.reconnect_config.keepalive_interval)
            except Exception as e:
                self.logger.error(f"Keepalive thread error: {e}")
                time.sleep(5)
    
    def _send_keepalive(self):
        """Send keepalive packet to maintain connection."""
        try:
            if hasattr(self._socket, 'send'):
                keepalive_data = b'KEEPALIVE'
                self._socket.send(keepalive_data)
                self.stats.last_activity = time.time()
        except Exception as e:
            self.logger.error(f"Keepalive failed: {e}")
            self._handle_error(e)
    
    def _notify_reconnect(self, data: Dict[str, Any]):
        """Notify reconnection callbacks."""
        for callback in self._on_reconnect_callbacks:
            try:
                callback(self, data)
            except Exception as e:
                self.logger.error(f"Error in reconnect callback: {e}")
    
    def _notify_server_switch(self, data: Dict[str, Any]):
        """Notify server switch callbacks."""
        for callback in self._on_server_switch_callbacks:
            try:
                callback(self, data)
            except Exception as e:
                self.logger.error(f"Error in server switch callback: {e}")
    
    def _notify_quality_degraded(self, data: Dict[str, Any]):
        """Notify quality degraded callbacks."""
        for callback in self._on_quality_degraded_callbacks:
            try:
                callback(self, data)
            except Exception as e:
                self.logger.error(f"Error in quality degraded callback: {e}")
    
    def add_reconnect_callback(self, callback: Callable[['Connection', Dict[str, Any]], None]) -> None:
        """Add a callback to be called during reconnection."""
        with self._lock:
            self._on_reconnect_callbacks.append(callback)
    
    def add_server_switch_callback(self, callback: Callable[['Connection', Dict[str, Any]], None]) -> None:
        """Add a callback to be called during server switch."""
        with self._lock:
            self._on_server_switch_callbacks.append(callback)
    
    def add_quality_degraded_callback(self, callback: Callable[['Connection', Dict[str, Any]], None]) -> None:
        """Add a callback to be called when quality degrades."""
        with self._lock:
            self._on_quality_degraded_callbacks.append(callback)
    
    def get_connection_quality(self) -> float:
        """Get current connection quality score."""
        if self.connection_metrics:
            recent_metrics = list(self.connection_metrics)[-5:]
            if recent_metrics:
                scores = [m.quality_score() for m in recent_metrics]
                return statistics.mean(scores)
        return 0.0
    
    def get_network_status(self) -> NetworkStatus:
        """Get current network status."""
        return self.network_status
    
    def get_failure_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent failure history."""
        return list(self.failure_history)[-limit:]
    
    def get_connection_metrics(self, hours: int = 1) -> List[ConnectionMetrics]:
        """Get connection metrics for the specified time period."""
        cutoff_time = time.time() - (hours * 3600)
        return [m for m in self.connection_metrics if m.timestamp >= cutoff_time]
    
    def stop_monitoring(self):
        """Stop background monitoring threads."""
        self.running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)
        
        if self.keepalive_thread and self.keepalive_thread.is_alive():
            self.keepalive_thread.join(timeout=10)
        
        self.logger.info("Stopped connection monitoring")
    
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
        Connect to the server with resilience features.
        
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
            
            # Start monitoring for this connection
            if hasattr(conn, '_start_monitoring'):
                conn._start_monitoring()
            
            return True
    
    def disconnect(self) -> None:
        """Close the active connection with cleanup."""
        with self._lock:
            if self.active_connection:
                # Stop monitoring for this connection
                if hasattr(self.active_connection, 'stop_monitoring'):
                    self.active_connection.stop_monitoring()
                
                self.active_connection.disconnect()
                self.active_connection = None
    
    def send(self, data: bytes) -> bool:
        """
        Send data through the active connection with resilience.
        
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
                # Don't set active_connection to None here, let resilience handle it
                return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive data from the active connection with resilience.
        
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
                # Don't set active_connection to None here, let resilience handle it
                return None
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get comprehensive connection statistics with resilience metrics."""
        with self._lock:
            if not self.active_connection:
                return {'status': 'no_active_connection'}
            
            # Get basic stats
            stats = {
                'state': self.active_connection.state.name,
                'server': f"{self.active_connection.config.server_host}:{self.active_connection.config.server_port}",
                'bytes_sent': self.active_connection.stats.bytes_sent,
                'bytes_received': self.active_connection.stats.bytes_received,
                'packets_sent': self.active_connection.stats.packets_sent,
                'packets_received': self.active_connection.stats.packets_received,
                'errors': self.active_connection.stats.errors,
                'reconnects': self.active_connection.stats.reconnects,
                'uptime': self.active_connection.stats.uptime,
                'quality_score': self.active_connection.stats.quality_score,
                'latency_ms': self.active_connection.stats.latency_ms,
                'packet_loss': self.active_connection.stats.packet_loss,
                'server_switches': self.active_connection.stats.server_switches,
                'network_failures': self.active_connection.stats.network_failures,
                'network_status': self.active_connection.get_network_status().name if hasattr(self.active_connection, 'get_network_status') else 'unknown'
            }
            
            # Add resilience stats if available
            if hasattr(self.active_connection, 'get_failure_history'):
                stats['failure_history'] = self.active_connection.get_failure_history(5)
            
            if hasattr(self.active_connection, 'get_connection_metrics'):
                metrics = self.active_connection.get_connection_metrics(1)  # Last hour
                if metrics:
                    stats['recent_metrics'] = [{
                        'timestamp': m.timestamp,
                        'quality_score': m.quality_score(),
                        'latency_ms': m.latency_ms,
                        'packet_loss': m.packet_loss
                    } for m in metrics[-10:]]  # Last 10 metrics
            
            return stats
    
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
        """Close all connections and clean up resources with monitoring cleanup."""
        with self._lock:
            # Stop monitoring for active connection
            if self.active_connection and hasattr(self.active_connection, 'stop_monitoring'):
                self.active_connection.stop_monitoring()
            
            self.pool.close()


def main():
    """Example usage of enhanced ConnectionManager with resilience features."""
    import argparse
    import json
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Enhanced VPN Connection Manager")
    parser.add_argument("-c", "--config", required=True, help="Path to configuration file")
    parser.add_argument("--enable-resilience", action="store_true", help="Enable connection resilience features")
    parser.add_argument("--quality-threshold", type=float, default=0.3, help="Connection quality threshold (0.0-1.0)")
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
    
    # Create and use enhanced connection manager
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
        
        # Create connection configurations
        configs = [
            ConnectionConfig(
                server_host=config.server_host,
                server_port=config.server_port,
                protocol=config.protocol,
                timeout=10,
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
                encryption_key=None
            )
        ]
        
        # Create connection pool
        pool = ConnectionPool(configs, pool_size=1)
        
        # Create enhanced connection manager
        manager = ConnectionManager(config)
        
        # Add resilience callbacks
        def on_reconnect(conn, data):
            print(f" Reconnection attempt {data['attempt']}/{data['max_attempts']}")
        
        def on_server_switch(conn, data):
            print(f" Server switch: {data['reason']} (switch #{data['switch_count']})")
        
        def on_quality_degraded(conn, data):
            print(f" Quality degraded: {data['current_score']:.2f} < {data['threshold']:.2f}")
        
        # Add callbacks to active connection
        if hasattr(pool, 'connections') and pool.connections:
            conn = pool.connections[0]
            conn.add_reconnect_callback(on_reconnect)
            conn.add_server_switch_callback(on_server_switch)
            conn.add_quality_degraded_callback(on_quality_degraded)
        
        # Connect to server
        print(" Connecting to VPN server...")
        if manager.connect():
            print(" Successfully connected to server!")
            
            # Get connection statistics
            stats = manager.get_connection_stats()
            print(f" Connection Stats:")
            print(f"   Server: {stats.get('server', 'N/A')}")
            print(f"   State: {stats.get('state', 'N/A')}")
            print(f"   Quality Score: {stats.get('quality_score', 0):.3f}")
            print(f"   Network Status: {stats.get('network_status', 'N/A')}")
            
            # Example: Send some data
            if manager.send(b"Hello, server!"):
                print(" Sent data to server")
            
            # Example: Receive data (with timeout)
            data = manager.receive(timeout=5.0)
            if data:
                print(f" Received data: {data}")
            else:
                print("  No data received (timeout)")
            
            # Monitor connection for a while
            print(" Monitoring connection for 30 seconds...")
            import time
            time.sleep(30)
            
            # Get final stats
            final_stats = manager.get_connection_stats()
            print(f" Final Stats:")
            print(f"   Uptime: {final_stats.get('uptime', 0):.2f}s")
            print(f"   Bytes Sent: {final_stats.get('bytes_sent', 0)}")
            print(f"   Bytes Received: {final_stats.get('bytes_received', 0)}")
            print(f"   Reconnects: {final_stats.get('reconnects', 0)}")
            print(f"   Server Switches: {final_stats.get('server_switches', 0)}")
            
            # Disconnect
            manager.disconnect()
            print(" Disconnected from server")
        else:
            print(" Failed to connect to any server")
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
