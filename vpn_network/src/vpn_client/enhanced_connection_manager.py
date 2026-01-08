"""
Enhanced Connection Manager for VPN Security Project.
This module provides comprehensive connection management with resilience features,
auto-reconnection, network monitoring, and quality assurance.
"""
import os
import sys
import time
import asyncio
import threading
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vpn_client.connection_resilience import (
    ConnectionResilienceManager, ConnectionState, NetworkStatus, FailureType,
    ConnectionMetrics, ReconnectionConfig
)
from discovery import (
    AdvancedLoadBalancer, LoadBalanceAlgorithm, VPNServer, ServerStatus,
    FailoverManager, FailoverTrigger
)
from integrations.openvpn_integration import OpenVPNClient
from integrations.wireguard_integration import WireGuardClient
from utils.logger import LoggableMixin
from utils.config_loader import Config


class VPNProtocol(Enum):
    """Supported VPN protocols."""
    OPENVPN = auto()
    WIREGUARD = auto()
    AUTO = auto()


@dataclass
class ConnectionConfig:
    """Connection configuration."""
    protocol: VPNProtocol = VPNProtocol.AUTO
    preferred_servers: List[str] = field(default_factory=list)
    excluded_servers: List[str] = field(default_factory=list)
    client_id: str = "default"
    client_location: Optional[tuple] = None
    auto_reconnect: bool = True
    server_switching: bool = True
    quality_threshold: float = 0.3
    max_reconnect_attempts: int = 5
    connection_timeout: float = 30.0
    keepalive_enabled: bool = True
    keepalive_interval: float = 30.0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConnectionConfig':
        """Create from dictionary."""
        protocol_map = {
            'openvpn': VPNProtocol.OPENVPN,
            'wireguard': VPNProtocol.WIREGUARD,
            'auto': VPNProtocol.AUTO
        }
        
        config = cls()
        
        if 'protocol' in data:
            config.protocol = protocol_map.get(data['protocol'].lower(), VPNProtocol.AUTO)
        
        if 'preferred_servers' in data:
            config.preferred_servers = data['preferred_servers']
        
        if 'excluded_servers' in data:
            config.excluded_servers = data['excluded_servers']
        
        if 'client_id' in data:
            config.client_id = data['client_id']
        
        if 'client_location' in data:
            config.client_location = tuple(data['client_location'])
        
        if 'auto_reconnect' in data:
            config.auto_reconnect = data['auto_reconnect']
        
        if 'server_switching' in data:
            config.server_switching = data['server_switching']
        
        if 'quality_threshold' in data:
            config.quality_threshold = data['quality_threshold']
        
        if 'max_reconnect_attempts' in data:
            config.max_reconnect_attempts = data['max_reconnect_attempts']
        
        if 'connection_timeout' in data:
            config.connection_timeout = data['connection_timeout']
        
        if 'keepalive_enabled' in data:
            config.keepalive_enabled = data['keepalive_enabled']
        
        if 'keepalive_interval' in data:
            config.keepalive_interval = data['keepalive_interval']
        
        return config


@dataclass
class ConnectionInfo:
    """Connection information."""
    connection_id: str
    server: VPNServer
    protocol: VPNProtocol
    client_instance: Any  # OpenVPNClient or WireGuardClient
    start_time: float
    last_activity: float
    bytes_sent: int = 0
    bytes_received: int = 0
    uptime: float = 0.0
    quality_score: float = 0.0
    
    def update_uptime(self):
        """Update uptime based on current time."""
        if self.start_time > 0:
            self.uptime = time.time() - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'connection_id': self.connection_id,
            'server_id': self.server.server_id,
            'server_hostname': self.server.hostname,
            'protocol': self.protocol.name,
            'start_time': self.start_time,
            'last_activity': self.last_activity,
            'uptime': self.uptime,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'quality_score': self.quality_score
        }


class EnhancedConnectionManager(LoggableMixin):
    """Enhanced connection manager with resilience features."""
    
    def __init__(self, config_path: str = "config/vpn_config.json"):
        self.config_path = config_path
        self.config = Config(config_path).to_dict()
        
        # Initialize components
        self._initialize_components()
        
        # Connection state
        self.current_connection: Optional[ConnectionInfo] = None
        self.connection_history: List[ConnectionInfo] = []
        self.connection_config = ConnectionConfig.from_dict(self.config.get('connection', {}))
        
        # Event callbacks
        self.event_callbacks: Dict[str, List[Callable]] = {
            'connection_established': [],
            'connection_lost': [],
            'reconnection_started': [],
            'reconnection_completed': [],
            'server_switched': [],
            'quality_degraded': [],
            'network_changed': []
        }
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'reconnections': 0,
            'server_switches': 0,
            'total_uptime': 0.0,
            'total_bytes_transferred': 0,
            'average_quality_score': 0.0
        }
        
        # Background tasks
        self.monitor_thread = None
        self.running = False
        
        self.logger.info("Enhanced connection manager initialized")
    
    def _initialize_components(self):
        """Initialize required components."""
        try:
            # Initialize load balancer
            from discovery.server_registry import ServerRegistry
            from discovery.health_checker import HealthChecker
            
            registry = ServerRegistry(self.config)
            health_checker = HealthChecker(self.config, registry)
            self.load_balancer = AdvancedLoadBalancer(self.config, registry, health_checker)
            self.failover_manager = FailoverManager(self.config, registry, health_checker, self.load_balancer)
            
            # Initialize connection resilience manager
            self.resilience_manager = ConnectionResilienceManager(
                self.config, self.load_balancer, self.failover_manager
            )
            
            # Set up resilience callbacks
            self._setup_resilience_callbacks()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _setup_resilience_callbacks(self):
        """Set up resilience manager callbacks."""
        def on_connected(data):
            self._handle_connection_established(data)
        
        def on_disconnected(data):
            self._handle_connection_lost(data)
        
        def on_reconnecting(data):
            self._handle_reconnection_started(data)
        
        def on_server_switched(data):
            self._handle_server_switched(data)
        
        def on_quality_degraded(data):
            self._handle_quality_degraded(data)
        
        def on_network_changed(data):
            self._handle_network_changed(data)
        
        # Register callbacks
        self.resilience_manager.add_connection_callback('connected', on_connected)
        self.resilience_manager.add_connection_callback('disconnected', on_disconnected)
        self.resilience_manager.add_connection_callback('reconnecting', on_reconnecting)
        self.resilience_manager.add_connection_callback('server_switched', on_server_switched)
        self.resilience_manager.add_connection_callback('quality_degraded', on_quality_degraded)
        self.resilience_manager.add_connection_callback('network_changed', on_network_changed)
    
    def connect(self, config: Optional[ConnectionConfig] = None) -> bool:
        """Establish VPN connection with resilience support."""
        try:
            # Update connection config if provided
            if config:
                self.connection_config = config
            
            # Check if already connected
            if self.current_connection and self.resilience_manager.connection_state == ConnectionState.CONNECTED:
                self.logger.warning("Already connected")
                return True
            
            self.logger.info(f"Starting VPN connection with {self.connection_config.protocol.name} protocol")
            
            # Select optimal server
            server = self._select_server()
            if not server:
                self.logger.error("No suitable server available")
                return False
            
            # Determine protocol
            protocol = self._determine_protocol(server)
            
            # Create VPN client
            client = self._create_vpn_client(protocol)
            if not client:
                self.logger.error(f"Failed to create {protocol.name} client")
                return False
            
            # Establish connection through resilience manager
            success = self.resilience_manager.connect(
                server, 
                self.connection_config.client_id,
                self.connection_config.client_location
            )
            
            if success:
                # Create connection info
                connection_id = f"conn_{int(time.time())}_{server.server_id}"
                
                self.current_connection = ConnectionInfo(
                    connection_id=connection_id,
                    server=server,
                    protocol=protocol,
                    client_instance=client,
                    start_time=time.time(),
                    last_activity=time.time()
                )
                
                # Update statistics
                self.stats['total_connections'] += 1
                self.stats['successful_connections'] += 1
                
                # Start monitoring
                if not self.running:
                    self._start_monitoring()
                
                self.logger.info(f"VPN connection established: {connection_id}")
                return True
            else:
                self.stats['total_connections'] += 1
                self.stats['failed_connections'] += 1
                self.logger.error("VPN connection failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.stats['total_connections'] += 1
            self.stats['failed_connections'] += 1
            return False
    
    def _select_server(self) -> Optional[VPNServer]:
        """Select optimal server based on configuration."""
        try:
            exclude_servers = set(self.connection_config.excluded_servers)
            
            # If preferred servers are specified, try them first
            if self.connection_config.preferred_servers:
                for server_id in self.connection_config.preferred_servers:
                    server = self.load_balancer.server_weights.get(server_id)
                    if server and server_id not in exclude_servers:
                        return self.load_balancer.registry.get_server(server_id)
            
            # Use load balancer to select optimal server
            server = self.load_balancer.select_server(
                client_id=self.connection_config.client_id,
                client_location=self.connection_config.client_location,
                exclude_servers=exclude_servers,
                algorithm=LoadBalanceAlgorithm.HEALTH_AWARE
            )
            
            return server
            
        except Exception as e:
            self.logger.error(f"Failed to select server: {e}")
            return None
    
    def _determine_protocol(self, server: VPNServer) -> VPNProtocol:
        """Determine which protocol to use."""
        try:
            if self.connection_config.protocol == VPNProtocol.AUTO:
                if server.protocol == 'both':
                    # Prefer OpenVPN for compatibility
                    return VPNProtocol.OPENVPN
                elif server.protocol == 'openvpn':
                    return VPNProtocol.OPENVPN
                elif server.protocol == 'wireguard':
                    return VPNProtocol.WIREGUARD
                else:
                    return VPNProtocol.OPENVPN  # Default
            else:
                return self.connection_config.protocol
                
        except Exception as e:
            self.logger.error(f"Failed to determine protocol: {e}")
            return VPNProtocol.OPENVPN
    
    def _create_vpn_client(self, protocol: VPNProtocol) -> Optional[Any]:
        """Create VPN client instance."""
        try:
            if protocol == VPNProtocol.OPENVPN:
                return OpenVPNClient(self.config)
            elif protocol == VPNProtocol.WIREGUARD:
                return WireGuardClient(self.config)
            else:
                self.logger.error(f"Unsupported protocol: {protocol}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to create VPN client: {e}")
            return None
    
    def disconnect(self, reason: str = "manual") -> bool:
        """Disconnect from VPN."""
        try:
            if not self.current_connection:
                self.logger.warning("No active connection")
                return True
            
            self.logger.info(f"Disconnecting VPN: {reason}")
            
            # Disconnect through resilience manager
            self.resilience_manager.disconnect(reason)
            
            # Update connection info
            if self.current_connection:
                self.current_connection.update_uptime()
                self.connection_history.append(self.current_connection)
                self.current_connection = None
            
            # Trigger event
            self._trigger_event('connection_lost', {'reason': reason})
            
            self.logger.info("VPN disconnected")
            return True
            
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
            return False
    
    def send_data(self, data: bytes) -> bool:
        """Send data through VPN connection."""
        try:
            if not self.current_connection or self.resilience_manager.connection_state != ConnectionState.CONNECTED:
                self.logger.error("No active connection")
                return False
            
            # Send data through VPN client
            client = self.current_connection.client_instance
            
            if hasattr(client, 'send_data'):
                success = client.send_data(data)
                if success:
                    self.current_connection.bytes_sent += len(data)
                    self.current_connection.last_activity = time.time()
                    self.stats['total_bytes_transferred'] += len(data)
                
                return success
            else:
                self.logger.error("VPN client does not support data sending")
                return False
                
        except Exception as e:
            self.logger.error(f"Send data error: {e}")
            return False
    
    def receive_data(self, buffer_size: int = 4096) -> Optional[bytes]:
        """Receive data from VPN connection."""
        try:
            if not self.current_connection or self.resilience_manager.connection_state != ConnectionState.CONNECTED:
                return None
            
            # Receive data from VPN client
            client = self.current_connection.client_instance
            
            if hasattr(client, 'receive_data'):
                data = client.receive_data(buffer_size)
                if data:
                    self.current_connection.bytes_received += len(data)
                    self.current_connection.last_activity = time.time()
                    self.stats['total_bytes_transferred'] += len(data)
                
                return data
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Receive data error: {e}")
            return None
    
    def switch_server(self, server_id: Optional[str] = None) -> bool:
        """Switch to a different server."""
        try:
            if not self.current_connection:
                self.logger.error("No active connection to switch from")
                return False
            
            self.logger.info("Initiating server switch")
            
            # Select new server
            if server_id:
                new_server = self.load_balancer.registry.get_server(server_id)
                if not new_server:
                    self.logger.error(f"Server {server_id} not found")
                    return False
            else:
                # Select optimal server excluding current
                exclude_servers = {self.current_connection.server.server_id}
                new_server = self.load_balancer.select_server(
                    client_id=self.connection_config.client_id,
                    client_location=self.connection_config.client_location,
                    exclude_servers=exclude_servers
                )
                
                if not new_server:
                    self.logger.error("No alternative server available")
                    return False
            
            # Disconnect from current server
            old_server_id = self.current_connection.server.server_id
            self.disconnect("server_switch")
            
            # Update preferred servers
            if server_id and server_id not in self.connection_config.preferred_servers:
                self.connection_config.preferred_servers.insert(0, server_id)
            
            # Connect to new server
            success = self.connect()
            
            if success:
                self.stats['server_switches'] += 1
                self.logger.info(f"Successfully switched from {old_server_id} to {new_server.server_id}")
                
                # Trigger event
                self._trigger_event('server_switched', {
                    'old_server_id': old_server_id,
                    'new_server_id': new_server.server_id
                })
                
                return True
            else:
                self.logger.error("Failed to connect to new server")
                return False
                
        except Exception as e:
            self.logger.error(f"Server switch error: {e}")
            return False
    
    def get_connection_info(self) -> Optional[Dict[str, Any]]:
        """Get current connection information."""
        try:
            if not self.current_connection:
                return None
            
            # Update uptime
            self.current_connection.update_uptime()
            
            # Get resilience status
            resilience_status = self.resilience_manager.get_connection_status()
            
            # Combine information
            connection_info = self.current_connection.to_dict()
            connection_info.update({
                'resilience_status': resilience_status,
                'config': {
                    'protocol': self.connection_config.protocol.name,
                    'auto_reconnect': self.connection_config.auto_reconnect,
                    'server_switching': self.connection_config.server_switching,
                    'quality_threshold': self.connection_config.quality_threshold
                }
            })
            
            return connection_info
            
        except Exception as e:
            self.logger.error(f"Failed to get connection info: {e}")
            return None
    
    def get_connection_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get connection history."""
        try:
            # Update uptimes
            for conn in self.connection_history:
                conn.update_uptime()
            
            # Return recent connections
            recent_connections = self.connection_history[-limit:]
            return [conn.to_dict() for conn in recent_connections]
            
        except Exception as e:
            self.logger.error(f"Failed to get connection history: {e}")
            return []
    
    def get_connection_statistics(self) -> Dict[str, Any]:
        """Get connection statistics."""
        try:
            # Update current connection uptime
            if self.current_connection:
                self.current_connection.update_uptime()
                self.stats['total_uptime'] += self.current_connection.uptime
            
            # Get resilience statistics
            resilience_stats = self.resilience_manager.get_connection_status()
            
            # Combine statistics
            combined_stats = self.stats.copy()
            combined_stats.update({
                'resilience_stats': resilience_stats,
                'current_uptime': self.current_connection.uptime if self.current_connection else 0,
                'connection_count': len(self.connection_history) + (1 if self.current_connection else 0),
                'preferred_servers': self.connection_config.preferred_servers,
                'excluded_servers': self.connection_config.excluded_servers
            })
            
            return combined_stats
            
        except Exception as e:
            self.logger.error(f"Failed to get connection statistics: {e}")
            return {}
    
    def update_connection_config(self, config: Dict[str, Any]):
        """Update connection configuration."""
        try:
            old_config = self.connection_config
            self.connection_config = ConnectionConfig.from_dict(config)
            
            self.logger.info("Connection configuration updated")
            
            # Apply changes if connected
            if self.current_connection and self.resilience_manager.connection_state == ConnectionState.CONNECTED:
                # Check if reconnection is needed
                if (old_config.quality_threshold != self.connection_config.quality_threshold or
                    old_config.auto_reconnect != self.connection_config.auto_reconnect):
                    
                    self.logger.info("Configuration change requires reconnection")
                    
                    if self.connection_config.auto_reconnect:
                        self.disconnect("config_update")
                        self.connect()
            
        except Exception as e:
            self.logger.error(f"Failed to update connection config: {e}")
    
    def add_event_callback(self, event_type: str, callback: Callable):
        """Add event callback."""
        if event_type not in self.event_callbacks:
            self.event_callbacks[event_type] = []
        
        self.event_callbacks[event_type].append(callback)
    
    def _trigger_event(self, event_type: str, data: Dict[str, Any]):
        """Trigger event callback."""
        try:
            for callback in self.event_callbacks.get(event_type, []):
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Event callback failed for {event_type}: {e}")
        except Exception as e:
            self.logger.error(f"Failed to trigger event: {e}")
    
    def _handle_connection_established(self, data):
        """Handle connection established event."""
        try:
            if self.current_connection:
                self.current_connection.quality_score = self.resilience_manager.current_quality_score
            
            self._trigger_event('connection_established', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle connection established: {e}")
    
    def _handle_connection_lost(self, data):
        """Handle connection lost event."""
        try:
            self._trigger_event('connection_lost', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle connection lost: {e}")
    
    def _handle_reconnection_started(self, data):
        """Handle reconnection started event."""
        try:
            self.stats['reconnections'] += 1
            self._trigger_event('reconnection_started', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle reconnection started: {e}")
    
    def _handle_reconnection_completed(self, data):
        """Handle reconnection completed event."""
        try:
            self._trigger_event('reconnection_completed', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle reconnection completed: {e}")
    
    def _handle_server_switched(self, data):
        """Handle server switched event."""
        try:
            self._trigger_event('server_switched', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle server switched: {e}")
    
    def _handle_quality_degraded(self, data):
        """Handle quality degraded event."""
        try:
            if self.current_connection:
                self.current_connection.quality_score = data.get('current_score', 0.0)
            
            self._trigger_event('quality_degraded', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle quality degraded: {e}")
    
    def _handle_network_changed(self, data):
        """Handle network changed event."""
        try:
            self._trigger_event('network_changed', data)
            
        except Exception as e:
            self.logger.error(f"Failed to handle network changed: {e}")
    
    def _start_monitoring(self):
        """Start background monitoring."""
        def monitoring_worker():
            while self.running:
                try:
                    # Update current connection info
                    if self.current_connection:
                        self.current_connection.update_uptime()
                        self.current_connection.quality_score = self.resilience_manager.current_quality_score
                    
                    time.sleep(10)  # Update every 10 seconds
                    
                except Exception as e:
                    self.logger.error(f"Connection monitoring error: {e}")
                    time.sleep(5)
        
        self.running = True
        self.monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Started connection monitoring")
    
    def stop(self):
        """Stop the connection manager."""
        try:
            self.running = False
            
            # Disconnect if connected
            if self.current_connection:
                self.disconnect("manager_stopped")
            
            # Stop resilience manager
            self.resilience_manager.stop()
            
            # Wait for monitoring thread
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
            
            self.logger.info("Enhanced connection manager stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop connection manager: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
