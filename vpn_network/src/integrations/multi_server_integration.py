"""
Multi-Server Discovery Integration for VPN Security Project.
This module integrates server discovery, registry, health checking, and load balancing
into a unified multi-server management system.
"""
import os
import time
import asyncio
import threading
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum, auto

from discovery import (
    ServerDiscovery, ServerRegistry, HealthChecker, GeographicLoadBalancer,
    VPNServer, ServerStatus, HealthStatus, LoadBalanceStrategy, ClientLocation
)
from integrations.openvpn_integration import OpenVPNClient, OpenVPNServer
from integrations.wireguard_integration import WireGuardClient, WireGuardServer
from utils.logger import LoggableMixin


class MultiServerMode(Enum):
    """Multi-server operation modes."""
    STANDALONE = auto()  # Single server mode
    CLUSTER = auto()     # Multi-server cluster
    DISTRIBUTED = auto()  # Distributed across regions
    HYBRID = auto()      # Mix of local and remote servers


@dataclass
class ServerConnection:
    """Server connection information."""
    server_id: str
    server: VPNServer
    client_type: str  # "openvpn" or "wireguard"
    client: Any  # OpenVPNClient or WireGuardClient instance
    connected: bool = False
    connection_time: float = 0.0
    last_activity: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'server_id': self.server_id,
            'server': self.server.to_dict(),
            'client_type': self.client_type,
            'connected': self.connected,
            'connection_time': self.connection_time,
            'last_activity': self.last_activity,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received
        }


class MultiServerManager(LoggableMixin):
    """Multi-server management system."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.multi_server_config = config.get('multi_server', {})
        
        # Initialize components
        self.server_discovery = ServerDiscovery(config)
        self.server_registry = ServerRegistry(config)
        self.health_checker = HealthChecker(config, self.server_registry)
        self.load_balancer = GeographicLoadBalancer(config, self.server_registry, self.health_checker)
        
        # Multi-server settings
        self.mode = MultiServerMode[
            self.multi_server_config.get('mode', 'standalone').upper()
        ]
        self.auto_discovery = self.multi_server_config.get('auto_discovery', True)
        self.auto_failover = self.multi_server_config.get('auto_failover', True)
        self.max_connections = self.multi_server_config.get('max_connections', 5)
        
        # Connection management
        self.connections: Dict[str, ServerConnection] = {}
        self.primary_server_id: Optional[str] = None
        self.failover_servers: List[str] = []
        
        # Client location (for geographic selection)
        self.client_location: Optional[ClientLocation] = None
        
        # Background tasks
        self.discovery_thread = None
        self.health_monitor_thread = None
        self.running = False
        
        # Callbacks
        self.server_connected_callbacks: List[Callable[[str], None]] = []
        self.server_disconnected_callbacks: List[Callable[[str], None]] = []
        self.failover_callbacks: List[Callable[[str, str], None]] = []
        
        # Statistics
        self.stats = {
            'total_discoveries': 0,
            'total_connections': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'failover_events': 0,
            'active_connections': 0,
            'average_connection_time': 0.0
        }
    
    def start(self):
        """Start multi-server management."""
        try:
            self.running = True
            
            # Detect client location
            self._detect_client_location()
            
            # Start health monitoring
            self.health_checker.start_monitoring()
            
            # Start auto-discovery if enabled
            if self.auto_discovery:
                self._start_discovery_thread()
            
            # Initial server discovery
            asyncio.run(self._initial_discovery())
            
            self.logger.info(f"Multi-server manager started in {self.mode.name} mode")
            
        except Exception as e:
            self.logger.error(f"Failed to start multi-server manager: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop multi-server management."""
        try:
            self.running = False
            
            # Disconnect all servers
            self.disconnect_all_servers()
            
            # Stop health monitoring
            self.health_checker.stop_monitoring()
            
            # Wait for threads to finish
            if self.discovery_thread and self.discovery_thread.is_alive():
                self.discovery_thread.join(timeout=10)
            
            if self.health_monitor_thread and self.health_monitor_thread.is_alive():
                self.health_monitor_thread.join(timeout=10)
            
            self.logger.info("Multi-server manager stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping multi-server manager: {e}")
    
    def _detect_client_location(self):
        """Detect client geographic location."""
        try:
            import socket
            
            # Get client's public IP
            client_ip = socket.gethostbyname(socket.gethostname())
            
            # If it's a private IP, use a public IP service
            if self._is_private_ip(client_ip):
                # For now, use a default location
                # In production, you'd use a service like ipinfo.io
                client_ip = "8.8.8.8"  # Google DNS as fallback
            
            self.client_location = ClientLocation.from_ip(client_ip)
            self.logger.info(f"Client location detected: {self.client_location.city}, {self.client_location.country}")
            
        except Exception as e:
            self.logger.warning(f"Failed to detect client location: {e}")
            self.client_location = ClientLocation(40.7128, -74.0060)  # New York default
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return True  # Assume private if can't determine
    
    def _start_discovery_thread(self):
        """Start background discovery thread."""
        def discovery_worker():
            while self.running:
                try:
                    asyncio.run(self.server_discovery.discover_servers(force_refresh=True))
                    self.stats['total_discoveries'] += 1
                    time.sleep(300)  # Discover every 5 minutes
                except Exception as e:
                    self.logger.error(f"Discovery thread error: {e}")
                    time.sleep(60)  # Retry in 1 minute
        
        self.discovery_thread = threading.Thread(target=discovery_worker, daemon=True)
        self.discovery_thread.start()
        self.logger.info("Started discovery thread")
    
    async def _initial_discovery(self):
        """Perform initial server discovery."""
        try:
            self.logger.info("Performing initial server discovery")
            
            discovered_servers = await self.server_discovery.discover_servers(force_refresh=True)
            
            # Register discovered servers
            for server in discovered_servers:
                self.server_registry.register_server(server)
            
            self.logger.info(f"Initial discovery completed: {len(discovered_servers)} servers found")
            
            # Select primary server if not set
            if not self.primary_server_id and discovered_servers:
                await self._select_primary_server()
            
        except Exception as e:
            self.logger.error(f"Initial discovery failed: {e}")
    
    async def _select_primary_server(self):
        """Select primary server based on load balancing."""
        try:
            # Get best servers
            best_servers = self.load_balancer.select_best_servers(
                client_location=self.client_location,
                count=1,
                strategy=LoadBalanceStrategy.GEOGRAPHIC
            )
            
            if best_servers:
                primary_server = best_servers[0].server
                self.primary_server_id = primary_server.server_id
                
                # Set up failover servers
                failover_candidates = self.load_balancer.select_best_servers(
                    client_location=self.client_location,
                    count=self.max_connections - 1,
                    exclude_servers=[self.primary_server_id]
                )
                
                self.failover_servers = [s.server_id for s in failover_candidates]
                
                self.logger.info(f"Selected primary server: {primary_server.hostname}")
                self.logger.info(f"Failover servers: {len(self.failover_servers)} available")
            
        except Exception as e:
            self.logger.error(f"Failed to select primary server: {e}")
    
    async def connect_to_servers(self, protocol: str = "auto", 
                               max_connections: int = None) -> List[str]:
        """Connect to best available servers."""
        try:
            max_connections = max_connections or self.max_connections
            
            # Get server recommendations
            recommendations = self.load_balancer.get_server_recommendations(
                client_location=self.client_location,
                protocol=protocol if protocol != "auto" else None,
                preferences={'count': max_connections}
            )
            
            connected_servers = []
            
            # Try to connect to recommended servers
            for category, server_scores in recommendations.items():
                for server_score in server_scores:
                    if len(connected_servers) >= max_connections:
                        break
                    
                    server_id = server_score.server_id
                    
                    if server_id not in self.connections:
                        success = await self._connect_to_server(server_id, protocol)
                        if success:
                            connected_servers.append(server_id)
                            
                            # Set primary if not set
                            if not self.primary_server_id:
                                self.primary_server_id = server_id
                                self.logger.info(f"Set primary server: {server_id}")
            
            self.logger.info(f"Connected to {len(connected_servers)} servers")
            return connected_servers
            
        except Exception as e:
            self.logger.error(f"Failed to connect to servers: {e}")
            return []
    
    async def _connect_to_server(self, server_id: str, protocol: str = "auto") -> bool:
        """Connect to a specific server."""
        try:
            server = self.server_registry.get_server(server_id)
            if not server:
                self.logger.error(f"Server not found: {server_id}")
                return False
            
            # Determine protocol
            if protocol == "auto":
                client_protocol = server.protocol
                if client_protocol == "both":
                    client_protocol = "openvpn"  # Default to OpenVPN
            else:
                client_protocol = protocol
            
            # Validate server supports protocol
            if server.protocol != "both" and server.protocol != client_protocol:
                self.logger.error(f"Server {server_id} doesn't support {client_protocol}")
                return False
            
            # Create client
            client = await self._create_client(client_protocol, server)
            if not client:
                return False
            
            # Connect to server
            success = await self._establish_connection(client, server, client_protocol)
            
            if success:
                # Create connection record
                connection = ServerConnection(
                    server_id=server_id,
                    server=server,
                    client_type=client_protocol,
                    client=client,
                    connected=True,
                    connection_time=time.time(),
                    last_activity=time.time()
                )
                
                self.connections[server_id] = connection
                
                # Update statistics
                self.stats['total_connections'] += 1
                self.stats['successful_connections'] += 1
                self.stats['active_connections'] += 1
                
                # Record connection attempt
                self.server_registry.record_connection_attempt(server_id, True)
                
                # Trigger callback
                for callback in self.server_connected_callbacks:
                    try:
                        callback(server_id)
                    except Exception as e:
                        self.logger.error(f"Server connected callback failed: {e}")
                
                self.logger.info(f"Connected to server {server_id} using {client_protocol}")
                return True
            else:
                self.stats['total_connections'] += 1
                self.stats['failed_connections'] += 1
                self.server_registry.record_connection_attempt(server_id, False, error="Connection failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to connect to server {server_id}: {e}")
            self.stats['total_connections'] += 1
            self.stats['failed_connections'] += 1
            self.server_registry.record_connection_attempt(server_id, False, error=str(e))
            return False
    
    async def _create_client(self, protocol: str, server: VPNServer) -> Optional[Any]:
        """Create VPN client for the specified protocol."""
        try:
            if protocol == "openvpn":
                client = OpenVPNClient(self.config)
                return client
            elif protocol == "wireguard":
                client = WireGuardClient(self.config)
                return client
            else:
                self.logger.error(f"Unsupported protocol: {protocol}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to create {protocol} client: {e}")
            return None
    
    async def _establish_connection(self, client: Any, server: VPNServer, 
                                  protocol: str) -> bool:
        """Establish connection to server."""
        try:
            if protocol == "openvpn":
                success = client.connect(server.ip_address, server.port)
            elif protocol == "wireguard":
                # For WireGuard, we need the server's public key
                if not server.public_key:
                    self.logger.error(f"WireGuard server {server.server_id} missing public key")
                    return False
                
                public_key = bytes.fromhex(server.public_key)
                success = client.connect(server.ip_address, server.port, public_key)
            else:
                return False
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to establish {protocol} connection: {e}")
            return False
    
    def disconnect_from_server(self, server_id: str) -> bool:
        """Disconnect from a specific server."""
        try:
            connection = self.connections.get(server_id)
            if not connection:
                self.logger.warning(f"No connection found for server {server_id}")
                return False
            
            # Disconnect client
            if hasattr(connection.client, 'disconnect'):
                connection.client.disconnect()
            elif hasattr(connection.client, 'stop'):
                connection.client.stop()
            
            # Remove connection
            del self.connections[server_id]
            
            # Update statistics
            self.stats['active_connections'] -= 1
            
            # Update primary server if needed
            if self.primary_server_id == server_id:
                self.primary_server_id = None
                if self.auto_failover and self.failover_servers:
                    self._trigger_failover(server_id)
            
            # Trigger callback
            for callback in self.server_disconnected_callbacks:
                try:
                    callback(server_id)
                except Exception as e:
                    self.logger.error(f"Server disconnected callback failed: {e}")
            
            self.logger.info(f"Disconnected from server {server_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to disconnect from server {server_id}: {e}")
            return False
    
    def disconnect_all_servers(self):
        """Disconnect from all servers."""
        server_ids = list(self.connections.keys())
        
        for server_id in server_ids:
            self.disconnect_from_server(server_id)
        
        self.logger.info("Disconnected from all servers")
    
    def _trigger_failover(self, failed_server_id: str):
        """Trigger failover to backup server."""
        try:
            self.logger.warning(f"Triggering failover from {failed_server_id}")
            
            # Find available failover server
            for failover_id in self.failover_servers:
                if failover_id not in self.connections and failover_id != failed_server_id:
                    # Connect to failover server
                    success = asyncio.run(self._connect_to_server(failover_id))
                    
                    if success:
                        self.primary_server_id = failover_id
                        self.stats['failover_events'] += 1
                        
                        # Trigger failover callback
                        for callback in self.failover_callbacks:
                            try:
                                callback(failed_server_id, failover_id)
                            except Exception as e:
                                self.logger.error(f"Failover callback failed: {e}")
                        
                        self.logger.info(f"Failover successful: {failed_server_id} -> {failover_id}")
                        return
                    else:
                        self.logger.error(f"Failed to connect to failover server {failover_id}")
            
            self.logger.error("No available failover servers")
            
        except Exception as e:
            self.logger.error(f"Failover failed: {e}")
    
    def send_data(self, data: bytes, server_id: Optional[str] = None) -> bool:
        """Send data through primary server or specific server."""
        try:
            target_server_id = server_id or self.primary_server_id
            
            if not target_server_id:
                self.logger.error("No server available for data transmission")
                return False
            
            connection = self.connections.get(target_server_id)
            if not connection or not connection.connected:
                self.logger.error(f"Server {target_server_id} not connected")
                return False
            
            # Send data through client
            if hasattr(connection.client, 'send_data'):
                success = connection.client.send_data(data)
            else:
                self.logger.error(f"Client for server {target_server_id} doesn't support data sending")
                return False
            
            if success:
                connection.bytes_sent += len(data)
                connection.last_activity = time.time()
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")
            return False
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get connection status for all servers."""
        connections_info = {}
        
        for server_id, connection in self.connections.items():
            connections_info[server_id] = connection.to_dict()
        
        return {
            'mode': self.mode.name,
            'primary_server_id': self.primary_server_id,
            'failover_servers': self.failover_servers,
            'active_connections': len(self.connections),
            'max_connections': self.max_connections,
            'client_location': {
                'city': self.client_location.city,
                'country': self.client_location.country,
                'latitude': self.client_location.latitude,
                'longitude': self.client_location.longitude
            } if self.client_location else None,
            'connections': connections_info,
            'stats': self.stats
        }
    
    def get_available_servers(self, protocol: Optional[str] = None) -> List[VPNServer]:
        """Get list of available servers."""
        return self.server_registry.get_servers_by_protocol(protocol) if protocol else self.server_registry.get_all_servers()
    
    def get_server_recommendations(self, protocol: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get server recommendations."""
        recommendations = self.load_balancer.get_server_recommendations(
            client_location=self.client_location,
            protocol=protocol
        )
        
        # Convert to dictionaries
        result = {}
        for category, server_scores in recommendations.items():
            result[category] = [score.to_dict() for score in server_scores]
        
        return result
    
    def add_server_connected_callback(self, callback: Callable[[str], None]):
        """Add callback for server connection events."""
        self.server_connected_callbacks.append(callback)
    
    def add_server_disconnected_callback(self, callback: Callable[[str], None]):
        """Add callback for server disconnection events."""
        self.server_disconnected_callbacks.append(callback)
    
    def add_failover_callback(self, callback: Callable[[str, str], None]):
        """Add callback for failover events."""
        self.failover_callbacks.append(callback)
    
    def get_multi_server_stats(self) -> Dict[str, Any]:
        """Get comprehensive multi-server statistics."""
        return {
            'multi_server_stats': self.stats,
            'discovery_stats': self.server_discovery.get_discovery_stats(),
            'registry_stats': self.server_registry.get_registry_stats(),
            'health_summary': self.health_checker.get_health_summary(),
            'load_balancer_stats': self.load_balancer.get_load_balancer_stats(),
            'connection_status': self.get_connection_status()
        }
