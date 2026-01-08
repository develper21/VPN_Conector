"""
Server Discovery Module for VPN Security Project.
This module provides functionality to discover available VPN servers
using multiple methods including DNS, HTTP APIs, and direct probing.
"""
import os
import socket
import time
import json
import random
import asyncio
import aiohttp
import dns.resolver
import geoip2.database
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import LoggableMixin
from utils.validator import validate_ip_address, validate_port, validate_string


class DiscoveryMethod(Enum):
    """Server discovery methods."""
    DNS_LOOKUP = auto()
    HTTP_API = auto()
    DIRECT_PROBE = auto()
    MULTICAST_DISCOVERY = auto()
    PEER_TO_PEER = auto()


class ServerStatus(Enum):
    """Server status enumeration."""
    ONLINE = auto()
    OFFLINE = auto()
    MAINTENANCE = auto()
    OVERLOADED = auto()
    UNKNOWN = auto()


@dataclass
class VPNServer:
    """VPN server information."""
    server_id: str
    hostname: str
    ip_address: str
    port: int
    protocol: str  # "openvpn", "wireguard", "both"
    region: str
    country: str
    city: str
    latitude: float
    longitude: float
    load: float = 0.0  # 0.0 to 1.0
    status: ServerStatus = ServerStatus.UNKNOWN
    last_checked: float = 0.0
    response_time: float = 0.0  # in milliseconds
    bandwidth_mbps: float = 0.0
    max_clients: int = 100
    current_clients: int = 0
    supported_ciphers: List[str] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    public_key: Optional[str] = None  # For WireGuard
    certificate_fingerprint: Optional[str] = None  # For OpenVPN
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'server_id': self.server_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'port': self.port,
            'protocol': self.protocol,
            'region': self.region,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'load': self.load,
            'status': self.status.name,
            'last_checked': self.last_checked,
            'response_time': self.response_time,
            'bandwidth_mbps': self.bandwidth_mbps,
            'max_clients': self.max_clients,
            'current_clients': self.current_clients,
            'supported_ciphers': self.supported_ciphers,
            'features': self.features,
            'public_key': self.public_key,
            'certificate_fingerprint': self.certificate_fingerprint
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VPNServer':
        """Create from dictionary."""
        server = cls(
            server_id=data['server_id'],
            hostname=data['hostname'],
            ip_address=data['ip_address'],
            port=data['port'],
            protocol=data['protocol'],
            region=data['region'],
            country=data['country'],
            city=data['city'],
            latitude=data['latitude'],
            longitude=data['longitude']
        )
        
        # Update optional fields
        if 'load' in data:
            server.load = data['load']
        if 'status' in data:
            server.status = ServerStatus[data['status']]
        if 'last_checked' in data:
            server.last_checked = data['last_checked']
        if 'response_time' in data:
            server.response_time = data['response_time']
        if 'bandwidth_mbps' in data:
            server.bandwidth_mbps = data['bandwidth_mbps']
        if 'max_clients' in data:
            server.max_clients = data['max_clients']
        if 'current_clients' in data:
            server.current_clients = data['current_clients']
        if 'supported_ciphers' in data:
            server.supported_ciphers = data['supported_ciphers']
        if 'features' in data:
            server.features = data['features']
        if 'public_key' in data:
            server.public_key = data['public_key']
        if 'certificate_fingerprint' in data:
            server.certificate_fingerprint = data['certificate_fingerprint']
        
        return server


class ServerDiscovery(LoggableMixin):
    """Main server discovery class."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.discovery_config = config.get('discovery', {})
        
        # Discovery settings
        self.enabled_methods = self._parse_enabled_methods()
        self.discovery_interval = self.discovery_config.get('interval', 300)  # 5 minutes
        self.timeout = self.discovery_config.get('timeout', 10)
        self.max_concurrent_checks = self.discovery_config.get('max_concurrent', 50)
        
        # Geographic database
        self.geoip_db_path = self.discovery_config.get('geoip_db_path', 'data/GeoLite2-City.mmdb')
        self.geoip_reader = None
        self._init_geoip()
        
        # Known server lists
        self.dns_servers = self.discovery_config.get('dns_servers', [])
        self.api_endpoints = self.discovery_config.get('api_endpoints', [])
        self.static_servers = self.discovery_config.get('static_servers', [])
        
        # Discovery state
        self.discovered_servers: Dict[str, VPNServer] = {}
        self.last_discovery = 0.0
        self.discovery_stats = {
            'total_discoveries': 0,
            'successful_discoveries': 0,
            'failed_discoveries': 0,
            'last_discovery_time': 0.0,
            'average_discovery_time': 0.0
        }
    
    def _parse_enabled_methods(self) -> Set[DiscoveryMethod]:
        """Parse enabled discovery methods from config."""
        enabled = self.discovery_config.get('enabled_methods', ['dns_lookup', 'http_api'])
        method_map = {
            'dns_lookup': DiscoveryMethod.DNS_LOOKUP,
            'http_api': DiscoveryMethod.HTTP_API,
            'direct_probe': DiscoveryMethod.DIRECT_PROBE,
            'multicast_discovery': DiscoveryMethod.MULTICAST_DISCOVERY,
            'peer_to_peer': DiscoveryMethod.PEER_TO_PEER
        }
        
        return {method_map[method] for method in enabled if method in method_map}
    
    def _init_geoip(self):
        """Initialize GeoIP database."""
        try:
            if os.path.exists(self.geoip_db_path):
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                self.logger.info("GeoIP database loaded successfully")
            else:
                self.logger.warning(f"GeoIP database not found: {self.geoip_db_path}")
        except Exception as e:
            self.logger.error(f"Failed to load GeoIP database: {e}")
    
    async def discover_servers(self, force_refresh: bool = False) -> List[VPNServer]:
        """Discover available VPN servers using all enabled methods."""
        current_time = time.time()
        
        if not force_refresh and (current_time - self.last_discovery) < self.discovery_interval:
            self.logger.debug("Using cached server list")
            return list(self.discovered_servers.values())
        
        self.logger.info("Starting server discovery")
        start_time = time.time()
        
        discovered = []
        
        # Run all enabled discovery methods
        if DiscoveryMethod.DNS_LOOKUP in self.enabled_methods:
            discovered.extend(await self._discover_via_dns())
        
        if DiscoveryMethod.HTTP_API in self.enabled_methods:
            discovered.extend(await self._discover_via_api())
        
        if DiscoveryMethod.DIRECT_PROBE in self.enabled_methods:
            discovered.extend(await self._discover_via_probe())
        
        if DiscoveryMethod.MULTICAST_DISCOVERY in self.enabled_methods:
            discovered.extend(await self._discover_via_multicast())
        
        # Add static servers
        discovered.extend(self._get_static_servers())
        
        # Remove duplicates and update registry
        unique_servers = self._deduplicate_servers(discovered)
        self.discovered_servers = {server.server_id: server for server in unique_servers}
        
        # Update statistics
        discovery_time = time.time() - start_time
        self.discovery_stats['total_discoveries'] += 1
        self.discovery_stats['successful_discoveries'] = len(unique_servers)
        self.discovery_stats['last_discovery_time'] = current_time
        self.discovery_stats['average_discovery_time'] = (
            (self.discovery_stats['average_discovery_time'] * (self.discovery_stats['total_discoveries'] - 1) + discovery_time) /
            self.discovery_stats['total_discoveries']
        )
        
        self.last_discovery = current_time
        
        self.logger.info(f"Discovery completed: {len(unique_servers)} servers found in {discovery_time:.2f}s")
        
        return unique_servers
    
    async def _discover_via_dns(self) -> List[VPNServer]:
        """Discover servers via DNS lookup."""
        servers = []
        
        for dns_server in self.dns_servers:
            try:
                # Query DNS for VPN server records
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                
                # Look for SRV records
                try:
                    answers = resolver.resolve(f"_vpn._tcp.{dns_server}", "SRV")
                    for answer in answers:
                        hostname = str(answer.target).rstrip('.')
                        port = answer.port
                        
                        # Resolve hostname to IP
                        ip_address = socket.gethostbyname(hostname)
                        
                        # Get geo location
                        geo_info = self._get_geo_location(ip_address)
                        
                        server = VPNServer(
                            server_id=f"dns-{hostname}-{port}",
                            hostname=hostname,
                            ip_address=ip_address,
                            port=port,
                            protocol="both",
                            **geo_info
                        )
                        servers.append(server)
                        
                except dns.resolver.NXDOMAIN:
                    # Try A/AAAA records
                    try:
                        answers = resolver.resolve(dns_server, "A")
                        for answer in answers:
                            ip_address = str(answer)
                            geo_info = self._get_geo_location(ip_address)
                            
                            server = VPNServer(
                                server_id=f"dns-{dns_server}-{ip_address}",
                                hostname=dns_server,
                                ip_address=ip_address,
                                port=1194,  # Default OpenVPN port
                                protocol="both",
                                **geo_info
                            )
                            servers.append(server)
                    except:
                        pass
                        
            except Exception as e:
                self.logger.error(f"DNS discovery failed for {dns_server}: {e}")
        
        return servers
    
    async def _discover_via_api(self) -> List[VPNServer]:
        """Discover servers via HTTP API endpoints."""
        servers = []
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            tasks = []
            
            for endpoint in self.api_endpoints:
                task = self._fetch_api_endpoint(session, endpoint)
                tasks.append(task)
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, list):
                        servers.extend(result)
                    elif isinstance(result, Exception):
                        self.logger.error(f"API discovery failed: {result}")
        
        return servers
    
    async def _fetch_api_endpoint(self, session: aiohttp.ClientSession, endpoint: str) -> List[VPNServer]:
        """Fetch server list from API endpoint."""
        try:
            headers = {
                'User-Agent': 'VPN-Client/1.0',
                'Accept': 'application/json'
            }
            
            async with session.get(endpoint, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    servers = []
                    for server_data in data.get('servers', []):
                        try:
                            server = VPNServer.from_dict(server_data)
                            servers.append(server)
                        except Exception as e:
                            self.logger.error(f"Failed to parse server data: {e}")
                    
                    return servers
                else:
                    self.logger.error(f"API returned status {response.status}: {endpoint}")
                    
        except Exception as e:
            self.logger.error(f"API request failed: {e}")
        
        return []
    
    async def _discover_via_probe(self) -> List[VPNServer]:
        """Discover servers via direct probing of common ports."""
        servers = []
        
        # Common VPN server ports to probe
        common_ports = [1194, 443, 8080, 51820]  # OpenVPN, custom, WireGuard
        
        # Get local network range for probing
        local_ip = socket.gethostbyname(socket.gethostname())
        network_parts = local_ip.split('.')
        network_base = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}"
        
        # Probe common server IPs in local network
        probe_targets = []
        for i in range(1, 255):  # .1 to .254
            for port in common_ports:
                probe_targets.append((f"{network_base}.{i}", port))
        
        # Limit concurrent probes
        semaphore = asyncio.Semaphore(self.max_concurrent_checks)
        
        async def probe_single(target_ip: str, target_port: int) -> Optional[VPNServer]:
            async with semaphore:
                try:
                    # Try to connect to the port
                    future = asyncio.open_connection(target_ip, target_port)
                    reader, writer = await asyncio.wait_for(future, timeout=2.0)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    # Get geo location
                    geo_info = self._get_geo_location(target_ip)
                    
                    # Determine protocol based on port
                    protocol = "wireguard" if target_port == 51820 else "openvpn"
                    
                    server = VPNServer(
                        server_id=f"probe-{target_ip}-{target_port}",
                        hostname=target_ip,
                        ip_address=target_ip,
                        port=target_port,
                        protocol=protocol,
                        **geo_info
                    )
                    
                    return server
                    
                except:
                    return None
        
        # Run probes concurrently
        tasks = []
        for target_ip, target_port in probe_targets[:100]:  # Limit to 100 probes
            task = probe_single(target_ip, target_port)
            tasks.append(task)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, VPNServer):
                    servers.append(result)
        
        return servers
    
    async def _discover_via_multicast(self) -> List[VPNServer]:
        """Discover servers via multicast discovery."""
        servers = []
        
        try:
            # Create multicast socket
            multicast_group = '224.0.0.1'
            multicast_port = 5353  # mDNS-like port
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to multicast address
            sock.bind(('', multicast_port))
            
            # Join multicast group
            mreq = socket.inet_aton(multicast_group) + socket.inet_aton('0.0.0.0')
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Send discovery request
            discovery_msg = json.dumps({
                'type': 'vpn_discovery_request',
                'timestamp': time.time()
            }).encode()
            
            sock.sendto(discovery_msg, (multicast_group, multicast_port))
            
            # Listen for responses
            start_time = time.time()
            while time.time() - start_time < 5.0:  # 5 second timeout
                try:
                    data, addr = sock.recvfrom(1024)
                    
                    # Parse response
                    try:
                        response = json.loads(data.decode())
                        if response.get('type') == 'vpn_discovery_response':
                            
                            server_info = response.get('server_info', {})
                            geo_info = self._get_geo_location(addr[0])
                            
                            server = VPNServer(
                                server_id=f"multicast-{addr[0]}-{server_info.get('port', 1194)}",
                                hostname=server_info.get('hostname', addr[0]),
                                ip_address=addr[0],
                                port=server_info.get('port', 1194),
                                protocol=server_info.get('protocol', 'both'),
                                **geo_info
                            )
                            servers.append(server)
                            
                    except json.JSONDecodeError:
                        continue
                        
                except socket.timeout:
                    break
                except Exception as e:
                    self.logger.error(f"Multicast discovery error: {e}")
                    break
            
            sock.close()
            
        except Exception as e:
            self.logger.error(f"Multicast discovery failed: {e}")
        
        return servers
    
    def _get_static_servers(self) -> List[VPNServer]:
        """Get static server list from configuration."""
        servers = []
        
        for server_config in self.static_servers:
            try:
                geo_info = self._get_geo_location(server_config.get('ip_address', ''))
                
                server = VPNServer(
                    server_id=server_config['server_id'],
                    hostname=server_config['hostname'],
                    ip_address=server_config['ip_address'],
                    port=server_config['port'],
                    protocol=server_config.get('protocol', 'both'),
                    **geo_info
                )
                
                # Update additional fields
                if 'public_key' in server_config:
                    server.public_key = server_config['public_key']
                if 'certificate_fingerprint' in server_config:
                    server.certificate_fingerprint = server_config['certificate_fingerprint']
                if 'supported_ciphers' in server_config:
                    server.supported_ciphers = server_config['supported_ciphers']
                if 'features' in server_config:
                    server.features = server_config['features']
                
                servers.append(server)
                
            except Exception as e:
                self.logger.error(f"Failed to load static server: {e}")
        
        return servers
    
    def _get_geo_location(self, ip_address: str) -> Dict[str, Any]:
        """Get geographic location for IP address."""
        default_location = {
            'region': 'Unknown',
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0
        }
        
        if not ip_address or not self.geoip_reader:
            return default_location
        
        try:
            response = self.geoip_reader.city(ip_address)
            
            return {
                'region': response.continent.names.get('en', 'Unknown'),
                'country': response.country.names.get('en', 'Unknown'),
                'city': response.city.names.get('en', 'Unknown'),
                'latitude': float(response.location.latitude),
                'longitude': float(response.location.longitude)
            }
            
        except Exception:
            return default_location
    
    def _deduplicate_servers(self, servers: List[VPNServer]) -> List[VPNServer]:
        """Remove duplicate servers from the list."""
        seen = set()
        unique_servers = []
        
        for server in servers:
            # Create unique key based on IP and port
            key = (server.ip_address, server.port)
            
            if key not in seen:
                seen.add(key)
                unique_servers.append(server)
        
        return unique_servers
    
    def get_servers_by_region(self, region: str) -> List[VPNServer]:
        """Get servers in a specific region."""
        return [server for server in self.discovered_servers.values() 
                if server.region.lower() == region.lower()]
    
    def get_servers_by_protocol(self, protocol: str) -> List[VPNServer]:
        """Get servers supporting a specific protocol."""
        return [server for server in self.discovered_servers.values() 
                if server.protocol == protocol or server.protocol == 'both']
    
    def get_best_servers(self, count: int = 5, protocol: str = None) -> List[VPNServer]:
        """Get the best servers based on load and response time."""
        candidates = list(self.discovered_servers.values())
        
        if protocol:
            candidates = [s for s in candidates if s.protocol == protocol or s.protocol == 'both']
        
        # Filter by online status
        candidates = [s for s in candidates if s.status == ServerStatus.ONLINE]
        
        # Sort by load (ascending) and response time (ascending)
        candidates.sort(key=lambda s: (s.load, s.response_time))
        
        return candidates[:count]
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get discovery statistics."""
        return {
            **self.discovery_stats,
            'total_servers': len(self.discovered_servers),
            'online_servers': len([s for s in self.discovered_servers.values() if s.status == ServerStatus.ONLINE]),
            'offline_servers': len([s for s in self.discovered_servers.values() if s.status == ServerStatus.OFFLINE]),
            'enabled_methods': [method.name for method in self.enabled_methods],
            'last_discovery': self.last_discovery
        }
    
    def export_server_list(self, filepath: str):
        """Export server list to JSON file."""
        try:
            servers_data = [server.to_dict() for server in self.discovered_servers.values()]
            
            with open(filepath, 'w') as f:
                json.dump({
                    'export_time': time.time(),
                    'total_servers': len(servers_data),
                    'servers': servers_data
                }, f, indent=2)
            
            self.logger.info(f"Server list exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to export server list: {e}")
    
    def import_server_list(self, filepath: str) -> int:
        """Import server list from JSON file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            for server_data in data.get('servers', []):
                try:
                    server = VPNServer.from_dict(server_data)
                    self.discovered_servers[server.server_id] = server
                    imported_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to import server: {e}")
            
            self.logger.info(f"Imported {imported_count} servers from {filepath}")
            return imported_count
            
        except Exception as e:
            self.logger.error(f"Failed to import server list: {e}")
            return 0
