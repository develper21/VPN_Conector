"""
Tunnel Manager for the VPN Server

This module handles the management of VPN tunnels, including IP address allocation,
routing, and network interface configuration.
"""
import os
import sys
import time
import socket
import struct
import logging
import ipaddress
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass, field
from threading import Lock

from utils.logger import LoggableMixin
from utils.validator import (
    validate_ip_address, validate_netmask, validate_boolean,
    validate_integer, validate_string, validate_list
)

class TunnelError(Exception):
    """Base exception for tunnel-related errors."""
    pass

class IPAllocationError(TunnelError):
    """Raised when IP address allocation fails."""
    pass

class RoutingError(TunnelError):
    """Raised when a routing operation fails."""
    pass

@dataclass
class Tunnel(LoggableMixin):
    """Represents a VPN tunnel to a client."""
    client_id: str
    virtual_ip: str
    public_ip: str
    public_port: int
    last_active: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def update_activity(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update the tunnel's last activity time and byte counters."""
        self.last_active = time.time()
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received

class TunnelManager(LoggableMixin):
    """
    Manages VPN tunnels, IP address allocation, and routing.
    """
    
    def __init__(
        self,
        tunnel_network: str = "10.8.0.0",
        netmask: str = "255.255.255.0",
        dns_servers: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize the TunnelManager.
        
        Args:
            tunnel_network: The network address for the VPN tunnel.
            netmask: The network mask for the VPN tunnel.
            dns_servers: List of DNS servers to push to clients.
            **kwargs: Additional keyword arguments for LoggableMixin.
        """
        super().__init__(**kwargs)
        
        # Network configuration
        self.tunnel_network = ipaddress.IPv4Network(f"{tunnel_network}/{netmask}", strict=False)
        self.netmask = str(self.tunnel_network.netmask)
        self.gateway_ip = str(self.tunnel_network[1])  # First usable IP is the gateway
        
        # DNS configuration
        self.dns_servers = dns_servers or ["8.8.8.8", "8.8.4.4"]
        
        # Tunnel management
        self._tunnels: Dict[str, Tunnel] = {}
        self._ip_pool: Set[str] = set()
        self._allocated_ips: Set[str] = set()
        self._lock = Lock()
        
        # Initialize the IP pool
        self._init_ip_pool()
        
        # Platform-specific initialization
        self._platform_init()
        
        self.logger.info(f"TunnelManager initialized for network {self.tunnel_network}")
    
    def _platform_init(self) -> None:
        """Platform-specific initialization."""
        self.platform = sys.platform.lower()
        
        if self.platform.startswith('linux'):
            self._init_linux()
        elif self.platform.startswith('darwin'):
            self._init_macos()
        elif self.platform.startswith('win'):
            self._init_windows()
        else:
            self.logger.warning(f"Unsupported platform: {self.platform}")
    
    def _init_linux(self) -> None:
        """Linux-specific initialization."""
        self.tun_device = "tun0"
        self._check_command("ip", "iproute2 package is required")
        self._check_command("iptables", "iptables is required")
    
    def _init_macos(self) -> None:
        """macOS-specific initialization."""
        self.tun_device = "utun0"
        self._check_command("ifconfig", "ifconfig is required")
        self._check_command("route", "route command is required")
    
    def _init_windows(self) -> None:
        """Windows-specific initialization."""
        self.tun_device = "Ethernet"  # This is a placeholder
        # On Windows, we'll need to use netsh for network configuration
        self._check_command("netsh", "netsh is required")
    
    def _check_command(self, cmd: str, error_msg: str) -> None:
        """Check if a command is available."""
        try:
            subprocess.run(
                [cmd, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.warning(f"{error_msg} (command not found: {cmd})")
    
    def _init_ip_pool(self) -> None:
        """Initialize the pool of available IP addresses."""
        # Reserve the first few IPs (network, gateway, etc.)
        reserved_ips = {str(self.tunnel_network[0]),  # Network address
                       str(self.tunnel_network[1]),   # Gateway
                       str(self.tunnel_network[-1])}  # Broadcast
        
        # Add all other IPs to the pool
        self._ip_pool = {
            str(host) for host in self.tunnel_network.hosts()
            if str(host) not in reserved_ips
        }
        
        self.logger.debug(f"Initialized IP pool with {len(self._ip_pool)} addresses")
    
    def allocate_ip(self) -> Optional[str]:
        """
        Allocate an available IP address from the pool.
        
        Returns:
            An available IP address, or None if no addresses are available.
        """
        with self._lock:
            available_ips = self._ip_pool - self._allocated_ips
            
            if not available_ips:
                self.logger.error("No available IP addresses in the pool")
                return None
            
            # Get the first available IP
            ip = next(iter(available_ips))
            self._allocated_ips.add(ip)
            
            self.logger.debug(f"Allocated IP: {ip}")
            return ip
    
    def release_ip(self, ip: str) -> bool:
        """
        Release an IP address back to the pool.
        
        Args:
            ip: The IP address to release.
            
        Returns:
            True if the IP was successfully released, False otherwise.
        """
        with self._lock:
            if ip not in self._allocated_ips:
                self.logger.warning(f"Attempted to release unallocated IP: {ip}")
                return False
            
            self._allocated_ips.remove(ip)
            self.logger.debug(f"Released IP: {ip}")
            return True
    
    def create_tunnel(
        self,
        client_id: str,
        public_ip: str,
        public_port: int,
        virtual_ip: Optional[str] = None
    ) -> Tunnel:
        """
        Create a new tunnel for a client.
        
        Args:
            client_id: Unique identifier for the client.
            public_ip: The client's public IP address.
            public_port: The client's public port.
            virtual_ip: Optional specific virtual IP to assign.
            
        Returns:
            The created Tunnel object.
            
        Raises:
            IPAllocationError: If no IP address is available.
        """
        with self._lock:
            # Check if the client already has a tunnel
            if client_id in self._tunnels:
                return self._tunnels[client_id]
            
            # Allocate a virtual IP if not specified
            if virtual_ip is None:
                virtual_ip = self.allocate_ip()
                if virtual_ip is None:
                    raise IPAllocationError("No available IP addresses")
            else:
                # Validate the requested IP
                try:
                    ip_obj = ipaddress.IPv4Address(virtual_ip)
                    if ip_obj not in self.tunnel_network:
                        raise IPAllocationError(f"IP {virtual_ip} is not in the tunnel network")
                    
                    # Check if the IP is already allocated
                    if virtual_ip in self._allocated_ips:
                        raise IPAllocationError(f"IP {virtual_ip} is already allocated")
                    
                    self._allocated_ips.add(virtual_ip)
                except ipaddress.AddressValueError as e:
                    raise IPAllocationError(f"Invalid IP address: {virtual_ip}") from e
            
            # Create the tunnel
            tunnel = Tunnel(
                client_id=client_id,
                virtual_ip=virtual_ip,
                public_ip=public_ip,
                public_port=public_port
            )
            
            self._tunnels[client_id] = tunnel
            
            # Set up routing for this tunnel
            try:
                self._add_route(virtual_ip, public_ip, public_port)
            except Exception as e:
                # Clean up if routing fails
                del self._tunnels[client_id]
                self._allocated_ips.discard(virtual_ip)
                raise RoutingError(f"Failed to set up routing: {e}") from e
            
            self.logger.info(
                f"Created tunnel for {client_id}: "
                f"{virtual_ip} <-> {public_ip}:{public_port}"
            )
            
            return tunnel
    
    def remove_tunnel(self, client_id: str) -> bool:
        """
        Remove a tunnel and release its resources.
        
        Args:
            client_id: The ID of the client whose tunnel to remove.
            
        Returns:
            True if the tunnel was removed, False if it didn't exist.
        """
        with self._lock:
            if client_id not in self._tunnels:
                return False
            
            tunnel = self._tunnels[client_id]
            
            try:
                # Remove the route
                self._remove_route(tunnel.virtual_ip)
            except Exception as e:
                self.logger.error(f"Failed to remove route for {client_id}: {e}")
            
            # Release the IP address
            self.release_ip(tunnel.virtual_ip)
            
            # Remove the tunnel
            del self._tunnels[client_id]
            
            self.logger.info(f"Removed tunnel for {client_id}")
            return True
    
    def get_tunnel(self, client_id: str) -> Optional[Tunnel]:
        """
        Get a tunnel by client ID.
        
        Args:
            client_id: The ID of the client.
            
        Returns:
            The Tunnel object, or None if not found.
        """
        with self._lock:
            return self._tunnels.get(client_id)
    
    def get_tunnel_by_ip(self, ip: str) -> Optional[Tunnel]:
        """
        Get a tunnel by virtual IP address.
        
        Args:
            ip: The virtual IP address.
            
        Returns:
            The Tunnel object, or None if not found.
        """
        with self._lock:
            for tunnel in self._tunnels.values():
                if tunnel.virtual_ip == ip:
                    return tunnel
            return None
    
    def list_tunnels(self) -> List[Dict[str, Any]]:
        """
        Get information about all active tunnels.
        
        Returns:
            A list of dictionaries containing tunnel information.
        """
        with self._lock:
            return [
                {
                    'client_id': tunnel.client_id,
                    'virtual_ip': tunnel.virtual_ip,
                    'public_ip': tunnel.public_ip,
                    'public_port': tunnel.public_port,
                    'last_active': time.strftime(
                        '%Y-%m-%d %H:%M:%S',
                        time.localtime(tunnel.last_active)
                    ),
                    'bytes_sent': tunnel.bytes_sent,
                    'bytes_received': tunnel.bytes_received,
                    'uptime': int(time.time() - tunnel.last_active)
                }
                for tunnel in self._tunnels.values()
            ]
    
    def _add_route(self, virtual_ip: str, public_ip: str, public_port: int) -> None:
        """
        Add a route for a client's virtual IP.
        
        Args:
            virtual_ip: The client's virtual IP.
            public_ip: The client's public IP.
            public_port: The client's public port.
            
        Raises:
            RoutingError: If the route could not be added.
        """
        if self.platform.startswith('linux'):
            self._add_route_linux(virtual_ip, public_ip, public_port)
        elif self.platform.startswith('darwin'):
            self._add_route_macos(virtual_ip, public_ip, public_port)
        elif self.platform.startswith('win'):
            self._add_route_windows(virtual_ip, public_ip, public_port)
        else:
            self.logger.warning(f"Routing not supported on platform: {self.platform}")
    
    def _remove_route(self, virtual_ip: str) -> None:
        """
        Remove a route for a client's virtual IP.
        
        Args:
            virtual_ip: The client's virtual IP.
            
        Raises:
            RoutingError: If the route could not be removed.
        """
        if self.platform.startswith('linux'):
            self._remove_route_linux(virtual_ip)
        elif self.platform.startswith('darwin'):
            self._remove_route_macos(virtual_ip)
        elif self.platform.startswith('win'):
            self._remove_route_windows(virtual_ip)
        else:
            self.logger.warning(f"Routing not supported on platform: {self.platform}")
    
    # Platform-specific routing implementations
    
    def _add_route_linux(self, virtual_ip: str, public_ip: str, public_port: int) -> None:
        """Add a route on Linux using iproute2."""
        try:
            # Add the route
            subprocess.run(
                ["ip", "route", "add", virtual_ip, "via", self.gateway_ip],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Add NAT/masquerading
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", virtual_ip,
                 "-j", "MASQUERADE"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to add route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e
    
    def _remove_route_linux(self, virtual_ip: str) -> None:
        """Remove a route on Linux."""
        try:
            # Remove the route
            subprocess.run(
                ["ip", "route", "del", virtual_ip],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Remove NAT/masquerading
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", virtual_ip,
                 "-j", "MASQUERADE"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to remove route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e
    
    def _add_route_macos(self, virtual_ip: str, public_ip: str, public_port: int) -> None:
        """Add a route on macOS."""
        try:
            # Add the route
            subprocess.run(
                ["route", "-n", "add", "-host", virtual_ip, self.gateway_ip],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to add route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e
    
    def _remove_route_macos(self, virtual_ip: str) -> None:
        """Remove a route on macOS."""
        try:
            subprocess.run(
                ["route", "-n", "delete", "-host", virtual_ip],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to remove route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e
    
    def _add_route_windows(self, virtual_ip: str, public_ip: str, public_port: int) -> None:
        """Add a route on Windows."""
        try:
            # Add the route
            subprocess.run(
                ["route", "add", virtual_ip, "mask", "255.255.255.255", self.gateway_ip],
                check=True,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to add route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e
    
    def _remove_route_windows(self, virtual_ip: str) -> None:
        """Remove a route on Windows."""
        try:
            subprocess.run(
                ["route", "delete", virtual_ip],
                check=True,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            raise RoutingError(
                f"Failed to remove route for {virtual_ip}: {e.stderr.decode().strip()}"
            ) from e

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VPN Tunnel Manager")
    parser.add_argument("--network", default="10.8.0.0",
                       help="Tunnel network (e.g., 10.8.0.0/24)")
    parser.add_argument("--netmask", default="255.255.255.0",
                       help="Network mask")
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a tunnel manager
    manager = TunnelManager(
        tunnel_network=args.network,
        netmask=args.netmask
    )
    
    # Example: Allocate an IP
    ip = manager.allocate_ip()
    print(f"Allocated IP: {ip}")
    
    # Example: Create a tunnel
    try:
        tunnel = manager.create_tunnel(
            client_id="test-client",
            public_ip="203.0.113.1",
            public_port=12345,
            virtual_ip=ip
        )
        print(f"Created tunnel: {tunnel}")
        
        # List tunnels
        print("\nActive tunnels:")
        for t in manager.list_tunnels():
            print(f"- {t['client_id']}: {t['virtual_ip']} <-> {t['public_ip']}:{t['public_port']}")
        
        # Remove the tunnel
        print("\nRemoving tunnel...")
        manager.remove_tunnel("test-client")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
