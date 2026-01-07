"""
Network interface implementation for the VPN Security Project.

This module provides the base NetworkInterface class that handles low-level
network operations for both client and server components.
"""
import socket
import errno
import select
import struct
import logging
import time
import os
import fcntl
import array
import platform
from typing import Optional, Tuple, List, Callable, Any, Dict, Union
from abc import ABC, abstractmethod

from utils.logger import LoggableMixin
from utils.validator import (
    validate_ip_address, validate_port, validate_protocol,
    validate_boolean, validate_integer, ValidationError
)

# Constants for TUN/TAP interface
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
DEFAULT_MTU = 1500
DEFAULT_READ_SIZE = 4096

class NetworkError(Exception):
    """Base exception for network-related errors."""
    pass

class NetworkInterface(LoggableMixin, ABC):
    """
    Abstract base class for network interfaces.
    
    This class provides common functionality for both TUN and TAP interfaces,
    as well as raw socket-based network communication.
    """
    
    def __init__(
        self,
        name: str = "vpn",
        mtu: int = DEFAULT_MTU,
        read_size: int = DEFAULT_READ_SIZE,
        **kwargs
    ):
        """
        Initialize the network interface.
        
        Args:
            name: Base name for the interface.
            mtu: Maximum Transmission Unit for the interface.
            read_size: Size of the read buffer.
            **kwargs: Additional arguments passed to LoggableMixin.
        """
        super().__init__(**kwargs)
        
        self.name = name
        self.mtu = validate_integer(mtu, min_value=68, max_value=65535)
        self.read_size = validate_integer(read_size, min_value=128, max_value=65535)
        
        self._fd: Optional[int] = None
        self._is_running = False
        self._read_buffer = bytearray()
        self._write_buffer = bytearray()
        self._callbacks: Dict[str, List[Callable[[bytes], None]]] = {
            'data': [],
            'error': [],
            'close': []
        }
    
    def __del__(self):
        """Ensure resources are cleaned up."""
        self.close()
    
    @property
    def is_open(self) -> bool:
        """Check if the interface is open."""
        return self._fd is not None
    
    @property
    def is_running(self) -> bool:
        """Check if the interface is running."""
        return self._is_running
    
    @abstractmethod
    def open(self) -> None:
        """
        Open the network interface.
        
        Raises:
            NetworkError: If the interface cannot be opened.
        """
        pass
    
    def close(self) -> None:
        """Close the network interface and clean up resources."""
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError as e:
                self.logger.error(f"Error closing interface: {e}")
            finally:
                self._fd = None
                self._is_running = False
                self._trigger_callbacks('close', b'')
    
    def start(self) -> None:
        """Start the network interface."""
        if not self.is_open:
            self.open()
        self._is_running = True
        self.logger.info(f"Started network interface: {self.name}")
    
    def stop(self) -> None:
        """Stop the network interface."""
        self._is_running = False
        self.close()
        self.logger.info(f"Stopped network interface: {self.name}")
    
    def read(self, size: Optional[int] = None) -> bytes:
        """
        Read data from the network interface.
        
        Args:
            size: Maximum number of bytes to read. If None, uses the default read size.
            
        Returns:
            The data read from the interface.
            
        Raises:
            NetworkError: If the interface is not open or an error occurs.
        """
        if not self.is_open:
            raise NetworkError("Interface is not open")
        
        if size is None:
            size = self.read_size
        else:
            size = validate_integer(size, min_value=1, max_value=65535)
        
        try:
            # If we have buffered data, return that first
            if self._read_buffer:
                data = bytes(self._read_buffer[:size])
                self._read_buffer = self._read_buffer[size:]
                return data
            
            # Otherwise, read from the interface
            data = os.read(self._fd, size)
            if not data:
                raise NetworkError("Interface closed")
                
            return data
        except OSError as e:
            raise NetworkError(f"Error reading from interface: {e}") from e
    
    def write(self, data: bytes) -> int:
        """
        Write data to the network interface.
        
        Args:
            data: The data to write.
            
        Returns:
            The number of bytes written.
            
        Raises:
            NetworkError: If the interface is not open or an error occurs.
        """
        if not self.is_open:
            raise NetworkError("Interface is not open")
        
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")
        
        try:
            return os.write(self._fd, data)
        except OSError as e:
            raise NetworkError(f"Error writing to interface: {e}") from e
    
    def process(self, timeout: float = 0.1) -> None:
        """
        Process incoming data.
        
        This method should be called in a loop to handle incoming data.
        
        Args:
            timeout: Maximum time to wait for data, in seconds.
        """
        if not self.is_open or not self.is_running:
            return
        
        try:
            # Check if there's data to read
            r, _, _ = select.select([self._fd], [], [], timeout)
            if not r:
                return
            
            # Read the data
            data = self.read()
            if data:
                self._trigger_callbacks('data', data)
                
        except (OSError, select.error) as e:
            self.logger.error(f"Error in process loop: {e}")
            self._trigger_callbacks('error', str(e).encode())
            self.stop()
    
    def add_callback(self, event: str, callback: Callable[[bytes], None]) -> None:
        """
        Add a callback for an event.
        
        Args:
            event: The event to listen for ('data', 'error', or 'close').
            callback: The callback function to call when the event occurs.
        """
        if event not in self._callbacks:
            raise ValueError(f"Unknown event: {event}")
        self._callbacks[event].append(callback)
    
    def remove_callback(self, event: str, callback: Callable[[bytes], None]) -> None:
        """
        Remove a callback for an event.
        
        Args:
            event: The event to remove the callback from.
            callback: The callback function to remove.
        """
        if event in self._callbacks:
            self._callbacks[event] = [cb for cb in self._callbacks[event] if cb != callback]
    
    def _trigger_callbacks(self, event: str, data: bytes) -> None:
        """Trigger all callbacks for an event."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                self.logger.error(f"Error in {event} callback: {e}")
    
    @staticmethod
    def _get_interface_index(name: str) -> int:
        """
        Get the interface index for a given interface name.
        
        Args:
            name: The name of the interface.
            
        Returns:
            The interface index.
            
        Raises:
            NetworkError: If the interface does not exist.
        """
        # This is a simple implementation that works on Linux
        if platform.system() != 'Linux':
            raise NetworkError("This operation is only supported on Linux")
        
        try:
            with open(f"/sys/class/net/{name}/ifindex", 'r') as f:
                return int(f.read().strip())
        except (IOError, ValueError) as e:
            raise NetworkError(f"Could not get interface index for {name}: {e}")
    
    @staticmethod
    def _get_interface_mac(name: str) -> str:
        """
        Get the MAC address of a network interface.
        
        Args:
            name: The name of the interface.
            
        Returns:
            The MAC address as a string in the format 'xx:xx:xx:xx:xx:xx'.
            
        Raises:
            NetworkError: If the MAC address cannot be retrieved.
        """
        # This works on Linux
        if platform.system() == 'Linux':
            try:
                with open(f"/sys/class/net/{name}/address", 'r') as f:
                    mac = f.read().strip()
                    if not mac:
                        raise NetworkError(f"Empty MAC address for interface {name}")
                    return mac
            except IOError as e:
                raise NetworkError(f"Could not get MAC address for {name}: {e}")
        
        # Fallback for other Unix-like systems
        try:
            # This requires the 'ifconfig' command
            import subprocess
            result = subprocess.run(
                ['ifconfig', name],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to find the MAC address
            import re
            match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
            if match:
                return match.group(0).lower()
            
            raise NetworkError(f"Could not parse MAC address from ifconfig output")
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise NetworkError(f"Failed to get MAC address using ifconfig: {e}")
    
    @staticmethod
    def _get_interface_ip(name: str) -> str:
        """
        Get the IP address of a network interface.
        
        Args:
            name: The name of the interface.
            
        Returns:
            The IP address as a string.
            
        Raises:
            NetworkError: If the IP address cannot be retrieved.
        """
        # This works on Linux
        if platform.system() == 'Linux':
            try:
                # Try to get IPv4 address first
                with open(f"/sys/class/net/{name}/address_family", 'r') as f:
                    if 'inet' not in f.read():
                        raise NetworkError(f"Interface {name} does not have an IPv4 address")
                
                # Get the IP address using ioctl
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # SIOCGIFADDR = 0x8915
                    ifreq = struct.pack('256s', name[:15].encode())
                    result = fcntl.ioctl(s.fileno(), 0x8915, ifreq)
                    ip = socket.inet_ntoa(result[20:24])
                    return ip
                finally:
                    s.close()
            except (IOError, OSError) as e:
                raise NetworkError(f"Could not get IP address for {name}: {e}")
        
        # Fallback for other Unix-like systems
        try:
            # This requires the 'ifconfig' command
            import subprocess
            result = subprocess.run(
                ['ifconfig', name, 'inet'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to find the IP address
            import re
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
            
            raise NetworkError(f"Could not parse IP address from ifconfig output")
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise NetworkError(f"Failed to get IP address using ifconfig: {e}")


class TunInterface(NetworkInterface):
    """
    A TUN (network layer) interface.
    
    TUN interfaces operate at the network layer (IP) and are used for routing.
    """
    
    def open(self) -> None:
        """Open the TUN interface."""
        if self.is_open:
            return
        
        try:
            # Open the TUN device
            self._fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # IFF_TUN: TUN device (no Ethernet headers)
            # IFF_NO_PI: Don't provide packet information
            ifr = struct.pack('16sH', self.name.encode(), IFF_TUN | IFF_NO_PI)
            
            # Set the interface name and flags
            ifs = fcntl.ioctl(self._fd, TUNSETIFF, ifr)
            
            # Get the actual interface name
            self.name = ifs[:16].decode().strip('\x00')
            
            # Set the MTU
            self._set_mtu()
            
            self.logger.debug(f"Opened TUN interface: {self.name}")
            
        except OSError as e:
            self.close()
            raise NetworkError(f"Failed to open TUN interface: {e}") from e
    
    def _set_mtu(self) -> None:
        """Set the MTU for the interface."""
        if not self.is_open:
            return
        
        if platform.system() == 'Linux':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # SIOCSIFMTU = 0x8922
                    ifr = struct.pack('16sH', self.name.encode(), self.mtu)
                    fcntl.ioctl(s.fileno(), 0x8922, ifr)
                finally:
                    s.close()
            except OSError as e:
                self.logger.warning(f"Failed to set MTU: {e}")


class TapInterface(NetworkInterface):
    """
    A TAP (link layer) interface.
    
    TAP interfaces operate at the link layer (Ethernet) and are used for bridging.
    """
    
    def open(self) -> None:
        """Open the TAP interface."""
        if self.is_open:
            return
        
        try:
            # Open the TAP device
            self._fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # IFF_TAP: TAP device (with Ethernet headers)
            # IFF_NO_PI: Don't provide packet information
            ifr = struct.pack('16sH', self.name.encode(), IFF_TAP | IFF_NO_PI)
            
            # Set the interface name and flags
            ifs = fcntl.ioctl(self._fd, TUNSETIFF, ifr)
            
            # Get the actual interface name
            self.name = ifs[:16].decode().strip('\x00')
            
            # Set the MTU
            self._set_mtu()
            
            self.logger.debug(f"Opened TAP interface: {self.name}")
            
        except OSError as e:
            self.close()
            raise NetworkError(f"Failed to open TAP interface: {e}") from e
    
    def _set_mtu(self) -> None:
        """Set the MTU for the interface."""
        if not self.is_open:
            return
        
        if platform.system() == 'Linux':
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # SIOCSIFMTU = 0x8922
                    ifr = struct.pack('16sH', self.name.encode(), self.mtu)
                    fcntl.ioctl(s.fileno(), 0x8922, ifr)
                finally:
                    s.close()
            except OSError as e:
                self.logger.warning(f"Failed to set MTU: {e}")


def create_interface(
    interface_type: str = "tun",
    name: str = "vpn",
    mtu: int = DEFAULT_MTU,
    **kwargs
) -> NetworkInterface:
    """
    Create a network interface of the specified type.
    
    Args:
        interface_type: The type of interface ('tun' or 'tap').
        name: The base name for the interface.
        mtu: The MTU for the interface.
        **kwargs: Additional arguments to pass to the interface constructor.
        
    Returns:
        A new NetworkInterface instance.
        
    Raises:
        ValueError: If the interface type is invalid.
    """
    if interface_type.lower() == 'tun':
        return TunInterface(name=name, mtu=mtu, **kwargs)
    elif interface_type.lower() == 'tap':
        return TapInterface(name=name, mtu=mtu, **kwargs)
    else:
        raise ValueError(f"Invalid interface type: {interface_type}")


class UDPSocket(LoggableMixin):
    """
    A simple UDP socket wrapper for the VPN.
    """
    
    def __init__(
        self,
        local_addr: Tuple[str, int] = ('0.0.0.0', 0),
        remote_addr: Optional[Tuple[str, int]] = None,
        **kwargs
    ):
        """
        Initialize the UDP socket.
        
        Args:
            local_addr: Local address to bind to (host, port).
            remote_addr: Optional remote address to connect to (host, port).
            **kwargs: Additional arguments passed to LoggableMixin.
        """
        super().__init__(**kwargs)
        
        self.local_addr = self._validate_address(local_addr)
        self.remote_addr = self._validate_address(remote_addr) if remote_addr else None
        
        self._socket: Optional[socket.socket] = None
        self._is_running = False
        self._callbacks: Dict[str, List[Callable[[bytes, Tuple[str, int]], None]]] = {
            'data': [],
            'error': [],
            'close': []
        }
    
    def __del__(self):
        """Ensure the socket is closed."""
        self.close()
    
    @property
    def is_open(self) -> bool:
        """Check if the socket is open."""
        return self._socket is not None
    
    @property
    def is_running(self) -> bool:
        """Check if the socket is running."""
        return self._is_running
    
    @staticmethod
    def _validate_address(addr: Tuple[str, int]) -> Tuple[str, int]:
        """
        Validate an address tuple.
        
        Args:
            addr: The address to validate (host, port).
            
        Returns:
            The validated address.
            
        Raises:
            ValueError: If the address is invalid.
        """
        if not isinstance(addr, (list, tuple)) or len(addr) != 2:
            raise ValueError("Address must be a (host, port) tuple")
        
        host, port = addr
        
        # Validate host
        if not isinstance(host, str):
            raise ValueError("Host must be a string")
        
        # Validate port
        try:
            port = int(port)
            if not (0 <= port <= 65535):
                raise ValueError("Port must be between 0 and 65535")
        except (ValueError, TypeError) as e:
            raise ValueError("Port must be an integer") from e
        
        return (host, port)
    
    def open(self) -> None:
        """Open the UDP socket."""
        if self.is_open:
            return
        
        try:
            # Create a UDP socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Allow address reuse
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to the local address
            self._socket.bind(self.local_addr)
            
            # If a remote address was provided, connect to it
            if self.remote_addr:
                self._socket.connect(self.remote_addr)
            
            # Set non-blocking mode
            self._socket.setblocking(False)
            
            self.logger.debug(f"Opened UDP socket on {self.local_addr}")
            
        except OSError as e:
            self.close()
            raise NetworkError(f"Failed to open UDP socket: {e}") from e
    
    def close(self) -> None:
        """Close the UDP socket."""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError as e:
                self.logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
                self._is_running = False
                self._trigger_callbacks('close', b'', ('', 0))
    
    def start(self) -> None:
        """Start the UDP socket."""
        if not self.is_open:
            self.open()
        self._is_running = True
        self.logger.info(f"Started UDP socket on {self.local_addr}")
    
    def stop(self) -> None:
        """Stop the UDP socket."""
        self._is_running = False
        self.close()
        self.logger.info("Stopped UDP socket")
    
    def get_native_socket(self) -> socket.socket:
        """Return the underlying Python socket instance."""
        if self._socket is None:
            raise NetworkError("Socket is not open")
        return self._socket
    
    def send(self, data: bytes, addr: Optional[Tuple[str, int]] = None) -> int:
        """
        Send data to a remote address.
        
        Args:
            data: The data to send.
            addr: The remote address to send to. If None, uses the connected address.
            
        Returns:
            The number of bytes sent.
            
        Raises:
            NetworkError: If the socket is not open or an error occurs.
        """
        if not self.is_open:
            raise NetworkError("Socket is not open")
        
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")
        
        try:
            if addr is not None:
                return self._socket.sendto(data, addr)
            else:
                if self.remote_addr is None:
                    raise NetworkError("No remote address specified and not connected")
                return self._socket.send(data)
        except OSError as e:
            raise NetworkError(f"Error sending data: {e}") from e
    
    def recv(self, bufsize: int = 4096) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data from the socket.
        
        Args:
            bufsize: Maximum amount of data to receive.
            
        Returns:
            A tuple of (data, address), where address is a (host, port) tuple.
            
        Raises:
            NetworkError: If the socket is not open or an error occurs.
        """
        if not self.is_open:
            raise NetworkError("Socket is not open")
        
        try:
            return self._socket.recvfrom(bufsize)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, 35):
                return b'', ('', 0)
            raise NetworkError(f"Error receiving data: {e}") from e
    
    def process(self, timeout: float = 0.1) -> None:
        """
        Process incoming data.
        
        This method should be called in a loop to handle incoming data.
        
        Args:
            timeout: Maximum time to wait for data, in seconds.
        """
        if not self.is_open or not self.is_running:
            return
        
        try:
            # Check if there's data to read
            r, _, _ = select.select([self._socket], [], [], timeout)
            if not r:
                return
            
            # Read the data
            data, addr = self.recv()
            if data:
                self._trigger_callbacks('data', data, addr)
                
        except (OSError, select.error) as e:
            self.logger.error(f"Error in process loop: {e}")
            self._trigger_callbacks('error', str(e).encode(), ('', 0))
            self.stop()
    
    def add_callback(self, event: str, callback: Callable[[bytes, Tuple[str, int]], None]) -> None:
        """
        Add a callback for an event.
        
        Args:
            event: The event to listen for ('data', 'error', or 'close').
            callback: The callback function to call when the event occurs.
        """
        if event not in self._callbacks:
            raise ValueError(f"Unknown event: {event}")
        self._callbacks[event].append(callback)
    
    def remove_callback(self, event: str, callback: Callable[[bytes, Tuple[str, int]], None]) -> None:
        """
        Remove a callback for an event.
        
        Args:
            event: The event to remove the callback from.
            callback: The callback function to remove.
        """
        if event in self._callbacks:
            self._callbacks[event] = [cb for cb in self._callbacks[event] if cb != callback]
    
    def _trigger_callbacks(self, event: str, data: bytes, addr: Tuple[str, int]) -> None:
        """Trigger all callbacks for an event."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data, addr)
            except Exception as e:
                self.logger.error(f"Error in {event} callback: {e}")


def create_udp_socket(
    local_addr: Tuple[str, int] = ('0.0.0.0', 0),
    remote_addr: Optional[Tuple[str, int]] = None,
    **kwargs
) -> UDPSocket:
    """
    Create a UDP socket.
    
    Args:
        local_addr: Local address to bind to (host, port).
        remote_addr: Optional remote address to connect to (host, port).
        **kwargs: Additional arguments to pass to the UDPSocket constructor.
        
    Returns:
        A new UDPSocket instance.
    """
    return UDPSocket(local_addr=local_addr, remote_addr=remote_addr, **kwargs)
