"""
VPN Server Package

This package contains the server-side implementation of the VPN, including:
- Server: Main server class that handles client connections
- TunnelManager: Manages VPN tunnels and routing
- AccessControl: Handles client authentication and authorization
"""

__version__ = '0.1.0'
__all__ = ['VPNServer', 'TunnelManager', 'AccessControl']

from .server import VPNServer
from .tunnel_manager import TunnelManager
from .access_control import AccessControl
