"""
VPN Client Package

This package contains the client-side implementation of the VPN, including the main client,
connection management, and authentication components.
"""

# Import key components to make them available at the package level
from .client import VPNClient
from .connection_manager import ConnectionManager
from .authentication import ClientAuthenticator

# Define what gets imported with 'from vpn_client import *'
__all__ = ['VPNClient', 'ConnectionManager', 'ClientAuthenticator']

# Package version
__version__ = '0.1.0'
