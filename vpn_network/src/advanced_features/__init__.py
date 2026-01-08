#!/usr/bin/env python3
"""
Advanced Features Package for VPN
Contains implementations of advanced VPN features including:
- Split Tunneling
- Kill Switch
- DNS Leak Protection
- Protocol Obfuscation
"""

from .split_tunneling import SplitTunnelingManager, RoutingRule
from .kill_switch import KillSwitch, KillSwitchConfig
from .dns_leak_protection import DNSLeakProtection, DNSConfig
from .protocol_obfuscation import ProtocolObfuscator, ObfuscationConfig

__all__ = [
    'SplitTunnelingManager',
    'RoutingRule',
    'KillSwitch',
    'KillSwitchConfig',
    'DNSLeakProtection',
    'DNSConfig',
    'ProtocolObfuscator',
    'ObfuscationConfig'
]

VERSION = "1.0.0"
