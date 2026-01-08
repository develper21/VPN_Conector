#!/usr/bin/env python3
"""
Kill Switch Implementation for VPN
Automatically blocks internet access when VPN connection is lost.
Uses iptables rules and network monitoring to ensure privacy.
"""
import json
import logging
import os
import signal
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import psutil

from utils.logger import setup_logger


@dataclass
class KillSwitchConfig:
    """Configuration for kill switch behavior."""
    enabled: bool = True
    block_all_internet: bool = True  # If True, blocks all internet when VPN down
    allowed_networks: List[str] = None  # Networks to always allow (LAN, etc.)
    allowed_applications: List[str] = None  # Apps that can bypass kill switch
    vpn_interface: str = "tun0"
    monitoring_interval: int = 5  # seconds
    auto_recovery: bool = True  # Attempt to reconnect VPN
    strict_mode: bool = False  # Block even local traffic if True
    
    def __post_init__(self):
        if self.allowed_networks is None:
            self.allowed_networks = [
                "192.168.0.0/16",
                "10.0.0.0/8", 
                "172.16.0.0/12",
                "127.0.0.0/8"
            ]
        if self.allowed_applications is None:
            self.allowed_applications = []


class KillSwitch:
    """Kill Switch implementation that blocks internet when VPN disconnects."""
    
    def __init__(self, config_path: str = "config/kill_switch.json"):
        self.logger = setup_logger("kill_switch", "INFO")
        self.config_path = Path(config_path)
        self.config = KillSwitchConfig()
        self.is_active = False
        self.is_vpn_connected = False
        self.monitoring_thread = None
        self.original_iptables_rules: List[str] = []
        self.blocked = False
        self.recovery_attempts = 0
        self.max_recovery_attempts = 5
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.load_configuration()
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def load_configuration(self) -> None:
        """Load kill switch configuration from file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Update config with loaded values
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                self.logger.info("Kill switch configuration loaded")
            else:
                self.save_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            config_data = {
                'enabled': self.config.enabled,
                'block_all_internet': self.config.block_all_internet,
                'allowed_networks': self.config.allowed_networks,
                'allowed_applications': self.config.allowed_applications,
                'vpn_interface': self.config.vpn_interface,
                'monitoring_interval': self.config.monitoring_interval,
                'auto_recovery': self.config.auto_recovery,
                'strict_mode': self.config.strict_mode
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
            self.logger.info("Configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def activate(self, vpn_interface: Optional[str] = None) -> bool:
        """Activate the kill switch."""
        try:
            if self.is_active:
                self.logger.warning("Kill switch is already active")
                return False
            
            if not self.config.enabled:
                self.logger.info("Kill switch is disabled in configuration")
                return False
            
            if vpn_interface:
                self.config.vpn_interface = vpn_interface
            
            # Backup current iptables rules
            self.backup_iptables_rules()
            
            # Set up kill switch rules
            self.setup_kill_switch_rules()
            
            # Start monitoring VPN connection
            self.is_active = True
            self.monitoring_thread = threading.Thread(target=self._monitor_vpn_connection, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info(f"Kill switch activated for interface {self.config.vpn_interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to activate kill switch: {e}")
            return False
    
    def deactivate(self) -> bool:
        """Deactivate the kill switch and restore original rules."""
        try:
            if not self.is_active:
                self.logger.warning("Kill switch is not active")
                return False
            
            self.is_active = False
            
            # Stop monitoring thread
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=10)
            
            # Restore original iptables rules
            self.restore_iptables_rules()
            
            self.logger.info("Kill switch deactivated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate kill switch: {e}")
            return False
    
    def backup_iptables_rules(self) -> None:
        """Backup current iptables rules."""
        try:
            # Backup current rules
            result = subprocess.run(
                ["iptables-save"],
                check=True, capture_output=True, text=True
            )
            self.original_iptables_rules = result.stdout.strip().split('\n')
            self.logger.debug("Backed up iptables rules")
            
        except Exception as e:
            self.logger.error(f"Failed to backup iptables rules: {e}")
    
    def restore_iptables_rules(self) -> None:
        """Restore original iptables rules."""
        try:
            # Flush all rules
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-X"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-X"], check=True)
            
            # Restore original rules if any
            if self.original_iptables_rules:
                process = subprocess.Popen(
                    ["iptables-restore"],
                    stdin=subprocess.PIPE,
                    text=True
                )
                process.communicate(input='\n'.join(self.original_iptables_rules))
            
            self.logger.debug("Restored iptables rules")
            
        except Exception as e:
            self.logger.error(f"Failed to restore iptables rules: {e}")
    
    def setup_kill_switch_rules(self) -> None:
        """Set up iptables rules for kill switch."""
        try:
            # Clear existing rules first
            subprocess.run(["iptables", "-F"], check=True)
            
            if self.config.block_all_internet:
                # Block all outgoing traffic by default
                subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
                
                # Allow traffic through VPN interface
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-o", self.config.vpn_interface, "-j", "ACCEPT"
                ], check=True)
                
                # Allow traffic to allowed networks
                for network in self.config.allowed_networks:
                    subprocess.run([
                        "iptables", "-A", "OUTPUT", "-d", network, "-j", "ACCEPT"
                    ], check=True)
                
                # Allow loopback traffic
                subprocess.run(["iptables", "-A", "OUTPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
                
                # Allow established and related connections
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
                ], check=True)
                
                # Allow DNS queries through VPN
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-o", self.config.vpn_interface, "-j", "ACCEPT"
                ], check=True)
                
                # Allow specific applications if configured
                for app in self.config.allowed_applications:
                    self._allow_application(app)
            
            if self.config.strict_mode:
                # Additional strict mode rules
                subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
                
                # Allow only essential local traffic
                subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
            
            self.logger.info("Kill switch iptables rules configured")
            
        except Exception as e:
            self.logger.error(f"Failed to setup kill switch rules: {e}")
            raise
    
    def _allow_application(self, app_path: str) -> None:
        """Allow specific application to bypass kill switch."""
        try:
            if os.path.exists(app_path):
                # Get the application's user/group
                stat_info = os.stat(app_path)
                uid = stat_info.st_uid
                gid = stat_info.st_gid
                
                # Allow traffic from this user/group
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "ACCEPT"
                ], check=True)
                
                self.logger.debug(f"Allowed application: {app_path}")
            else:
                self.logger.warning(f"Application not found: {app_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to allow application {app_path}: {e}")
    
    def _monitor_vpn_connection(self) -> None:
        """Monitor VPN connection and activate kill switch if disconnected."""
        while self.is_active:
            try:
                vpn_status = self.check_vpn_connection()
                
                if vpn_status and not self.is_vpn_connected:
                    # VPN reconnected
                    self.is_vpn_connected = True
                    self.blocked = False
                    self.recovery_attempts = 0
                    self.logger.info("VPN connection restored")
                    
                    # Remove block if it was active
                    if self.blocked:
                        self.remove_internet_block()
                
                elif not vpn_status and self.is_vpn_connected:
                    # VPN disconnected
                    self.is_vpn_connected = False
                    self.logger.warning("VPN connection lost - activating kill switch")
                    self.activate_internet_block()
                
                elif not vpn_status and not self.is_vpn_connected:
                    # VPN still disconnected
                    if self.config.auto_recovery and self.recovery_attempts < self.max_recovery_attempts:
                        self.attempt_vpn_recovery()
                
                time.sleep(self.config.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in VPN monitoring: {e}")
                time.sleep(10)
    
    def check_vpn_connection(self) -> bool:
        """Check if VPN connection is active."""
        try:
            # Check if VPN interface exists
            result = subprocess.run(
                ["ip", "link", "show", self.config.vpn_interface],
                capture_output=True
            )
            if result.returncode != 0:
                return False
            
            # Check if interface has IP address
            result = subprocess.run(
                ["ip", "addr", "show", self.config.vpn_interface],
                capture_output=True, text=True
            )
            if "inet " not in result.stdout:
                return False
            
            # Check if there's traffic through VPN
            result = subprocess.run(
                ["ip", "route", "show", "table", "main"],
                capture_output=True, text=True
            )
            if self.config.vpn_interface not in result.stdout:
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking VPN connection: {e}")
            return False
    
    def activate_internet_block(self) -> None:
        """Activate internet block."""
        try:
            if not self.blocked:
                self.blocked = True
                
                if self.config.block_all_internet:
                    # Block is already active through iptables default policy
                    pass
                else:
                    # Add specific block rules
                    subprocess.run([
                        "iptables", "-A", "OUTPUT", "-j", "DROP"
                    ], check=True)
                
                self.logger.warning("Internet access blocked by kill switch")
                
        except Exception as e:
            self.logger.error(f"Failed to activate internet block: {e}")
    
    def remove_internet_block(self) -> None:
        """Remove internet block."""
        try:
            if self.blocked:
                self.blocked = False
                
                if not self.config.block_all_internet:
                    # Remove specific block rules
                    subprocess.run([
                        "iptables", "-D", "OUTPUT", "-j", "DROP"
                    ], check=False)
                
                self.logger.info("Internet access restored")
                
        except Exception as e:
            self.logger.error(f"Failed to remove internet block: {e}")
    
    def attempt_vpn_recovery(self) -> None:
        """Attempt to recover VPN connection."""
        try:
            self.recovery_attempts += 1
            self.logger.info(f"Attempting VPN recovery (attempt {self.recovery_attempts}/{self.max_recovery_attempts})")
            
            # This would integrate with the VPN client to attempt reconnection
            # For now, we'll just log the attempt
            time.sleep(2)  # Brief delay before next check
            
        except Exception as e:
            self.logger.error(f"VPN recovery attempt failed: {e}")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, deactivating kill switch")
        self.deactivate()
    
    def get_status(self) -> Dict:
        """Get current status of kill switch."""
        return {
            'active': self.is_active,
            'vpn_connected': self.is_vpn_connected,
            'internet_blocked': self.blocked,
            'vpn_interface': self.config.vpn_interface,
            'recovery_attempts': self.recovery_attempts,
            'config': {
                'enabled': self.config.enabled,
                'block_all_internet': self.config.block_all_internet,
                'strict_mode': self.config.strict_mode,
                'auto_recovery': self.config.auto_recovery,
                'monitoring_interval': self.config.monitoring_interval
            }
        }
    
    def test_kill_switch(self) -> bool:
        """Test the kill switch functionality."""
        try:
            self.logger.info("Testing kill switch functionality...")
            
            # Simulate VPN disconnection
            original_status = self.is_vpn_connected
            self.is_vpn_connected = False
            
            # Check if internet gets blocked
            self.activate_internet_block()
            
            # Test connectivity to a non-allowed address
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                capture_output=True
            )
            
            # Restore original status
            self.is_vpn_connected = original_status
            self.remove_internet_block()
            
            if result.returncode != 0:
                self.logger.info("Kill switch test passed - internet was blocked")
                return True
            else:
                self.logger.warning("Kill switch test failed - internet was not blocked")
                return False
                
        except Exception as e:
            self.logger.error(f"Kill switch test failed: {e}")
            return False


# Example usage and testing
if __name__ == "__main__":
    # Create kill switch
    kill_switch = KillSwitch()
    
    # Print status
    status = kill_switch.get_status()
    print("Kill Switch Status:")
    print(json.dumps(status, indent=2))
    
    # Test functionality
    if kill_switch.test_kill_switch():
        print("Kill switch test: PASSED")
    else:
        print("Kill switch test: FAILED")
