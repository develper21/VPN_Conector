#!/usr/bin/env python3
"""
Split Tunneling Implementation for VPN
Allows selective routing of traffic through VPN or direct internet connection.
Supports both application-based and IP-based routing rules.
"""
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

from utils.logger import setup_logger


@dataclass
class RoutingRule:
    """Represents a routing rule for split tunneling."""
    name: str
    target: str  # IP range, domain, or application path
    route_via_vpn: bool
    rule_type: str  # 'ip', 'domain', 'application'
    priority: int = 100
    enabled: bool = True


class SplitTunnelingManager:
    """Manages split tunneling configuration and routing rules."""
    
    def __init__(self, config_path: str = "config/split_tunneling.json"):
        self.logger = setup_logger("split_tunneling", "INFO")
        self.config_path = Path(config_path)
        self.rules: List[RoutingRule] = []
        self.is_active = False
        self.monitoring_thread = None
        self.vpn_interface = None
        self.original_routes: Dict[str, str] = {}
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing configuration
        self.load_configuration()
        
    def load_configuration(self) -> None:
        """Load split tunneling configuration from file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    
                self.rules = []
                for rule_data in config.get('rules', []):
                    rule = RoutingRule(**rule_data)
                    self.rules.append(rule)
                    
                self.logger.info(f"Loaded {len(self.rules)} split tunneling rules")
            else:
                # Create default configuration
                self.create_default_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self.create_default_configuration()
    
    def create_default_configuration(self) -> None:
        """Create default split tunneling configuration."""
        default_rules = [
            RoutingRule(
                name="Local Network",
                target="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
                route_via_vpn=False,
                rule_type="ip",
                priority=10
            ),
            RoutingRule(
                name="Streaming Services",
                target="netflix.com,amazon.com,disney.com,hulu.com",
                route_via_vpn=True,
                rule_type="domain",
                priority=50
            ),
            RoutingRule(
                name="Banking Apps",
                target="/usr/bin/chrome,/usr/bin/firefox",
                route_via_vpn=False,
                rule_type="application",
                priority=20
            )
        ]
        
        self.rules = default_rules
        self.save_configuration()
        self.logger.info("Created default split tunneling configuration")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            config = {
                'rules': [
                    {
                        'name': rule.name,
                        'target': rule.target,
                        'route_via_vpn': rule.route_via_vpn,
                        'rule_type': rule.rule_type,
                        'priority': rule.priority,
                        'enabled': rule.enabled
                    }
                    for rule in self.rules
                ]
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
                
            self.logger.info("Configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def add_rule(self, rule: RoutingRule) -> bool:
        """Add a new routing rule."""
        try:
            # Check for duplicate names
            if any(r.name == rule.name for r in self.rules):
                self.logger.error(f"Rule with name '{rule.name}' already exists")
                return False
            
            self.rules.append(rule)
            self.rules.sort(key=lambda x: x.priority)
            self.save_configuration()
            
            if self.is_active:
                self.apply_rule(rule)
            
            self.logger.info(f"Added rule: {rule.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add rule: {e}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a routing rule by name."""
        try:
            rule_to_remove = None
            for rule in self.rules:
                if rule.name == rule_name:
                    rule_to_remove = rule
                    break
            
            if not rule_to_remove:
                self.logger.error(f"Rule '{rule_name}' not found")
                return False
            
            self.rules.remove(rule_to_remove)
            self.save_configuration()
            
            if self.is_active:
                self.remove_rule_routes(rule_to_remove)
            
            self.logger.info(f"Removed rule: {rule_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove rule: {e}")
            return False
    
    def activate(self, vpn_interface: str = "tun0") -> bool:
        """Activate split tunneling with specified VPN interface."""
        try:
            if self.is_active:
                self.logger.warning("Split tunneling is already active")
                return False
            
            self.vpn_interface = vpn_interface
            self.backup_original_routes()
            
            # Apply all enabled rules
            for rule in self.rules:
                if rule.enabled:
                    self.apply_rule(rule)
            
            # Start monitoring thread
            self.is_active = True
            self.monitoring_thread = threading.Thread(target=self._monitor_connections, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info(f"Split tunneling activated with interface {vpn_interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to activate split tunneling: {e}")
            return False
    
    def deactivate(self) -> bool:
        """Deactivate split tunneling and restore original routes."""
        try:
            if not self.is_active:
                self.logger.warning("Split tunneling is not active")
                return False
            
            self.is_active = False
            
            # Stop monitoring thread
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5)
            
            # Restore original routes
            self.restore_original_routes()
            
            self.logger.info("Split tunneling deactivated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate split tunneling: {e}")
            return False
    
    def apply_rule(self, rule: RoutingRule) -> None:
        """Apply a single routing rule."""
        try:
            if rule.rule_type == "ip":
                self._apply_ip_rule(rule)
            elif rule.rule_type == "domain":
                self._apply_domain_rule(rule)
            elif rule.rule_type == "application":
                self._apply_application_rule(rule)
            
            self.logger.debug(f"Applied rule: {rule.name}")
            
        except Exception as e:
            self.logger.error(f"Failed to apply rule {rule.name}: {e}")
    
    def _apply_ip_rule(self, rule: RoutingRule) -> None:
        """Apply IP-based routing rule."""
        targets = [t.strip() for t in rule.target.split(',')]
        
        for target in targets:
            try:
                # Validate IP range
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    target_ip = str(network.network_address)
                    netmask = str(network.netmask)
                else:
                    target_ip = target
                    netmask = "255.255.255.255"
                
                if rule.route_via_vpn:
                    # Route through VPN
                    cmd = [
                        "ip", "route", "add", target_ip,
                        "dev", self.vpn_interface
                    ]
                    if '/' in target:
                        cmd[3:3] = [target]  # Replace with full CIDR
                else:
                    # Route through default gateway (bypass VPN)
                    cmd = [
                        "ip", "route", "add", target,
                        "via", self._get_default_gateway()
                    ]
                
                subprocess.run(cmd, check=True, capture_output=True)
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to apply IP rule for {target}: {e}")
            except ValueError as e:
                self.logger.error(f"Invalid IP target {target}: {e}")
    
    def _apply_domain_rule(self, rule: RoutingRule) -> None:
        """Apply domain-based routing rule by resolving to IPs."""
        domains = [d.strip() for d in rule.target.split(',')]
        
        for domain in domains:
            try:
                # Resolve domain to IP addresses
                import socket
                ips = socket.gethostbyname_ex(domain)[2]
                
                for ip in ips:
                    ip_rule = RoutingRule(
                        name=f"{rule.name}_{domain}_{ip}",
                        target=ip,
                        route_via_vpn=rule.route_via_vpn,
                        rule_type="ip",
                        priority=rule.priority
                    )
                    self._apply_ip_rule(ip_rule)
                
            except Exception as e:
                self.logger.error(f"Failed to resolve domain {domain}: {e}")
    
    def _apply_application_rule(self, rule: RoutingRule) -> None:
        """Apply application-based routing using cgroups."""
        apps = [a.strip() for a in rule.target.split(',')]
        
        for app_path in apps:
            try:
                if not os.path.exists(app_path):
                    self.logger.warning(f"Application not found: {app_path}")
                    continue
                
                # Create cgroup for application
                cgroup_path = f"/sys/fs/cgroup/net_cls/vpn_split_{rule.name}"
                os.makedirs(cgroup_path, exist_ok=True)
                
                # Set class ID for routing
                class_id = hash(rule.name) % 0xFFFF
                with open(f"{cgroup_path}/net_cls.classid", 'w') as f:
                    f.write(f"0x{class_id:04x}")
                
                # Add application to cgroup (would need to be done when app starts)
                self.logger.debug(f"Configured application rule for {app_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to apply application rule for {app_path}: {e}")
    
    def _get_default_gateway(self) -> str:
        """Get the default gateway IP."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                check=True, capture_output=True, text=True
            )
            output = result.stdout.strip()
            # Extract gateway IP from "default via X.X.X.X dev ..."
            for part in output.split():
                if part.replace('.', '').isdigit() and len(part.split('.')) == 4:
                    return part
            return "0.0.0.0"
        except Exception:
            return "0.0.0.0"
    
    def backup_original_routes(self) -> None:
        """Backup original routing table."""
        try:
            result = subprocess.run(
                ["ip", "route", "show"],
                check=True, capture_output=True, text=True
            )
            routes = result.stdout.strip().split('\n')
            
            for route in routes:
                if route and not route.startswith('default'):
                    self.original_routes[route] = route
            
            self.logger.debug(f"Backed up {len(self.original_routes)} routes")
            
        except Exception as e:
            self.logger.error(f"Failed to backup routes: {e}")
    
    def restore_original_routes(self) -> None:
        """Restore original routing table."""
        try:
            # Flush all routes except default
            subprocess.run(["ip", "route", "flush", "table", "main"], check=True)
            
            # Restore original routes
            for route in self.original_routes.values():
                subprocess.run(["ip", "route", "add"] + route.split(), check=True)
            
            self.logger.debug("Restored original routes")
            
        except Exception as e:
            self.logger.error(f"Failed to restore routes: {e}")
    
    def remove_rule_routes(self, rule: RoutingRule) -> None:
        """Remove routes associated with a specific rule."""
        try:
            if rule.rule_type == "ip":
                targets = [t.strip() for t in rule.target.split(',')]
                for target in targets:
                    subprocess.run(["ip", "route", "del", target], 
                                 check=False, capture_output=True)
            
            elif rule.rule_type == "domain":
                domains = [d.strip() for d in rule.target.split(',')]
                for domain in domains:
                    try:
                        import socket
                        ips = socket.gethostbyname_ex(domain)[2]
                        for ip in ips:
                            subprocess.run(["ip", "route", "del", ip], 
                                         check=False, capture_output=True)
                    except:
                        pass
            
        except Exception as e:
            self.logger.error(f"Failed to remove rule routes: {e}")
    
    def _monitor_connections(self) -> None:
        """Monitor network connections and apply rules dynamically."""
        while self.is_active:
            try:
                # Monitor application-based rules
                for rule in self.rules:
                    if rule.enabled and rule.rule_type == "application":
                        self._monitor_application(rule)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring: {e}")
                time.sleep(10)
    
    def _monitor_application(self, rule: RoutingRule) -> None:
        """Monitor specific applications and apply routing."""
        try:
            apps = [a.strip() for a in rule.target.split(',')]
            
            for app_path in apps:
                # Check if application is running
                result = subprocess.run(
                    ["pgrep", "-f", app_path],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0:
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        if pid:
                            self._apply_application_routing(pid, rule)
                
        except Exception as e:
            self.logger.debug(f"Error monitoring application: {e}")
    
    def _apply_application_routing(self, pid: str, rule: RoutingRule) -> None:
        """Apply routing to a specific process PID."""
        try:
            # This would require more complex implementation with network namespaces
            # For now, we'll just log the intent
            self.logger.debug(f"Would apply routing rule {rule.name} to PID {pid}")
            
        except Exception as e:
            self.logger.debug(f"Error applying routing to PID {pid}: {e}")
    
    def get_status(self) -> Dict:
        """Get current status of split tunneling."""
        return {
            'active': self.is_active,
            'vpn_interface': self.vpn_interface,
            'rules_count': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.enabled]),
            'rules': [
                {
                    'name': rule.name,
                    'type': rule.rule_type,
                    'target': rule.target,
                    'route_via_vpn': rule.route_via_vpn,
                    'enabled': rule.enabled
                }
                for rule in self.rules
            ]
        }


# Example usage and testing
if __name__ == "__main__":
    # Create split tunneling manager
    split_manager = SplitTunnelingManager()
    
    # Add a custom rule
    custom_rule = RoutingRule(
        name="Work Applications",
        target="slack.com,teams.microsoft.com",
        route_via_vpn=True,
        rule_type="domain",
        priority=30
    )
    
    split_manager.add_rule(custom_rule)
    
    # Print status
    status = split_manager.get_status()
    print("Split Tunneling Status:")
    print(json.dumps(status, indent=2))
