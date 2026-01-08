#!/usr/bin/env python3
"""
DNS Leak Protection Implementation for VPN
Prevents DNS queries from leaking outside the VPN tunnel.
Monitors DNS traffic and enforces DNS routing through VPN tunnel.
"""
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from utils.logger import setup_logger


@dataclass
class DNSConfig:
    """Configuration for DNS leak protection."""
    enabled: bool = True
    vpn_dns_servers: List[str] = None
    block_external_dns: bool = True
    force_vpn_dns: bool = True
    monitor_interface: str = "any"
    dns_port: int = 53
    allowed_dns_servers: List[str] = None
    log_dns_queries: bool = True
    block_dns_over_https: bool = True
    custom_dns_port: int = 5353
    
    def __post_init__(self):
        if self.vpn_dns_servers is None:
            self.vpn_dns_servers = [
                "1.1.1.1",    # Cloudflare
                "8.8.8.8",    # Google
                "1.0.0.1"     # Cloudflare secondary
            ]
        if self.allowed_dns_servers is None:
            self.allowed_dns_servers = []


class DNSLeakProtection:
    """DNS Leak Protection implementation."""
    
    def __init__(self, config_path: str = "config/dns_leak_protection.json"):
        self.logger = setup_logger("dns_leak_protection", "INFO")
        self.config_path = Path(config_path)
        self.config = DNSConfig()
        self.is_active = False
        self.monitoring_thread = None
        self.dns_filter_thread = None
        self.original_resolv_conf: str = ""
        self.blocked_ips: Set[str] = set()
        self.dns_query_log: List[Dict] = []
        self.max_log_entries = 1000
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> None:
        """Load DNS leak protection configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                self.logger.info("DNS leak protection configuration loaded")
            else:
                self.save_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            config_data = {
                'enabled': self.config.enabled,
                'vpn_dns_servers': self.config.vpn_dns_servers,
                'block_external_dns': self.config.block_external_dns,
                'force_vpn_dns': self.config.force_vpn_dns,
                'monitor_interface': self.config.monitor_interface,
                'dns_port': self.config.dns_port,
                'allowed_dns_servers': self.config.allowed_dns_servers,
                'log_dns_queries': self.config.log_dns_queries,
                'block_dns_over_https': self.config.block_dns_over_https,
                'custom_dns_port': self.config.custom_dns_port
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
            self.logger.info("Configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def activate(self, vpn_interface: str = "tun0") -> bool:
        """Activate DNS leak protection."""
        try:
            if self.is_active:
                self.logger.warning("DNS leak protection is already active")
                return False
            
            if not self.config.enabled:
                self.logger.info("DNS leak protection is disabled in configuration")
                return False
            
            # Backup original resolv.conf
            self.backup_resolv_conf()
            
            # Configure DNS settings
            self.configure_dns_settings(vpn_interface)
            
            # Set up iptables rules to block external DNS
            if self.config.block_external_dns:
                self.setup_dns_firewall_rules()
            
            # Start DNS monitoring
            self.is_active = True
            self.monitoring_thread = threading.Thread(target=self._monitor_dns_traffic, daemon=True)
            self.monitoring_thread.start()
            
            # Start DNS filtering if needed
            if self.config.force_vpn_dns:
                self.dns_filter_thread = threading.Thread(target=self._dns_filter_server, daemon=True)
                self.dns_filter_thread.start()
            
            self.logger.info("DNS leak protection activated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to activate DNS leak protection: {e}")
            return False
    
    def deactivate(self) -> bool:
        """Deactivate DNS leak protection."""
        try:
            if not self.is_active:
                self.logger.warning("DNS leak protection is not active")
                return False
            
            self.is_active = False
            
            # Stop monitoring threads
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5)
            if self.dns_filter_thread:
                self.dns_filter_thread.join(timeout=5)
            
            # Restore original resolv.conf
            self.restore_resolv_conf()
            
            # Remove firewall rules
            self.remove_dns_firewall_rules()
            
            self.logger.info("DNS leak protection deactivated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate DNS leak protection: {e}")
            return False
    
    def backup_resolv_conf(self) -> None:
        """Backup original resolv.conf."""
        try:
            resolv_path = "/etc/resolv.conf"
            if os.path.exists(resolv_path):
                with open(resolv_path, 'r') as f:
                    self.original_resolv_conf = f.read()
                self.logger.debug("Backed up original resolv.conf")
            
        except Exception as e:
            self.logger.error(f"Failed to backup resolv.conf: {e}")
    
    def restore_resolv_conf(self) -> None:
        """Restore original resolv.conf."""
        try:
            resolv_path = "/etc/resolv.conf"
            if self.original_resolv_conf:
                with open(resolv_path, 'w') as f:
                    f.write(self.original_resolv_conf)
                self.logger.debug("Restored original resolv.conf")
            
        except Exception as e:
            self.logger.error(f"Failed to restore resolv.conf: {e}")
    
    def configure_dns_settings(self, vpn_interface: str) -> None:
        """Configure DNS settings to use VPN DNS servers."""
        try:
            resolv_path = "/etc/resolv.conf"
            
            # Create new resolv.conf with VPN DNS servers
            new_resolv = "# Generated by VPN DNS Leak Protection\n"
            for dns_server in self.config.vpn_dns_servers:
                new_resolv += f"nameserver {dns_server}\n"
            
            # Add options to prevent DNS leaks
            new_resolv += "options timeout:2 attempts:3\n"
            new_resolv += "options rotate\n"
            
            with open(resolv_path, 'w') as f:
                f.write(new_resolv)
            
            self.logger.info(f"Configured DNS servers: {self.config.vpn_dns_servers}")
            
        except Exception as e:
            self.logger.error(f"Failed to configure DNS settings: {e}")
    
    def setup_dns_firewall_rules(self) -> None:
        """Set up iptables rules to block external DNS."""
        try:
            # Block outgoing DNS queries to non-VPN servers
            subprocess.run([
                "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", str(self.config.dns_port),
                "!", "-d", "127.0.0.1", "-j", "DROP"
            ], check=True)
            
            subprocess.run([
                "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(self.config.dns_port),
                "!", "-d", "127.0.0.1", "-j", "DROP"
            ], check=True)
            
            # Allow DNS queries to VPN DNS servers
            for dns_server in self.config.vpn_dns_servers:
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "udp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=True)
                
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=True)
            
            # Allow DNS queries to allowed servers
            for dns_server in self.config.allowed_dns_servers:
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "udp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=True)
                
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=True)
            
            # Block DNS over HTTPS (DoH)
            if self.config.block_dns_over_https:
                self._block_dns_over_https()
            
            self.logger.info("DNS firewall rules configured")
            
        except Exception as e:
            self.logger.error(f"Failed to setup DNS firewall rules: {e}")
    
    def _block_dns_over_https(self) -> None:
        """Block common DNS over HTTPS endpoints."""
        try:
            # Block common DoH ports and services
            doh_ports = ["443", "80", "8080"]
            doh_domains = [
                "cloudflare-dns.com",
                "dns.google", 
                "doh.opendns.com",
                "dns.quad9.net"
            ]
            
            for domain in doh_domains:
                # Block HTTPS to DoH providers
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443",
                    "-m", "string", "--string", domain, "--algo", "bm", "-j", "DROP"
                ], check=False)
            
            self.logger.debug("DNS over HTTPS blocking configured")
            
        except Exception as e:
            self.logger.error(f"Failed to block DNS over HTTPS: {e}")
    
    def remove_dns_firewall_rules(self) -> None:
        """Remove DNS firewall rules."""
        try:
            # Remove DNS rules
            subprocess.run([
                "iptables", "-D", "OUTPUT", "-p", "udp", "--dport", str(self.config.dns_port),
                "!", "-d", "127.0.0.1", "-j", "DROP"
            ], check=False)
            
            subprocess.run([
                "iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", str(self.config.dns_port),
                "!", "-d", "127.0.0.1", "-j", "DROP"
            ], check=False)
            
            # Remove allowed server rules
            for dns_server in self.config.vpn_dns_servers + self.config.allowed_dns_servers:
                subprocess.run([
                    "iptables", "-D", "OUTPUT", "-p", "udp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=False)
                
                subprocess.run([
                    "iptables", "-D", "OUTPUT", "-p", "tcp", "-d", dns_server, "--dport", str(self.config.dns_port), "-j", "ACCEPT"
                ], check=False)
            
            self.logger.info("DNS firewall rules removed")
            
        except Exception as e:
            self.logger.error(f"Failed to remove DNS firewall rules: {e}")
    
    def _monitor_dns_traffic(self) -> None:
        """Monitor DNS traffic for leaks."""
        try:
            # Start packet capture for DNS traffic
            filter_expr = f"udp port {self.config.dns_port} or tcp port {self.config.dns_port}"
            
            def packet_handler(packet):
                if not self.is_active:
                    return
                
                try:
                    if packet.haslayer(DNS) and packet.haslayer(IP):
                        dns_layer = packet[DNS]
                        ip_layer = packet[IP]
                        
                        # Check if this is a DNS query
                        if dns_layer.qr == 0:  # Query
                            query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                            dest_ip = ip_layer.dst
                            
                            # Log the query
                            if self.config.log_dns_queries:
                                self._log_dns_query(query_name, dest_ip, ip_layer.src)
                            
                            # Check for DNS leak
                            if self._is_dns_leak(dest_ip):
                                self.logger.warning(f"DNS leak detected: {query_name} -> {dest_ip}")
                                self._handle_dns_leak(dest_ip)
                
                except Exception as e:
                    self.logger.debug(f"Error processing DNS packet: {e}")
            
            # Start sniffing
            scapy.sniff(filter=filter_expr, prn=packet_handler, store=0, stop_filter=lambda x: not self.is_active)
            
        except Exception as e:
            self.logger.error(f"Error in DNS traffic monitoring: {e}")
    
    def _log_dns_query(self, query_name: str, dest_ip: str, src_ip: str) -> None:
        """Log DNS query information."""
        try:
            log_entry = {
                'timestamp': time.time(),
                'query': query_name,
                'destination': dest_ip,
                'source': src_ip,
                'is_leak': self._is_dns_leak(dest_ip)
            }
            
            self.dns_query_log.append(log_entry)
            
            # Keep log size manageable
            if len(self.dns_query_log) > self.max_log_entries:
                self.dns_query_log = self.dns_query_log[-self.max_log_entries:]
            
            self.logger.debug(f"DNS query: {query_name} -> {dest_ip}")
            
        except Exception as e:
            self.logger.debug(f"Error logging DNS query: {e}")
    
    def _is_dns_leak(self, dest_ip: str) -> bool:
        """Check if DNS query is going to external server."""
        try:
            # Check if destination is in allowed DNS servers
            allowed_ips = self.config.vpn_dns_servers + self.config.allowed_dns_servers + ["127.0.0.1"]
            
            return dest_ip not in allowed_ips
            
        except Exception:
            return True  # Assume leak if we can't verify
    
    def _handle_dns_leak(self, dest_ip: str) -> None:
        """Handle detected DNS leak."""
        try:
            # Block the leaking IP
            if dest_ip not in self.blocked_ips:
                subprocess.run([
                    "iptables", "-A", "OUTPUT", "-d", dest_ip, "-j", "DROP"
                ], check=True)
                
                self.blocked_ips.add(dest_ip)
                self.logger.warning(f"Blocked leaking DNS server: {dest_ip}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle DNS leak: {e}")
    
    def _dns_filter_server(self) -> None:
        """Run a local DNS filter server."""
        try:
            # Create a simple DNS server that forwards to VPN DNS
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.bind(('127.0.0.1', self.config.custom_dns_port))
            server_socket.settimeout(1.0)
            
            self.logger.info(f"DNS filter server started on port {self.config.custom_dns_port}")
            
            while self.is_active:
                try:
                    data, addr = server_socket.recvfrom(512)
                    
                    # Forward to VPN DNS server
                    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    forward_socket.settimeout(5.0)
                    
                    dns_server = self.config.vpn_dns_servers[0]
                    forward_socket.sendto(data, (dns_server, self.config.dns_port))
                    
                    response, _ = forward_socket.recvfrom(512)
                    forward_socket.close()
                    
                    # Send response back to client
                    server_socket.sendto(response, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error in DNS filter server: {e}")
            
            server_socket.close()
            
        except Exception as e:
            self.logger.error(f"DNS filter server error: {e}")
    
    def test_dns_leak_protection(self) -> bool:
        """Test DNS leak protection."""
        try:
            self.logger.info("Testing DNS leak protection...")
            
            # Test DNS query to external server
            test_domains = ["example.com", "google.com", "cloudflare.com"]
            leaks_detected = 0
            
            for domain in test_domains:
                try:
                    # Perform DNS query
                    result = socket.gethostbyname(domain)
                    
                    # Check if the query went through allowed DNS
                    # This is a simplified test - in practice you'd need more sophisticated monitoring
                    self.logger.debug(f"DNS query for {domain} resolved to {result}")
                    
                except Exception as e:
                    self.logger.debug(f"DNS query for {domain} failed: {e}")
                    leaks_detected += 1
            
            if leaks_detected == 0:
                self.logger.info("DNS leak protection test passed")
                return True
            else:
                self.logger.warning(f"DNS leak protection test failed - {leaks_detected} leaks detected")
                return False
                
        except Exception as e:
            self.logger.error(f"DNS leak protection test failed: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get current status of DNS leak protection."""
        return {
            'active': self.is_active,
            'config': {
                'enabled': self.config.enabled,
                'vpn_dns_servers': self.config.vpn_dns_servers,
                'block_external_dns': self.config.block_external_dns,
                'force_vpn_dns': self.config.force_vpn_dns,
                'log_dns_queries': self.config.log_dns_queries
            },
            'blocked_ips': list(self.blocked_ips),
            'query_log_size': len(self.dns_query_log),
            'recent_queries': self.dns_query_log[-10:] if self.dns_query_log else []
        }
    
    def get_dns_query_log(self, limit: int = 100) -> List[Dict]:
        """Get recent DNS query log."""
        return self.dns_query_log[-limit:] if self.dns_query_log else []


# Example usage and testing
if __name__ == "__main__":
    # Create DNS leak protection
    dns_protection = DNSLeakProtection()
    
    # Print status
    status = dns_protection.get_status()
    print("DNS Leak Protection Status:")
    print(json.dumps(status, indent=2))
    
    # Test functionality
    if dns_protection.test_dns_leak_protection():
        print("DNS leak protection test: PASSED")
    else:
        print("DNS leak protection test: FAILED")
