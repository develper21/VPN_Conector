#!/usr/bin/env python3
"""
Security Auditing Tools for VPN
Comprehensive vulnerability scanning and security assessment capabilities.
Monitors system security, configuration vulnerabilities, and compliance.
"""
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import cryptography.hazmat.primitives as crypto
from cryptography.hazmat.primitives import hashes
import psutil
import requests

from utils.logger import setup_logger


@dataclass
class VulnerabilityFinding:
    """Represents a security vulnerability finding."""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # configuration, network, encryption, system
    affected_component: str
    recommendation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class SecurityScore:
    """Overall security assessment score."""
    overall_score: float  # 0-100
    configuration_score: float
    network_score: float
    encryption_score: float
    system_score: float
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    assessment_timestamp: float


class SecurityAuditor:
    """Comprehensive security auditing and vulnerability scanning."""
    
    def __init__(self, config_path: str = "config/security_auditing.json"):
        self.logger = setup_logger("security_auditor", "INFO")
        self.config_path = Path(config_path)
        self.findings: List[VulnerabilityFinding] = []
        self.is_monitoring = False
        self.monitoring_thread = None
        
        # Configuration
        self.config = {
            'enable_continuous_monitoring': True,
            'scan_interval': 3600,  # 1 hour
            'enable_network_scanning': True,
            'enable_config_checking': True,
            'enable_encryption_audit': True,
            'enable_system_audit': True,
            'severity_threshold': 'medium',  # minimum severity to report
            'auto_remediate': False,
            'compliance_standards': ['nist', 'iso27001'],
            'scan_ports': [22, 80, 443, 1194, 51820],  # Common VPN ports
            'max_concurrent_scans': 10,
            'timeout_seconds': 10
        }
        
        # Known vulnerability database (simplified)
        self.vulnerability_db = self._load_vulnerability_database()
        
        # Security check modules
        self.check_modules = {
            'configuration': self._check_configuration_security,
            'network': self._check_network_security,
            'encryption': self._check_encryption_security,
            'system': self._check_system_security
        }
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> None:
        """Load security auditing configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                self.config.update(loaded_config)
                self.logger.info("Security auditing configuration loaded")
            else:
                self.save_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info("Configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def _load_vulnerability_database(self) -> Dict[str, Dict]:
        """Load vulnerability database (simplified version)."""
        return {
            'weak_ssl_ciphers': {
                'title': 'Weak SSL/TLS Ciphers Detected',
                'description': 'The system is using weak SSL/TLS cipher suites that may be vulnerable to attacks',
                'severity': 'high',
                'category': 'encryption',
                'recommendation': 'Disable weak ciphers and use only strong cipher suites',
                'cvss_score': 7.5
            },
            'default_passwords': {
                'title': 'Default Credentials in Use',
                'description': 'Default or weak passwords detected in configuration files',
                'severity': 'critical',
                'category': 'configuration',
                'recommendation': 'Change all default passwords to strong, unique passwords',
                'cvss_score': 9.8
            },
            'open_ports': {
                'title': 'Unnecessary Open Ports',
                'description': 'Unnecessary network ports are open and may expose the system to attacks',
                'severity': 'medium',
                'category': 'network',
                'recommendation': 'Close unnecessary ports and implement firewall rules',
                'cvss_score': 5.3
            },
            'outdated_software': {
                'title': 'Outdated Software Components',
                'description': 'Software components are outdated and may contain known vulnerabilities',
                'severity': 'high',
                'category': 'system',
                'recommendation': 'Update all software components to latest secure versions',
                'cvss_score': 8.1
            }
        }
    
    def start_monitoring(self) -> bool:
        """Start continuous security monitoring."""
        try:
            if self.is_monitoring:
                self.logger.warning("Security monitoring is already active")
                return False
            
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            # Run initial scan
            threading.Thread(target=self.run_full_audit, daemon=True).start()
            
            self.logger.info("Security monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start security monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop security monitoring."""
        try:
            if not self.is_monitoring:
                self.logger.warning("Security monitoring is not active")
                return False
            
            self.is_monitoring = False
            
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=10)
            
            self.logger.info("Security monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop security monitoring: {e}")
            return False
    
    def run_full_audit(self) -> SecurityScore:
        """Run comprehensive security audit."""
        try:
            self.logger.info("Starting comprehensive security audit...")
            
            # Clear previous findings
            self.findings.clear()
            
            # Run all security checks
            for category, check_func in self.check_modules.items():
                if self.config[f'enable_{category}_checking']:
                    try:
                        check_func()
                    except Exception as e:
                        self.logger.error(f"Error in {category} security check: {e}")
            
            # Calculate security score
            score = self._calculate_security_score()
            
            # Log summary
            self.logger.info(f"Security audit completed - Score: {score.overall_score:.1f}/100, "
                           f"Findings: {score.total_findings}")
            
            return score
            
        except Exception as e:
            self.logger.error(f"Security audit failed: {e}")
            return SecurityScore(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, time.time())
    
    def _check_configuration_security(self) -> None:
        """Check configuration file security."""
        try:
            # Check for default passwords
            self._check_default_passwords()
            
            # Check file permissions
            self._check_file_permissions()
            
            # Check configuration hardening
            self._check_config_hardening()
            
            # Check logging configuration
            self._check_logging_security()
            
        except Exception as e:
            self.logger.error(f"Configuration security check failed: {e}")
    
    def _check_default_passwords(self) -> None:
        """Check for default or weak passwords in configuration."""
        try:
            config_files = [
                'config/vpn_config.json',
                'config/openvpn_config.json',
                'config/wireguard_config.json'
            ]
            
            weak_passwords = [
                'password', '123456', 'admin', 'root', 'default',
                'changeme', 'password123', 'qwerty', 'letmein'
            ]
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read().lower()
                        
                    for weak_pwd in weak_passwords:
                        if weak_pwd in content:
                            finding = VulnerabilityFinding(
                                id=f"default_password_{config_file}",
                                title="Default or Weak Password Detected",
                                description=f"Weak password pattern found in {config_file}",
                                severity="critical",
                                category="configuration",
                                affected_component=config_file,
                                recommendation="Replace weak passwords with strong, unique passwords",
                                cvss_score=9.8
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.error(f"Default password check failed: {e}")
    
    def _check_file_permissions(self) -> None:
        """Check file permissions for security."""
        try:
            sensitive_files = [
                'config/vpn_config.json',
                'config/certificates/',
                'config/keys/',
                '/etc/resolv.conf'
            ]
            
            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    mode = oct(stat_info.st_mode)[-3:]
                    
                    # Check if file is world-readable or world-writable
                    if mode[2] in ['4', '6', '7']:  # World-readable
                        finding = VulnerabilityFinding(
                            id=f"world_readable_{file_path}",
                            title="World-Readable Sensitive File",
                            description=f"Sensitive file {file_path} is readable by all users",
                            severity="medium",
                            category="configuration",
                            affected_component=file_path,
                            recommendation="Restrict file permissions to owner only (chmod 600)",
                            cvss_score=5.3
                        )
                        self.findings.append(finding)
                    
                    if mode[2] in ['2', '3', '6', '7']:  # World-writable
                        finding = VulnerabilityFinding(
                            id=f"world_writable_{file_path}",
                            title="World-Writable Sensitive File",
                            description=f"Sensitive file {file_path} is writable by all users",
                            severity="high",
                            category="configuration",
                            affected_component=file_path,
                            recommendation="Restrict file permissions to owner only (chmod 600)",
                            cvss_score=7.5
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.error(f"File permissions check failed: {e}")
    
    def _check_config_hardening(self) -> None:
        """Check configuration hardening settings."""
        try:
            # Check SSL/TLS configuration
            self._check_ssl_configuration()
            
            # Check firewall configuration
            self._check_firewall_configuration()
            
            # Check VPN-specific security settings
            self._check_vpn_security_settings()
            
        except Exception as e:
            self.logger.error(f"Config hardening check failed: {e}")
    
    def _check_ssl_configuration(self) -> None:
        """Check SSL/TLS configuration security."""
        try:
            # Check for weak cipher suites
            weak_ciphers = [
                'RC4', 'DES', '3DES', 'MD5', 'NULL',
                'EXPORT', 'ADH', 'AECDH'
            ]
            
            # This would typically check actual SSL configuration
            # For demonstration, we'll simulate the check
            config_files = ['config/openvpn_config.json', 'config/vpn_config.json']
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    for cipher in weak_ciphers:
                        if cipher.lower() in content.lower():
                            finding = VulnerabilityFinding(
                                id=f"weak_cipher_{cipher}_{config_file}",
                                title="Weak SSL/TLS Cipher Suite",
                                description=f"Weak cipher suite {cipher} found in {config_file}",
                                severity="high",
                                category="encryption",
                                affected_component=config_file,
                                recommendation=f"Remove weak cipher {cipher} and use strong ciphers only",
                                cvss_score=7.5
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.error(f"SSL configuration check failed: {e}")
    
    def _check_firewall_configuration(self) -> None:
        """Check firewall configuration."""
        try:
            # Check iptables rules
            result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
            if result.returncode == 0:
                rules = result.stdout
                
                # Check for overly permissive rules
                if 'ACCEPT' in rules and 'anywhere' in rules:
                    finding = VulnerabilityFinding(
                        id="overly_permissive_firewall",
                        title="Overly Permissive Firewall Rules",
                        description="Firewall rules allow traffic from anywhere",
                        severity="medium",
                        category="network",
                        affected_component="iptables",
                        recommendation="Restrict firewall rules to specific IP ranges and ports",
                        cvss_score=5.3
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"Firewall configuration check failed: {e}")
    
    def _check_vpn_security_settings(self) -> None:
        """Check VPN-specific security settings."""
        try:
            # Check for weak encryption algorithms
            weak_algorithms = ['DES', 'RC4', 'MD5', 'SHA1']
            
            config_files = ['config/openvpn_config.json', 'config/wireguard_config.json']
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    for algo in weak_algorithms:
                        if algo.lower() in content.lower():
                            finding = VulnerabilityFinding(
                                id=f"weak_algorithm_{algo}_{config_file}",
                                title="Weak Encryption Algorithm",
                                description=f"Weak encryption algorithm {algo} found in {config_file}",
                                severity="high",
                                category="encryption",
                                affected_component=config_file,
                                recommendation=f"Replace {algo} with stronger algorithms like AES-256",
                                cvss_score=7.5
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.error(f"VPN security settings check failed: {e}")
    
    def _check_logging_security(self) -> None:
        """Check logging configuration for security."""
        try:
            # Check if sensitive information is logged
            log_files = [
                'logs/vpn.log',
                'logs/security.log',
                'logs/audit.log'
            ]
            
            sensitive_patterns = [
                r'password',
                r'key',
                r'secret',
                r'token',
                r'credential'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        content = f.read().lower()
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, content):
                            finding = VulnerabilityFinding(
                                id=f"sensitive_logging_{log_file}",
                                title="Sensitive Information in Logs",
                                description=f"Sensitive information pattern found in {log_file}",
                                severity="medium",
                                category="configuration",
                                affected_component=log_file,
                                recommendation="Remove sensitive information from logs and implement log sanitization",
                                cvss_score=5.3
                            )
                            self.findings.append(finding)
                            break
                            
        except Exception as e:
            self.logger.error(f"Logging security check failed: {e}")
    
    def _check_network_security(self) -> None:
        """Check network security."""
        try:
            # Port scanning
            self._scan_open_ports()
            
            # Network interface security
            self._check_network_interfaces()
            
            # DNS security
            self._check_dns_security()
            
        except Exception as e:
            self.logger.error(f"Network security check failed: {e}")
    
    def _scan_open_ports(self) -> None:
        """Scan for open ports."""
        try:
            open_ports = []
            
            # Get all listening ports
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    open_ports.append(conn.laddr.port)
            
            # Check for unexpected open ports
            expected_ports = {22, 80, 443, 1194, 51820}  # SSH, HTTP, HTTPS, OpenVPN, WireGuard
            
            for port in open_ports:
                if port not in expected_ports:
                    finding = VulnerabilityFinding(
                        id=f"unexpected_port_{port}",
                        title="Unexpected Open Port",
                        description=f"Port {port} is open but not in expected ports list",
                        severity="medium",
                        category="network",
                        affected_component=f"port_{port}",
                        recommendation=f"Verify if port {port} should be open and close if unnecessary",
                        cvss_score=4.3
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")
    
    def _check_network_interfaces(self) -> None:
        """Check network interface security."""
        try:
            interfaces = psutil.net_if_addrs()
            
            for interface_name, addresses in interfaces.items():
                for addr in addresses:
                    # Check for promiscuous mode (simplified check)
                    if interface_name.startswith('eth') or interface_name.startswith('wlan'):
                        # This would require more sophisticated checking in production
                        pass
                        
        except Exception as e:
            self.logger.error(f"Network interface check failed: {e}")
    
    def _check_dns_security(self) -> None:
        """Check DNS configuration security."""
        try:
            resolv_conf = '/etc/resolv.conf'
            if os.path.exists(resolv_conf):
                with open(resolv_conf, 'r') as f:
                    content = f.read()
                
                # Check for insecure DNS servers
                insecure_dns = ['8.8.8.8', '8.8.4.4']  # Example - these are actually secure
                
                for dns in insecure_dns:
                    if dns in content:
                        # This is just an example - in reality these are secure DNS servers
                        pass
                        
        except Exception as e:
            self.logger.error(f"DNS security check failed: {e}")
    
    def _check_encryption_security(self) -> None:
        """Check encryption and certificate security."""
        try:
            # Certificate validation
            self._check_certificates()
            
            # Key strength validation
            self._check_key_strength()
            
            # SSL/TLS version checking
            self._check_ssl_versions()
            
        except Exception as e:
            self.logger.error(f"Encryption security check failed: {e}")
    
    def _check_certificates(self) -> None:
        """Check SSL/TLS certificates."""
        try:
            cert_dir = 'config/certificates/'
            if os.path.exists(cert_dir):
                for cert_file in os.listdir(cert_dir):
                    if cert_file.endswith('.crt') or cert_file.endswith('.pem'):
                        cert_path = os.path.join(cert_dir, cert_file)
                        
                        # Check certificate expiration
                        try:
                            with open(cert_path, 'r') as f:
                                cert_data = f.read()
                            
                            # This would use proper certificate parsing in production
                            # For demonstration, we'll simulate the check
                            finding = VulnerabilityFinding(
                                id=f"cert_check_{cert_file}",
                                title="Certificate Validation Required",
                                description=f"Certificate {cert_file} should be validated for expiration and strength",
                                severity="medium",
                                category="encryption",
                                affected_component=cert_path,
                                recommendation="Validate certificate expiration and key strength",
                                cvss_score=5.3
                            )
                            # Only add if we find actual issues
                            # self.findings.append(finding)
                            
                        except Exception as e:
                            self.logger.error(f"Error checking certificate {cert_file}: {e}")
                            
        except Exception as e:
            self.logger.error(f"Certificate check failed: {e}")
    
    def _check_key_strength(self) -> None:
        """Check encryption key strength."""
        try:
            key_dir = 'config/keys/'
            if os.path.exists(key_dir):
                for key_file in os.listdir(key_dir):
                    if key_file.endswith('.key'):
                        key_path = os.path.join(key_dir, key_file)
                        
                        # Check key size (simplified)
                        stat_info = os.stat(key_path)
                        file_size = stat_info.st_size
                        
                        # RSA keys should be at least 2048 bits
                        if file_size < 256:  # Rough estimate
                            finding = VulnerabilityFinding(
                                id=f"weak_key_{key_file}",
                                title="Weak Encryption Key",
                                description=f"Key {key_file} may be too small for secure encryption",
                                severity="high",
                                category="encryption",
                                affected_component=key_path,
                                recommendation="Use at least 2048-bit RSA or 256-bit ECC keys",
                                cvss_score=7.5
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.error(f"Key strength check failed: {e}")
    
    def _check_ssl_versions(self) -> None:
        """Check SSL/TLS versions."""
        try:
            # Check for deprecated SSL/TLS versions
            deprecated_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            
            config_files = ['config/openvpn_config.json', 'config/vpn_config.json']
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    for version in deprecated_versions:
                        if version.lower() in content.lower():
                            finding = VulnerabilityFinding(
                                id=f"deprecated_ssl_{version}_{config_file}",
                                title="Deprecated SSL/TLS Version",
                                description=f"Deprecated SSL/TLS version {version} found in {config_file}",
                                severity="high",
                                category="encryption",
                                affected_component=config_file,
                                recommendation=f"Disable {version} and use TLS 1.2 or higher",
                                cvss_score=7.5
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            self.logger.error(f"SSL version check failed: {e}")
    
    def _check_system_security(self) -> None:
        """Check system-level security."""
        try:
            # System updates
            self._check_system_updates()
            
            # User permissions
            self._check_user_permissions()
            
            # Running services
            self._check_running_services()
            
        except Exception as e:
            self.logger.error(f"System security check failed: {e}")
    
    def _check_system_updates(self) -> None:
        """Check for system updates."""
        try:
            # Check for available updates (simplified)
            result = subprocess.run(['apt', 'list', '--upgradable'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                updates = result.stdout.strip().split('\n')
                if len(updates) > 1:  # More than just the header
                    finding = VulnerabilityFinding(
                        id="system_updates_available",
                        title="System Updates Available",
                        description=f"{len(updates)-1} system updates are available",
                        severity="medium",
                        category="system",
                        affected_component="system",
                        recommendation="Apply available system updates to patch security vulnerabilities",
                        cvss_score=5.3
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"System updates check failed: {e}")
    
    def _check_user_permissions(self) -> None:
        """Check user permissions and access control."""
        try:
            # Check for users with UID 0 (root) other than root
            result = subprocess.run(['awk', '-F:', '$3 == 0 {print $1}', '/etc/passwd'],
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                root_users = result.stdout.strip().split('\n')
                if len(root_users) > 1 or (len(root_users) == 1 and root_users[0] != 'root'):
                    finding = VulnerabilityFinding(
                        id="multiple_root_users",
                        title="Multiple Root Users Detected",
                        description="Multiple users have root privileges",
                        severity="high",
                        category="system",
                        affected_component="/etc/passwd",
                        recommendation="Review and minimize root access, use sudo instead",
                        cvss_score=7.5
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"User permissions check failed: {e}")
    
    def _check_running_services(self) -> None:
        """Check running services for security."""
        try:
            # Get running services
            services = psutil.win_service_iter() if os.name == 'nt' else []
            
            # For Linux, we'd use systemctl or service command
            if os.name != 'nt':
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    services_list = result.stdout.strip().split('\n')
                    
                    # Check for unnecessary services
                    unnecessary_services = ['telnet', 'rsh', 'rlogin']
                    
                    for service in services_list:
                        for unnecessary in unnecessary_services:
                            if unnecessary in service.lower():
                                finding = VulnerabilityFinding(
                                    id=f"unnecessary_service_{unnecessary}",
                                    title="Unnecessary Service Running",
                                    description=f"Potentially unnecessary service {unnecessary} is running",
                                    severity="medium",
                                    category="system",
                                    affected_component="system_services",
                                    recommendation=f"Disable unnecessary service {unnecessary}",
                                    cvss_score=4.3
                                )
                                self.findings.append(finding)
                                
        except Exception as e:
            self.logger.error(f"Running services check failed: {e}")
    
    def _calculate_security_score(self) -> SecurityScore:
        """Calculate overall security score based on findings."""
        try:
            # Count findings by severity
            critical_count = len([f for f in self.findings if f.severity == 'critical'])
            high_count = len([f for f in self.findings if f.severity == 'high'])
            medium_count = len([f for f in self.findings if f.severity == 'medium'])
            low_count = len([f for f in self.findings if f.severity == 'low'])
            
            # Calculate category scores
            config_findings = [f for f in self.findings if f.category == 'configuration']
            network_findings = [f for f in self.findings if f.category == 'network']
            encryption_findings = [f for f in self.findings if f.category == 'encryption']
            system_findings = [f for f in self.findings if f.category == 'system']
            
            # Calculate scores (0-100, higher is better)
            def calculate_category_score(findings):
                if not findings:
                    return 100.0
                
                score = 100.0
                for finding in findings:
                    if finding.severity == 'critical':
                        score -= 25
                    elif finding.severity == 'high':
                        score -= 15
                    elif finding.severity == 'medium':
                        score -= 10
                    elif finding.severity == 'low':
                        score -= 5
                
                return max(0, score)
            
            config_score = calculate_category_score(config_findings)
            network_score = calculate_category_score(network_findings)
            encryption_score = calculate_category_score(encryption_findings)
            system_score = calculate_category_score(system_findings)
            
            # Overall score (weighted average)
            overall_score = (config_score * 0.3 + network_score * 0.25 + 
                           encryption_score * 0.25 + system_score * 0.2)
            
            return SecurityScore(
                overall_score=overall_score,
                configuration_score=config_score,
                network_score=network_score,
                encryption_score=encryption_score,
                system_score=system_score,
                total_findings=len(self.findings),
                critical_findings=critical_count,
                high_findings=high_count,
                medium_findings=medium_count,
                low_findings=low_count,
                assessment_timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to calculate security score: {e}")
            return SecurityScore(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, time.time())
    
    def _monitoring_loop(self) -> None:
        """Continuous security monitoring loop."""
        while self.is_monitoring:
            try:
                # Run security scan
                self.run_full_audit()
                
                # Wait for next scan
                time.sleep(self.config['scan_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in security monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def get_findings_by_severity(self, min_severity: str = 'low') -> List[VulnerabilityFinding]:
        """Get findings filtered by minimum severity."""
        severity_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        min_level = severity_order.get(min_severity, 0)
        
        filtered_findings = []
        for finding in self.findings:
            if severity_order.get(finding.severity, 0) >= min_level:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def export_audit_report(self, filepath: str, format: str = 'json') -> bool:
        """Export security audit report."""
        try:
            score = self._calculate_security_score()
            
            report_data = {
                'audit_timestamp': time.time(),
                'security_score': asdict(score),
                'findings': [asdict(f) for f in self.findings],
                'config': self.config,
                'summary': {
                    'total_findings': len(self.findings),
                    'critical_issues': len([f for f in self.findings if f.severity == 'critical']),
                    'high_issues': len([f for f in self.findings if f.severity == 'high']),
                    'medium_issues': len([f for f in self.findings if f.severity == 'medium']),
                    'low_issues': len([f for f in self.findings if f.severity == 'low'])
                }
            }
            
            if format.lower() == 'json':
                with open(filepath, 'w') as f:
                    json.dump(report_data, f, indent=2)
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return False
            
            self.logger.info(f"Security audit report exported to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export audit report: {e}")
            return False
    
    def get_security_status(self) -> Dict:
        """Get current security status."""
        try:
            score = self._calculate_security_score()
            
            return {
                'monitoring_active': self.is_monitoring,
                'security_score': asdict(score),
                'recent_findings': len([f for f in self.findings if 
                                      time.time() - f.timestamp < 3600]),  # Last hour
                'total_findings': len(self.findings),
                'critical_findings': len([f for f in self.findings if f.severity == 'critical']),
                'config': self.config
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get security status: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    # Create security auditor
    auditor = SecurityAuditor()
    
    # Run full audit
    score = auditor.run_full_audit()
    print(f"Security Score: {score.overall_score:.1f}/100")
    
    # Get findings
    critical_findings = auditor.get_findings_by_severity('critical')
    print(f"Critical findings: {len(critical_findings)}")
    
    # Start monitoring
    auditor.start_monitoring()
    
    # Export report
    auditor.export_audit_report('security_audit_report.json')
    
    # Get status
    status = auditor.get_security_status()
    print(f"Security status: {status}")
    
    # Stop monitoring
    time.sleep(5)
    auditor.stop_monitoring()
