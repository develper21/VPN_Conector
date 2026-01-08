"""
Health Checker Module for VPN Security Project.
This module monitors server health, performance, and availability
with comprehensive health checks and alerting.
"""
import os
import time
import socket
import asyncio
import aiohttp
import threading
import statistics
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed
import ping3
import psutil

from discovery.server_discovery import VPNServer, ServerStatus
from discovery.server_registry import ServerRegistry, ServerMetrics
from utils.logger import LoggableMixin


class HealthCheckType(Enum):
    """Types of health checks."""
    CONNECTIVITY = auto()
    RESPONSE_TIME = auto()
    BANDWIDTH = auto()
    PACKET_LOSS = auto()
    SSL_CERTIFICATE = auto()
    PROTOCOL_SPECIFIC = auto()
    LOAD_BALANCE = auto()


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = auto()
    WARNING = auto()
    CRITICAL = auto()
    UNKNOWN = auto()


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    server_id: str
    check_type: HealthCheckType
    status: HealthStatus
    timestamp: float
    response_time: float  # milliseconds
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'server_id': self.server_id,
            'check_type': self.check_type.name,
            'status': self.status.name,
            'timestamp': self.timestamp,
            'response_time': self.response_time,
            'message': self.message,
            'details': self.details
        }


@dataclass
class HealthThresholds:
    """Health check thresholds."""
    response_time_warning: float = 500.0  # milliseconds
    response_time_critical: float = 1000.0
    packet_loss_warning: float = 0.01  # 1%
    packet_loss_critical: float = 0.05  # 5%
    bandwidth_warning: float = 10.0  # Mbps
    bandwidth_critical: float = 5.0  # Mbps
    cpu_warning: float = 0.8  # 80%
    cpu_critical: float = 0.95  # 95%
    memory_warning: float = 0.8  # 80%
    memory_critical: float = 0.95  # 95%
    uptime_warning: float = 0.95  # 95%
    uptime_critical: float = 0.9  # 90%


class HealthChecker(LoggableMixin):
    """Main health checker for VPN servers."""
    
    def __init__(self, config: Dict[str, Any], registry: ServerRegistry):
        self.config = config
        self.registry = registry
        self.health_config = config.get('health_checker', {})
        
        # Health check settings
        self.enabled_checks = self._parse_enabled_checks()
        self.check_interval = self.health_config.get('interval', 60)  # seconds
        self.timeout = self.health_config.get('timeout', 10)
        self.max_concurrent_checks = self.health_config.get('max_concurrent', 20)
        self.retry_count = self.health_config.get('retry_count', 3)
        
        # Thresholds
        self.thresholds = HealthThresholds(**self.health_config.get('thresholds', {}))
        
        # Health check state
        self.health_results: Dict[str, List[HealthCheckResult]] = {}
        self.health_status: Dict[str, HealthStatus] = {}
        self.last_check_time = 0.0
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[str, HealthCheckResult], None]] = []
        
        # Background checking
        self.check_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'successful_checks': 0,
            'failed_checks': 0,
            'alerts_triggered': 0,
            'average_check_time': 0.0,
            'last_check_time': 0.0
        }
    
    def _parse_enabled_checks(self) -> Set[HealthCheckType]:
        """Parse enabled health checks from config."""
        enabled = self.health_config.get('enabled_checks', [
            'connectivity', 'response_time', 'packet_loss'
        ])
        
        check_map = {
            'connectivity': HealthCheckType.CONNECTIVITY,
            'response_time': HealthCheckType.RESPONSE_TIME,
            'bandwidth': HealthCheckType.BANDWIDTH,
            'packet_loss': HealthCheckType.PACKET_LOSS,
            'ssl_certificate': HealthCheckType.SSL_CERTIFICATE,
            'protocol_specific': HealthCheckType.PROTOCOL_SPECIFIC,
            'load_balance': HealthCheckType.LOAD_BALANCE
        }
        
        return {check_map[check] for check in enabled if check in check_map}
    
    def start_monitoring(self):
        """Start continuous health monitoring."""
        if self.running:
            return
        
        self.running = True
        self.check_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.check_thread.start()
        
        self.logger.info("Health monitoring started")
    
    def stop_monitoring(self):
        """Stop continuous health monitoring."""
        self.running = False
        
        if self.check_thread and self.check_thread.is_alive():
            self.check_thread.join(timeout=10)
        
        self.logger.info("Health monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                start_time = time.time()
                
                # Get all servers from registry
                servers = self.registry.get_all_servers()
                
                if servers:
                    # Run health checks
                    asyncio.run(self._check_servers_health(servers))
                    
                    # Update statistics
                    check_time = time.time() - start_time
                    self.stats['total_checks'] += 1
                    self.stats['average_check_time'] = (
                        (self.stats['average_check_time'] * (self.stats['total_checks'] - 1) + check_time) /
                        self.stats['total_checks']
                    )
                    self.stats['last_check_time'] = time.time()
                
                # Wait for next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                time.sleep(30)  # Wait before retrying
    
    async def _check_servers_health(self, servers: List[VPNServer]):
        """Check health of multiple servers concurrently."""
        semaphore = asyncio.Semaphore(self.max_concurrent_checks)
        
        async def check_single_server(server: VPNServer):
            async with semaphore:
                return await self._check_server_health(server)
        
        tasks = [check_single_server(server) for server in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Health check error: {result}")
            elif result:
                self._process_health_result(result)
    
    async def _check_server_health(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check health of a single server."""
        try:
            # Perform enabled health checks
            if HealthCheckType.CONNECTIVITY in self.enabled_checks:
                result = await self._check_connectivity(server)
                if result:
                    return result
            
            if HealthCheckType.RESPONSE_TIME in self.enabled_checks:
                result = await self._check_response_time(server)
                if result:
                    return result
            
            if HealthCheckType.PACKET_LOSS in self.enabled_checks:
                result = await self._check_packet_loss(server)
                if result:
                    return result
            
            if HealthCheckType.BANDWIDTH in self.enabled_checks:
                result = await self._check_bandwidth(server)
                if result:
                    return result
            
            if HealthCheckType.SSL_CERTIFICATE in self.enabled_checks:
                result = await self._check_ssl_certificate(server)
                if result:
                    return result
            
            if HealthCheckType.PROTOCOL_SPECIFIC in self.enabled_checks:
                result = await self._check_protocol_specific(server)
                if result:
                    return result
            
            # Default healthy result
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.CONNECTIVITY,
                status=HealthStatus.HEALTHY,
                timestamp=time.time(),
                response_time=0.0,
                message="All checks passed"
            )
            
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.CONNECTIVITY,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message=f"Health check failed: {str(e)}"
            )
    
    async def _check_connectivity(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check basic connectivity to server."""
        start_time = time.time()
        
        try:
            # Try to connect to the server
            future = asyncio.open_connection(server.ip_address, server.port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            # Determine status based on response time
            if response_time > self.thresholds.response_time_critical:
                status = HealthStatus.CRITICAL
                message = f"Slow response: {response_time:.2f}ms"
            elif response_time > self.thresholds.response_time_warning:
                status = HealthStatus.WARNING
                message = f"Elevated response time: {response_time:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"Good response time: {response_time:.2f}ms"
            
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.CONNECTIVITY,
                status=status,
                timestamp=time.time(),
                response_time=response_time,
                message=message,
                details={'port': server.port, 'protocol': server.protocol}
            )
            
        except asyncio.TimeoutError:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.CONNECTIVITY,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=self.timeout * 1000,
                message="Connection timeout",
                details={'timeout': self.timeout}
            )
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.CONNECTIVITY,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message=f"Connection failed: {str(e)}"
            )
    
    async def _check_response_time(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check server response time with multiple samples."""
        response_times = []
        
        for _ in range(self.retry_count):
            try:
                start_time = time.time()
                
                # Simple TCP connection test
                future = asyncio.open_connection(server.ip_address, server.port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
                
                response_time = (time.time() - start_time) * 1000
                response_times.append(response_time)
                
                writer.close()
                await writer.wait_closed()
                
            except:
                continue
        
        if not response_times:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.RESPONSE_TIME,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message="All connection attempts failed"
            )
        
        avg_response_time = statistics.mean(response_times)
        
        # Determine status
        if avg_response_time > self.thresholds.response_time_critical:
            status = HealthStatus.CRITICAL
            message = f"Critical response time: {avg_response_time:.2f}ms"
        elif avg_response_time > self.thresholds.response_time_warning:
            status = HealthStatus.WARNING
            message = f"High response time: {avg_response_time:.2f}ms"
        else:
            status = HealthStatus.HEALTHY
            message = f"Good response time: {avg_response_time:.2f}ms"
        
        return HealthCheckResult(
            server_id=server.server_id,
            check_type=HealthCheckType.RESPONSE_TIME,
            status=status,
            timestamp=time.time(),
            response_time=avg_response_time,
            message=message,
            details={
                'samples': response_times,
                'min': min(response_times),
                'max': max(response_times),
                'std_dev': statistics.stdev(response_times) if len(response_times) > 1 else 0.0
            }
        )
    
    async def _check_packet_loss(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check packet loss using ping."""
        try:
            # Use ping3 library for ping
            response_times = []
            lost_packets = 0
            
            for _ in range(5):  # Send 5 pings
                try:
                    ping_time = ping3.ping(server.ip_address, timeout=self.timeout)
                    if ping_time is not None:
                        response_times.append(ping_time * 1000)  # Convert to ms
                    else:
                        lost_packets += 1
                except:
                    lost_packets += 1
            
            packet_loss_rate = lost_packets / 5.0
            
            # Determine status
            if packet_loss_rate > self.thresholds.packet_loss_critical:
                status = HealthStatus.CRITICAL
                message = f"Critical packet loss: {packet_loss_rate * 100:.1f}%"
            elif packet_loss_rate > self.thresholds.packet_loss_warning:
                status = HealthStatus.WARNING
                message = f"High packet loss: {packet_loss_rate * 100:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Low packet loss: {packet_loss_rate * 100:.1f}%"
            
            avg_response_time = statistics.mean(response_times) if response_times else 0.0
            
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.PACKET_LOSS,
                status=status,
                timestamp=time.time(),
                response_time=avg_response_time,
                message=message,
                details={
                    'packet_loss_rate': packet_loss_rate,
                    'lost_packets': lost_packets,
                    'response_times': response_times
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.PACKET_LOSS,
                status=HealthStatus.UNKNOWN,
                timestamp=time.time(),
                response_time=0.0,
                message=f"Ping check failed: {str(e)}"
            )
    
    async def _check_bandwidth(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check server bandwidth (simplified test)."""
        try:
            # Simple bandwidth test using HTTP if available
            if server.port in [80, 443, 8080, 8443]:
                test_url = f"http{'s' if server.port == 443 else ''}://{server.ip_address}:{server.port}/bandwidth_test"
                
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                        start_time = time.time()
                        
                        # Download a small test file (1MB)
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                data = await response.read()
                                download_time = time.time() - start_time
                                
                                # Calculate bandwidth in Mbps
                                bandwidth_mbps = (len(data) * 8) / (download_time * 1000000)
                                
                                # Determine status
                                if bandwidth_mbps < self.thresholds.bandwidth_critical:
                                    status = HealthStatus.CRITICAL
                                    message = f"Critical bandwidth: {bandwidth_mbps:.2f} Mbps"
                                elif bandwidth_mbps < self.thresholds.bandwidth_warning:
                                    status = HealthStatus.WARNING
                                    message = f"Low bandwidth: {bandwidth_mbps:.2f} Mbps"
                                else:
                                    status = HealthStatus.HEALTHY
                                    message = f"Good bandwidth: {bandwidth_mbps:.2f} Mbps"
                                
                                return HealthCheckResult(
                                    server_id=server.server_id,
                                    check_type=HealthCheckType.BANDWIDTH,
                                    status=status,
                                    timestamp=time.time(),
                                    response_time=download_time * 1000,
                                    message=message,
                                    details={
                                        'bandwidth_mbps': bandwidth_mbps,
                                        'download_size': len(data),
                                        'download_time': download_time
                                    }
                                )
                            else:
                                return None
                        
                except:
                    pass
            
            # If no HTTP test available, return unknown
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.BANDWIDTH,
                status=HealthStatus.UNKNOWN,
                timestamp=time.time(),
                response_time=0.0,
                message="Bandwidth test not available"
            )
            
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.BANDWIDTH,
                status=HealthStatus.UNKNOWN,
                timestamp=time.time(),
                response_time=0.0,
                message=f"Bandwidth check failed: {str(e)}"
            )
    
    async def _check_ssl_certificate(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check SSL certificate for HTTPS/OpenVPN servers."""
        if server.port not in [443, 1194] or server.protocol not in ['openvpn', 'both']:
            return None
        
        try:
            import ssl
            from datetime import datetime
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((server.ip_address, server.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=server.ip_address) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    # Determine status
                    if days_until_expiry < 7:
                        status = HealthStatus.CRITICAL
                        message = f"Certificate expires in {days_until_expiry} days"
                    elif days_until_expiry < 30:
                        status = HealthStatus.WARNING
                        message = f"Certificate expires in {days_until_expiry} days"
                    else:
                        status = HealthStatus.HEALTHY
                        message = f"Certificate valid for {days_until_expiry} days"
                    
                    return HealthCheckResult(
                        server_id=server.server_id,
                        check_type=HealthCheckType.SSL_CERTIFICATE,
                        status=status,
                        timestamp=time.time(),
                        response_time=0.0,
                        message=message,
                        details={
                            'expiry_date': cert['notAfter'],
                            'days_until_expiry': days_until_expiry,
                            'issuer': cert['issuer'],
                            'subject': cert['subject']
                        }
                    )
                    
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.SSL_CERTIFICATE,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message=f"SSL certificate check failed: {str(e)}"
            )
    
    async def _check_protocol_specific(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check protocol-specific health."""
        try:
            if server.protocol in ['wireguard', 'both'] and server.port == 51820:
                # WireGuard specific check
                return await self._check_wireguard_health(server)
            elif server.protocol in ['openvpn', 'both']:
                # OpenVPN specific check
                return await self._check_openvpn_health(server)
            
            return None
            
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                status=HealthStatus.UNKNOWN,
                timestamp=time.time(),
                response_time=0.0,
                message=f"Protocol-specific check failed: {str(e)}"
            )
    
    async def _check_wireguard_health(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check WireGuard-specific health."""
        try:
            # Simple WireGuard handshake test
            # This is a simplified version - in practice, you'd implement actual WireGuard protocol checks
            
            start_time = time.time()
            
            # Try to establish a WireGuard-like connection
            # For now, just check if the port responds to UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send a simple test packet
            test_packet = b'\x01\x00\x00\x00' + b'\x00' * 40  # Simplified handshake initiation
            sock.sendto(test_packet, (server.ip_address, server.port))
            
            try:
                data, _ = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000
                
                return HealthCheckResult(
                    server_id=server.server_id,
                    check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                    status=HealthStatus.HEALTHY,
                    timestamp=time.time(),
                    response_time=response_time,
                    message="WireGuard protocol responding",
                    details={'protocol': 'wireguard', 'response_length': len(data)}
                )
                
            except socket.timeout:
                return HealthCheckResult(
                    server_id=server.server_id,
                    check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                    status=HealthStatus.WARNING,
                    timestamp=time.time(),
                    response_time=self.timeout * 1000,
                    message="WireGuard protocol not responding",
                    details={'protocol': 'wireguard'}
                )
            finally:
                sock.close()
                
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message=f"WireGuard check failed: {str(e)}"
            )
    
    async def _check_openvpn_health(self, server: VPNServer) -> Optional[HealthCheckResult]:
        """Check OpenVPN-specific health."""
        try:
            # Simple OpenVPN management interface check
            # This would typically connect to OpenVPN's management port
            
            start_time = time.time()
            
            # Try to connect to OpenVPN management interface (if available)
            management_port = server.port + 1  # Common convention
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server.ip_address, management_port),
                    timeout=self.timeout
                )
                
                response_time = (time.time() - start_time) * 1000
                
                # Send management command
                writer.write(b'STATUS\n')
                await writer.drain()
                
                response = await reader.read(1024)
                
                writer.close()
                await writer.wait_closed()
                
                return HealthCheckResult(
                    server_id=server.server_id,
                    check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                    status=HealthStatus.HEALTHY,
                    timestamp=time.time(),
                    response_time=response_time,
                    message="OpenVPN management interface responding",
                    details={
                        'protocol': 'openvpn',
                        'management_port': management_port,
                        'status_response': response.decode('utf-8', errors='ignore')[:100]
                    }
                )
                
            except (asyncio.TimeoutError, ConnectionRefusedError):
                # Management interface not available, but main port might be working
                return HealthCheckResult(
                    server_id=server.server_id,
                    check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                    status=HealthStatus.UNKNOWN,
                    timestamp=time.time(),
                    response_time=0.0,
                    message="OpenVPN management interface not available",
                    details={'protocol': 'openvpn', 'management_port': management_port}
                )
                
        except Exception as e:
            return HealthCheckResult(
                server_id=server.server_id,
                check_type=HealthCheckType.PROTOCOL_SPECIFIC,
                status=HealthStatus.CRITICAL,
                timestamp=time.time(),
                response_time=0.0,
                message=f"OpenVPN check failed: {str(e)}"
            )
    
    def _process_health_result(self, result: HealthCheckResult):
        """Process health check result and update server status."""
        try:
            # Store result
            if result.server_id not in self.health_results:
                self.health_results[result.server_id] = []
            
            self.health_results[result.server_id].append(result)
            
            # Keep only recent results (last 10)
            if len(self.health_results[result.server_id]) > 10:
                self.health_results[result.server_id] = self.health_results[result.server_id][-10:]
            
            # Update overall health status
            self._update_health_status(result.server_id)
            
            # Update server in registry
            self._update_server_health(result)
            
            # Trigger alerts if needed
            if result.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                self._trigger_alert(result)
            
            # Update statistics
            if result.status == HealthStatus.HEALTHY:
                self.stats['successful_checks'] += 1
            else:
                self.stats['failed_checks'] += 1
            
        except Exception as e:
            self.logger.error(f"Failed to process health result: {e}")
    
    def _update_health_status(self, server_id: str):
        """Update overall health status for a server."""
        recent_results = self.health_results.get(server_id, [])
        
        if not recent_results:
            self.health_status[server_id] = HealthStatus.UNKNOWN
            return
        
        # Get the most recent result
        latest_result = recent_results[-1]
        
        # Consider the worst status from recent checks
        worst_status = latest_result.status
        for result in recent_results[-5:]:  # Last 5 results
            if result.status.value > worst_status.value:  # Higher enum value = worse status
                worst_status = result.status
        
        self.health_status[server_id] = worst_status
    
    def _update_server_health(self, result: HealthCheckResult):
        """Update server health in registry."""
        try:
            server = self.registry.get_server(result.server_id)
            if not server:
                return
            
            # Update server status based on health
            if result.status == HealthStatus.HEALTHY:
                server.status = ServerStatus.ONLINE
            elif result.status == HealthStatus.CRITICAL:
                server.status = ServerStatus.OFFLINE
            elif result.status == HealthStatus.WARNING:
                server.status = ServerStatus.OVERLOADED
            else:
                server.status = ServerStatus.UNKNOWN
            
            # Update response time
            if result.response_time > 0:
                server.response_time = result.response_time
            
            # Update last checked time
            server.last_checked = result.timestamp
            
            # Create metrics record
            metrics = ServerMetrics(
                server_id=result.server_id,
                timestamp=result.timestamp,
                response_time=result.response_time,
                bandwidth_mbps=server.bandwidth_mbps,
                packet_loss=0.0,  # Would be calculated from packet loss checks
                uptime=1.0 if result.status == HealthStatus.HEALTHY else 0.0,
                cpu_usage=server.load,
                memory_usage=0.0,  # Would need to be collected from server
                active_connections=server.current_clients,
                error_rate=0.0  # Would be calculated from failed checks
            )
            
            self.registry.add_metrics(metrics)
            self.registry.register_server(server)
            
        except Exception as e:
            self.logger.error(f"Failed to update server health: {e}")
    
    def _trigger_alert(self, result: HealthCheckResult):
        """Trigger alert for health check result."""
        try:
            self.stats['alerts_triggered'] += 1
            
            # Call all alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(result.server_id, result)
                except Exception as e:
                    self.logger.error(f"Alert callback failed: {e}")
            
            # Log alert
            level = "WARNING" if result.status == HealthStatus.WARNING else "CRITICAL"
            self.logger.log(
                getattr(logging, level),
                f"Health Alert [{result.server_id}]: {result.message}"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to trigger alert: {e}")
    
    def add_alert_callback(self, callback: Callable[[str, HealthCheckResult], None]):
        """Add alert callback function."""
        self.alert_callbacks.append(callback)
    
    def get_server_health(self, server_id: str) -> Optional[HealthStatus]:
        """Get health status for a server."""
        return self.health_status.get(server_id)
    
    def get_server_health_results(self, server_id: str, count: int = 10) -> List[HealthCheckResult]:
        """Get recent health results for a server."""
        results = self.health_results.get(server_id, [])
        return results[-count:] if results else []
    
    def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all servers."""
        return self.health_status.copy()
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary statistics."""
        total_servers = len(self.health_status)
        healthy_servers = sum(1 for status in self.health_status.values() if status == HealthStatus.HEALTHY)
        warning_servers = sum(1 for status in self.health_status.values() if status == HealthStatus.WARNING)
        critical_servers = sum(1 for status in self.health_status.values() if status == HealthStatus.CRITICAL)
        unknown_servers = sum(1 for status in self.health_status.values() if status == HealthStatus.UNKNOWN)
        
        return {
            'total_servers': total_servers,
            'healthy_servers': healthy_servers,
            'warning_servers': warning_servers,
            'critical_servers': critical_servers,
            'unknown_servers': unknown_servers,
            'health_percentage': (healthy_servers / total_servers * 100) if total_servers > 0 else 0,
            'stats': self.stats,
            'last_check_time': self.last_check_time
        }
    
    def run_manual_check(self, server_id: str) -> Optional[HealthCheckResult]:
        """Run manual health check for a specific server."""
        try:
            server = self.registry.get_server(server_id)
            if not server:
                self.logger.error(f"Server not found: {server_id}")
                return None
            
            # Run health check synchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(self._check_server_health(server))
                if result:
                    self._process_health_result(result)
                
                return result
                
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.error(f"Manual health check failed: {e}")
            return None
