"""
Connection Resilience Manager for VPN Security Project.
This module provides comprehensive connection resilience with auto-reconnection,
network failure detection, automatic server switching, and connection quality monitoring.
"""
import time
import asyncio
import threading
import socket
import subprocess
import platform
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque, defaultdict
import statistics

from discovery import (
    AdvancedLoadBalancer, LoadBalanceAlgorithm, VPNServer, ServerStatus,
    FailoverManager, FailoverTrigger
)
from utils.logger import LoggableMixin


class ConnectionState(Enum):
    """Connection state enumeration."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    RECONNECTING = auto()
    SWITCHING_SERVER = auto()
    FAILED = auto()
    SUSPENDED = auto()


class NetworkStatus(Enum):
    """Network status enumeration."""
    UNKNOWN = auto()
    HEALTHY = auto()
    DEGRADED = auto()
    UNSTABLE = auto()
    OFFLINE = auto()


class FailureType(Enum):
    """Types of connection failures."""
    NETWORK_UNREACHABLE = auto()
    DNS_FAILURE = auto()
    SERVER_UNREACHABLE = auto()
    AUTHENTICATION_FAILURE = auto()
    PROTOCOL_ERROR = auto()
    TIMEOUT = auto()
    CONNECTION_RESET = auto()
    QUALITY_DEGRADED = auto()
    MANUAL_DISCONNECT = auto()


@dataclass
class ConnectionMetrics:
    """Connection quality metrics."""
    timestamp: float
    latency_ms: float
    packet_loss: float
    jitter_ms: float
    bandwidth_mbps: float
    connection_stability: float  # 0-1 scale
    error_rate: float
    uptime_percentage: float
    reconnection_count: int
    server_switches: int
    
    def quality_score(self) -> float:
        """Calculate overall connection quality score."""
        # Weight different metrics
        weights = {
            'latency': 0.25,
            'packet_loss': 0.20,
            'jitter': 0.15,
            'bandwidth': 0.15,
            'stability': 0.15,
            'error_rate': 0.10
        }
        
        # Normalize metrics (lower is better for some, higher for others)
        latency_score = max(0, 1 - (self.latency_ms / 1000))  # 1000ms = 0 score
        packet_loss_score = max(0, 1 - self.packet_loss)
        jitter_score = max(0, 1 - (self.jitter_ms / 100))  # 100ms = 0 score
        bandwidth_score = min(1, self.bandwidth_mbps / 100)  # 100Mbps = 1 score
        stability_score = self.connection_stability
        error_score = max(0, 1 - self.error_rate)
        
        return (latency_score * weights['latency'] +
                packet_loss_score * weights['packet_loss'] +
                jitter_score * weights['jitter'] +
                bandwidth_score * weights['bandwidth'] +
                stability_score * weights['stability'] +
                error_score * weights['error_rate'])


@dataclass
class ReconnectionConfig:
    """Reconnection configuration."""
    max_attempts: int = 5
    initial_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    enable_exponential_backoff: bool = True
    enable_server_switching: bool = True
    server_switch_threshold: int = 3
    quality_threshold: float = 0.3
    network_check_interval: float = 5.0
    connection_timeout: float = 30.0
    keepalive_interval: float = 30.0
    keepalive_timeout: float = 10.0


@dataclass
class NetworkTestResult:
    """Network connectivity test result."""
    timestamp: float
    test_type: str
    success: bool
    latency_ms: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class ConnectionResilienceManager(LoggableMixin):
    """Comprehensive connection resilience management system."""
    
    def __init__(self, config: Dict[str, Any], load_balancer: AdvancedLoadBalancer,
                 failover_manager: FailoverManager):
        self.config = config
        self.load_balancer = load_balancer
        self.failover_manager = failover_manager
        self.resilience_config = config.get('connection_resilience', {})
        
        # Reconnection configuration
        self.reconnect_config = ReconnectionConfig(**self.resilience_config.get('reconnection', {}))
        
        # Connection state
        self.connection_state = ConnectionState.DISCONNECTED
        self.current_server: Optional[VPNServer] = None
        self.connection_start_time: Optional[float] = None
        self.last_activity_time: Optional[float] = None
        
        # Reconnection state
        self.reconnection_attempts = 0
        self.last_reconnection_time = 0.0
        self.reconnection_history: deque = deque(maxlen=100)
        self.server_switch_count = 0
        
        # Network monitoring
        self.network_status = NetworkStatus.UNKNOWN
        self.network_tests: deque = deque(maxlen=1000)
        self.last_network_check = 0.0
        
        # Connection quality monitoring
        self.connection_metrics: deque = deque(maxlen=1000)
        self.quality_history: deque = deque(maxlen=100)
        self.current_quality_score = 0.0
        
        # Failure tracking
        self.failure_history: deque = deque(maxlen=100)
        self.failure_counts: Dict[FailureType, int] = defaultdict(int)
        self.last_failure_time: Optional[float] = None
        
        # Callbacks
        self.connection_callbacks: Dict[str, List[Callable]] = {
            'connected': [],
            'disconnected': [],
            'reconnecting': [],
            'server_switched': [],
            'quality_degraded': [],
            'network_changed': []
        }
        
        # Background tasks
        self.monitor_thread = None
        self.keepalive_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'total_reconnections': 0,
            'successful_reconnections': 0,
            'server_switches': 0,
            'average_uptime': 0.0,
            'average_quality_score': 0.0,
            'network_failures': 0,
            'server_failures': 0
        }
        
        # Initialize resilience manager
        self._initialize()
    
    def _initialize(self):
        """Initialize the connection resilience manager."""
        try:
            # Start background monitoring
            self._start_monitoring_thread()
            self._start_keepalive_thread()
            
            # Initial network check
            self._check_network_connectivity()
            
            self.logger.info("Connection resilience manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize connection resilience manager: {e}")
            raise
    
    def connect(self, server: Optional[VPNServer] = None, 
               client_id: str = None, client_location: Tuple[float, float] = None) -> bool:
        """Establish connection with resilience support."""
        try:
            if self.connection_state in [ConnectionState.CONNECTING, ConnectionState.RECONNECTING]:
                self.logger.warning("Connection already in progress")
                return False
            
            # Select server if not provided
            if not server:
                server = self._select_optimal_server(client_id, client_location)
                if not server:
                    self.logger.error("No suitable server available")
                    return False
            
            self.connection_state = ConnectionState.CONNECTING
            self.connection_start_time = time.time()
            
            # Attempt connection
            success = self._establish_connection(server)
            
            if success:
                self.connection_state = ConnectionState.CONNECTED
                self.current_server = server
                self.reconnection_attempts = 0
                self.last_activity_time = time.time()
                
                # Update statistics
                self.stats['total_connections'] += 1
                self.stats['successful_connections'] += 1
                
                # Trigger callbacks
                self._trigger_callbacks('connected', {
                    'server': server,
                    'connection_time': time.time() - self.connection_start_time
                })
                
                self.logger.info(f"Connected to server {server.server_id}")
                return True
            else:
                self.connection_state = ConnectionState.FAILED
                self.stats['total_connections'] += 1
                self.stats['failed_connections'] += 1
                
                self.logger.error("Connection failed")
                return False
                
        except Exception as e:
            self.connection_state = ConnectionState.FAILED
            self.logger.error(f"Connection error: {e}")
            return False
    
    def _select_optimal_server(self, client_id: str = None, 
                              client_location: Tuple[float, float] = None) -> Optional[VPNServer]:
        """Select optimal server considering resilience factors."""
        try:
            # Get servers with good recent performance
            exclude_servers = set()
            
            # Exclude servers with recent failures
            for failure in list(self.failure_history)[-10:]:
                if time.time() - failure['timestamp'] < 300:  # Last 5 minutes
                    exclude_servers.add(failure['server_id'])
            
            # Select server using health-aware algorithm
            server = self.load_balancer.select_server(
                client_id=client_id,
                client_location=client_location,
                algorithm=LoadBalanceAlgorithm.HEALTH_AWARE,
                exclude_servers=exclude_servers
            )
            
            return server
            
        except Exception as e:
            self.logger.error(f"Failed to select optimal server: {e}")
            return None
    
    def _establish_connection(self, server: VPNServer) -> bool:
        """Establish connection to a server."""
        try:
            self.logger.info(f"Establishing connection to {server.server_id}")
            
            # Test basic connectivity first
            if not self._test_server_connectivity(server):
                return False
            
            # Here you would implement the actual VPN connection logic
            # For now, we'll simulate the connection
            
            # Simulate connection establishment
            time.sleep(0.1)  # Simulate connection time
            
            # Test connection quality
            if not self._test_connection_quality(server):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to establish connection: {e}")
            return False
    
    def _test_server_connectivity(self, server: VPNServer) -> bool:
        """Test basic server connectivity."""
        try:
            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.reconnect_config.connection_timeout)
            
            result = sock.connect_ex((server.ip_address, server.port))
            sock.close()
            
            if result != 0:
                self._record_failure(FailureType.SERVER_UNREACHABLE, 
                                  f"Cannot connect to {server.ip_address}:{server.port}")
                return False
            
            return True
            
        except Exception as e:
            self._record_failure(FailureType.NETWORK_UNREACHABLE, str(e))
            return False
    
    def _test_connection_quality(self, server: VPNServer) -> bool:
        """Test connection quality metrics."""
        try:
            # Measure latency
            start_time = time.time()
            
            # Simple ping test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((server.ip_address, server.port))
            sock.close()
            
            latency = (time.time() - start_time) * 1000
            
            # Check if latency is acceptable
            if latency > 1000:  # 1 second
                self._record_failure(FailureType.QUALITY_DEGRADED, 
                                  f"High latency: {latency:.2f}ms")
                return False
            
            # Record quality metrics
            metrics = ConnectionMetrics(
                timestamp=time.time(),
                latency_ms=latency,
                packet_loss=0.0,
                jitter_ms=0.0,
                bandwidth_mbps=0.0,  # Would measure actual bandwidth
                connection_stability=1.0,
                error_rate=0.0,
                uptime_percentage=100.0,
                reconnection_count=self.reconnection_attempts,
                server_switches=self.server_switch_count
            )
            
            self.connection_metrics.append(metrics)
            self.current_quality_score = metrics.quality_score()
            
            return self.current_quality_score >= self.reconnect_config.quality_threshold
            
        except Exception as e:
            self._record_failure(FailureType.TIMEOUT, str(e))
            return False
    
    def disconnect(self, reason: str = "manual"):
        """Disconnect from current server."""
        try:
            if self.connection_state == ConnectionState.DISCONNECTED:
                return
            
            # Record disconnection
            self._record_failure(FailureType.MANUAL_DISCONNECT, reason)
            
            # Update state
            self.connection_state = ConnectionState.DISCONNECTED
            self.current_server = None
            
            # Trigger callbacks
            self._trigger_callbacks('disconnected', {'reason': reason})
            
            self.logger.info(f"Disconnected: {reason}")
            
        except Exception as e:
            self.logger.error(f"Disconnect error: {e}")
    
    def start_auto_reconnection(self):
        """Start automatic reconnection process."""
        try:
            if self.connection_state == ConnectionState.CONNECTED:
                self.logger.warning("Already connected, no reconnection needed")
                return
            
            self.connection_state = ConnectionState.RECONNECTING
            self.reconnection_attempts += 1
            self.last_reconnection_time = time.time()
            
            # Trigger callbacks
            self._trigger_callbacks('reconnecting', {
                'attempt': self.reconnection_attempts,
                'max_attempts': self.reconnect_config.max_attempts
            })
            
            # Start reconnection process
            asyncio.create_task(self._reconnection_loop())
            
        except Exception as e:
            self.logger.error(f"Failed to start auto-reconnection: {e}")
    
    async def _reconnection_loop(self):
        """Main reconnection loop with exponential backoff."""
        try:
            for attempt in range(self.reconnection_attempts, 
                               self.reconnect_config.max_attempts + 1):
                
                self.logger.info(f"Reconnection attempt {attempt}/{self.reconnect_config.max_attempts}")
                
                # Calculate delay
                delay = self._calculate_reconnection_delay(attempt)
                
                if delay > 0:
                    await asyncio.sleep(delay)
                
                # Check network connectivity first
                if not self._check_network_connectivity():
                    self.logger.warning("Network not ready, waiting...")
                    continue
                
                # Attempt reconnection
                success = self._attempt_reconnection(attempt)
                
                if success:
                    self.logger.info(f"Reconnection successful on attempt {attempt}")
                    self.stats['total_reconnections'] += 1
                    self.stats['successful_reconnections'] += 1
                    
                    # Record successful reconnection
                    self.reconnection_history.append({
                        'timestamp': time.time(),
                        'attempt': attempt,
                        'success': True,
                        'server_id': self.current_server.server_id if self.current_server else None
                    })
                    
                    return
                else:
                    self.logger.warning(f"Reconnection attempt {attempt} failed")
                    
                    # Record failed attempt
                    self.reconnection_history.append({
                        'timestamp': time.time(),
                        'attempt': attempt,
                        'success': False,
                        'server_id': self.current_server.server_id if self.current_server else None
                    })
            
            # All attempts failed
            self.connection_state = ConnectionState.FAILED
            self.stats['total_reconnections'] += 1
            
            self.logger.error("All reconnection attempts failed")
            
        except Exception as e:
            self.logger.error(f"Reconnection loop error: {e}")
    
    def _calculate_reconnection_delay(self, attempt: int) -> float:
        """Calculate reconnection delay with exponential backoff."""
        try:
            if self.reconnect_config.enable_exponential_backoff:
                delay = self.reconnect_config.initial_delay * (
                    self.reconnect_config.backoff_multiplier ** (attempt - 1)
                )
                delay = min(delay, self.reconnect_config.max_delay)
            else:
                delay = self.reconnect_config.initial_delay
            
            # Add jitter if enabled
            if self.reconnect_config.jitter:
                import random
                jitter = random.uniform(0.1, 0.3) * delay
                delay += jitter
            
            return delay
            
        except Exception as e:
            self.logger.error(f"Failed to calculate reconnection delay: {e}")
            return self.reconnect_config.initial_delay
    
    def _attempt_reconnection(self, attempt: int) -> bool:
        """Attempt to reconnect to a server."""
        try:
            # Check if we should switch servers
            if (self.reconnect_config.enable_server_switching and 
                attempt >= self.reconnect_config.server_switch_threshold):
                
                return self._switch_server_and_reconnect(attempt)
            else:
                # Try to reconnect to the same server
                if self.current_server:
                    return self._establish_connection(self.current_server)
                else:
                    # No current server, select a new one
                    server = self._select_optimal_server()
                    return server and self._establish_connection(server)
            
        except Exception as e:
            self.logger.error(f"Reconnection attempt failed: {e}")
            return False
    
    def _switch_server_and_reconnect(self, attempt: int) -> bool:
        """Switch to a different server and reconnect."""
        try:
            self.connection_state = ConnectionState.SWITCHING_SERVER
            
            # Get current server to exclude it
            exclude_servers = {self.current_server.server_id} if self.current_server else set()
            
            # Select a different server
            new_server = self.load_balancer.select_server(
                exclude_servers=exclude_servers,
                algorithm=LoadBalanceAlgorithm.HEALTH_AWARE
            )
            
            if not new_server:
                self.logger.error("No alternative servers available")
                return False
            
            self.logger.info(f"Switching to server {new_server.server_id}")
            
            # Connect to new server
            success = self._establish_connection(new_server)
            
            if success:
                self.server_switch_count += 1
                self.stats['server_switches'] += 1
                
                # Trigger callbacks
                self._trigger_callbacks('server_switched', {
                    'old_server': self.current_server.server_id if self.current_server else None,
                    'new_server': new_server.server_id,
                    'attempt': attempt
                })
                
                self.logger.info(f"Successfully switched to {new_server.server_id}")
                return True
            else:
                self.logger.error(f"Failed to connect to alternative server {new_server.server_id}")
                return False
            
        except Exception as e:
            self.logger.error(f"Server switch failed: {e}")
            return False
    
    def _check_network_connectivity(self) -> bool:
        """Check network connectivity status."""
        try:
            current_time = time.time()
            
            # Rate limit network checks
            if current_time - self.last_network_check < self.reconnect_config.network_check_interval:
                return self.network_status in [NetworkStatus.HEALTHY, NetworkStatus.DEGRADED]
            
            self.last_network_check = current_time
            
            # Test basic connectivity
            tests = [
                self._test_dns_resolution(),
                self._test_internet_connectivity(),
                self._test_local_network()
            ]
            
            success_count = sum(1 for test in tests if test.success)
            
            # Determine network status
            if success_count == 3:
                self.network_status = NetworkStatus.HEALTHY
            elif success_count >= 2:
                self.network_status = NetworkStatus.DEGRADED
            elif success_count >= 1:
                self.network_status = NetworkStatus.UNSTABLE
            else:
                self.network_status = NetworkStatus.OFFLINE
            
            # Trigger network change callback
            old_status = getattr(self, '_last_network_status', NetworkStatus.UNKNOWN)
            if old_status != self.network_status:
                self._trigger_callbacks('network_changed', {
                    'old_status': old_status.name,
                    'new_status': self.network_status.name
                })
                self._last_network_status = self.network_status
            
            return self.network_status in [NetworkStatus.HEALTHY, NetworkStatus.DEGRADED]
            
        except Exception as e:
            self.logger.error(f"Network connectivity check failed: {e}")
            self.network_status = NetworkStatus.UNKNOWN
            return False
    
    def _test_dns_resolution(self) -> NetworkTestResult:
        """Test DNS resolution."""
        try:
            start_time = time.time()
            
            # Test DNS resolution
            socket.gethostbyname('google.com')
            
            latency = (time.time() - start_time) * 1000
            
            result = NetworkTestResult(
                timestamp=time.time(),
                test_type='dns_resolution',
                success=True,
                latency_ms=latency,
                details={'target': 'google.com'}
            )
            
            self.network_tests.append(result)
            return result
            
        except Exception as e:
            result = NetworkTestResult(
                timestamp=time.time(),
                test_type='dns_resolution',
                success=False,
                latency_ms=0,
                error_message=str(e)
            )
            
            self.network_tests.append(result)
            self._record_failure(FailureType.DNS_FAILURE, str(e))
            return result
    
    def _test_internet_connectivity(self) -> NetworkTestResult:
        """Test internet connectivity."""
        try:
            start_time = time.time()
            
            # Test connectivity to a reliable server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            
            latency = (time.time() - start_time) * 1000
            
            success = result == 0
            
            test_result = NetworkTestResult(
                timestamp=time.time(),
                test_type='internet_connectivity',
                success=success,
                latency_ms=latency,
                error_message=None if success else "Connection failed",
                details={'target': '8.8.8.8:53'}
            )
            
            self.network_tests.append(test_result)
            return test_result
            
        except Exception as e:
            result = NetworkTestResult(
                timestamp=time.time(),
                test_type='internet_connectivity',
                success=False,
                latency_ms=0,
                error_message=str(e)
            )
            
            self.network_tests.append(result)
            return result
    
    def _test_local_network(self) -> NetworkTestResult:
        """Test local network connectivity."""
        try:
            start_time = time.time()
            
            # Test local gateway connectivity
            import subprocess
            
            if platform.system().lower() == 'windows':
                # Windows
                result = subprocess.run(['ping', '-n', '1', '192.168.1.1'], 
                                      capture_output=True, text=True, timeout=5)
            else:
                # Linux/Mac
                result = subprocess.run(['ping', '-c', '1', '192.168.1.1'], 
                                      capture_output=True, text=True, timeout=5)
            
            latency = (time.time() - start_time) * 1000
            success = result.returncode == 0
            
            test_result = NetworkTestResult(
                timestamp=time.time(),
                test_type='local_network',
                success=success,
                latency_ms=latency,
                error_message=None if success else "Local gateway unreachable",
                details={'target': '192.168.1.1', 'ping_output': result.stdout[:100]}
            )
            
            self.network_tests.append(test_result)
            return test_result
            
        except Exception as e:
            result = NetworkTestResult(
                timestamp=time.time(),
                test_type='local_network',
                success=False,
                latency_ms=0,
                error_message=str(e)
            )
            
            self.network_tests.append(result)
            return result
    
    def _monitor_connection_quality(self):
        """Monitor connection quality and trigger actions if needed."""
        try:
            if self.connection_state != ConnectionState.CONNECTED:
                return
            
            current_time = time.time()
            
            # Check if enough time has passed for quality monitoring
            if (self.last_activity_time and 
                current_time - self.last_activity_time < 30):
                return
            
            # Measure current quality metrics
            if self.current_server:
                quality_test = self._test_connection_quality(self.current_server)
                
                if quality_test:
                    # Check if quality has degraded significantly
                    if self.current_quality_score < self.reconnect_config.quality_threshold:
                        self.logger.warning(f"Connection quality degraded: {self.current_quality_score:.2f}")
                        
                        # Trigger quality degraded callback
                        self._trigger_callbacks('quality_degraded', {
                            'current_score': self.current_quality_score,
                            'threshold': self.reconnect_config.quality_threshold,
                            'server': self.current_server.server_id
                        })
                        
                        # Consider switching servers
                        if self.reconnect_config.enable_server_switching:
                            self.logger.info("Initiating server switch due to quality degradation")
                            self._switch_server_and_reconnection(1)
            
        except Exception as e:
            self.logger.error(f"Connection quality monitoring failed: {e}")
    
    def _record_failure(self, failure_type: FailureType, message: str = None):
        """Record a connection failure."""
        try:
            current_time = time.time()
            
            # Update failure counts
            self.failure_counts[failure_type] += 1
            
            # Record failure in history
            failure_record = {
                'timestamp': current_time,
                'type': failure_type.name,
                'message': message,
                'server_id': self.current_server.server_id if self.current_server else None,
                'connection_state': self.connection_state.name
            }
            
            self.failure_history.append(failure_record)
            self.last_failure_time = current_time
            
            # Update statistics
            if failure_type in [FailureType.NETWORK_UNREACHABLE, FailureType.DNS_FAILURE]:
                self.stats['network_failures'] += 1
            elif failure_type in [FailureType.SERVER_UNREACHABLE, FailureType.AUTHENTICATION_FAILURE]:
                self.stats['server_failures'] += 1
            
            self.logger.warning(f"Connection failure recorded: {failure_type.name} - {message}")
            
        except Exception as e:
            self.logger.error(f"Failed to record failure: {e}")
    
    def _trigger_callbacks(self, event_type: str, data: Dict[str, Any]):
        """Trigger event callbacks."""
        try:
            for callback in self.connection_callbacks.get(event_type, []):
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Callback failed for {event_type}: {e}")
        except Exception as e:
            self.logger.error(f"Failed to trigger callbacks: {e}")
    
    def _start_monitoring_thread(self):
        """Start background monitoring thread."""
        def monitoring_worker():
            while self.running:
                try:
                    # Monitor network connectivity
                    self._check_network_connectivity()
                    
                    # Monitor connection quality
                    self._monitor_connection_quality()
                    
                    # Update statistics
                    self._update_statistics()
                    
                    time.sleep(10)  # Monitor every 10 seconds
                    
                except Exception as e:
                    self.logger.error(f"Monitoring thread error: {e}")
                    time.sleep(5)
        
        self.monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Started connection monitoring thread")
    
    def _start_keepalive_thread(self):
        """Start keepalive thread for connection maintenance."""
        def keepalive_worker():
            while self.running:
                try:
                    if self.connection_state == ConnectionState.CONNECTED and self.current_server:
                        # Send keepalive
                        self._send_keepalive()
                    
                    time.sleep(self.reconnect_config.keepalive_interval)
                    
                except Exception as e:
                    self.logger.error(f"Keepalive thread error: {e}")
                    time.sleep(5)
        
        self.keepalive_thread = threading.Thread(target=keepalive_worker, daemon=True)
        self.keepalive_thread.start()
        self.logger.info("Started keepalive thread")
    
    def _send_keepalive(self):
        """Send keepalive to maintain connection."""
        try:
            if not self.current_server:
                return
            
            # Simple keepalive - test connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.reconnect_config.keepalive_timeout)
            
            result = sock.connect_ex((self.current_server.ip_address, self.current_server.port))
            sock.close()
            
            if result != 0:
                self.logger.warning("Keepalive failed, connection may be lost")
                self._record_failure(FailureType.CONNECTION_RESET, "Keepalive failed")
                
                # Trigger reconnection
                self.start_auto_reconnection()
            else:
                self.last_activity_time = time.time()
                
        except Exception as e:
            self.logger.error(f"Keepalive error: {e}")
            self._record_failure(FailureType.CONNECTION_RESET, str(e))
    
    def _update_statistics(self):
        """Update connection statistics."""
        try:
            current_time = time.time()
            
            # Update uptime
            if (self.connection_start_time and 
                self.connection_state == ConnectionState.CONNECTED):
                uptime = current_time - self.connection_start_time
                
                # Update average uptime
                total_connections = self.stats['total_connections']
                if total_connections > 0:
                    self.stats['average_uptime'] = (
                        (self.stats['average_uptime'] * (total_connections - 1) + uptime) /
                        total_connections
                    )
            
            # Update average quality score
            if self.connection_metrics:
                recent_scores = [m.quality_score() for m in list(self.connection_metrics)[-10:]]
                if recent_scores:
                    self.stats['average_quality_score'] = statistics.mean(recent_scores)
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def add_connection_callback(self, event_type: str, callback: Callable):
        """Add connection event callback."""
        if event_type not in self.connection_callbacks:
            self.connection_callbacks[event_type] = []
        
        self.connection_callbacks[event_type].append(callback)
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get comprehensive connection status."""
        try:
            uptime = 0.0
            if self.connection_start_time and self.connection_state == ConnectionState.CONNECTED:
                uptime = time.time() - self.connection_start_time
            
            return {
                'connection_state': self.connection_state.name,
                'current_server': self.current_server.server_id if self.current_server else None,
                'uptime_seconds': uptime,
                'reconnection_attempts': self.reconnection_attempts,
                'server_switches': self.server_switch_count,
                'network_status': self.network_status.name,
                'quality_score': self.current_quality_score,
                'last_activity': self.last_activity_time,
                'stats': self.stats,
                'failure_counts': {k.name: v for k, v in self.failure_counts.items()},
                'recent_failures': list(self.failure_history)[-5:]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get connection status: {e}")
            return {}
    
    def get_connection_quality_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get connection quality history."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            recent_metrics = [m for m in self.connection_metrics if m.timestamp >= cutoff_time]
            
            return [m.__dict__ for m in recent_metrics]
            
        except Exception as e:
            self.logger.error(f"Failed to get quality history: {e}")
            return []
    
    def get_network_test_results(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get network test results."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            recent_tests = [t for t in self.network_tests if t.timestamp >= cutoff_time]
            
            return [t.__dict__ for t in recent_tests]
            
        except Exception as e:
            self.logger.error(f"Failed to get network test results: {e}")
            return []
    
    def reset_statistics(self):
        """Reset connection statistics."""
        try:
            self.stats = {
                'total_connections': 0,
                'successful_connections': 0,
                'failed_connections': 0,
                'total_reconnections': 0,
                'successful_reconnections': 0,
                'server_switches': 0,
                'average_uptime': 0.0,
                'average_quality_score': 0.0,
                'network_failures': 0,
                'server_failures': 0
            }
            
            self.failure_counts.clear()
            self.reconnection_attempts = 0
            self.server_switch_count = 0
            
            self.logger.info("Connection statistics reset")
            
        except Exception as e:
            self.logger.error(f"Failed to reset statistics: {e}")
    
    def stop(self):
        """Stop the connection resilience manager."""
        try:
            self.running = False
            
            # Disconnect if connected
            if self.connection_state == ConnectionState.CONNECTED:
                self.disconnect("manager_stopped")
            
            # Wait for threads to finish
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
            
            if self.keepalive_thread and self.keepalive_thread.is_alive():
                self.keepalive_thread.join(timeout=10)
            
            self.logger.info("Connection resilience manager stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop connection resilience manager: {e}")
