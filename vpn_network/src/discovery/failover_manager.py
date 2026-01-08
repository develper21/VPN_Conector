"""
Automatic Failover Manager for VPN Security Project.
This module provides comprehensive failover management with multiple strategies,
health monitoring, and automatic recovery capabilities.
"""
import time
import asyncio
import threading
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
import heapq

from discovery.server_discovery import VPNServer, ServerStatus
from discovery.server_registry import ServerRegistry
from discovery.health_checker import HealthChecker, HealthStatus, HealthCheckResult
from discovery.advanced_load_balancer import AdvancedLoadBalancer, LoadBalanceAlgorithm
from utils.logger import LoggableMixin


class FailoverTrigger(Enum):
    """Failover trigger events."""
    HEALTH_CHECK_FAILURE = auto()
    CONNECTION_TIMEOUT = auto()
    HIGH_ERROR_RATE = auto()
    PERFORMANCE_DEGRADATION = auto()
    MANUAL_TRIGGER = auto()
    SCHEDULED_MAINTENANCE = auto()
    NETWORK_PARTITION = auto()


class FailoverState(Enum):
    """Failover state machine."""
    NORMAL = auto()
    MONITORING = auto()
    FAILING = auto()
    FAILOVER_INITIATED = auto()
    FAILOVER_COMPLETE = auto()
    RECOVERY_INITIATED = auto()
    RECOVERY_COMPLETE = auto()


@dataclass
class FailoverEvent:
    """Failover event record."""
    event_id: str
    server_id: str
    trigger: FailoverTrigger
    state: FailoverState
    timestamp: float
    error_message: Optional[str] = None
    replacement_server_id: Optional[str] = None
    recovery_time: Optional[float] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'server_id': self.server_id,
            'trigger': self.trigger.name,
            'state': self.state.name,
            'timestamp': self.timestamp,
            'error_message': self.error_message,
            'replacement_server_id': self.replacement_server_id,
            'recovery_time': self.recovery_time,
            'metrics': self.metrics
        }


@dataclass
class FailoverPolicy:
    """Failover policy configuration."""
    max_failures: int = 3
    failure_window: float = 300.0  # 5 minutes
    health_check_threshold: float = 0.5
    error_rate_threshold: float = 0.1
    response_time_threshold: float = 1000.0  # milliseconds
    recovery_check_interval: float = 60.0
    max_recovery_attempts: int = 5
    failover_timeout: float = 30.0
    enable_graceful_failover: bool = True
    enable_circuit_breaker: bool = True
    circuit_breaker_threshold: int = 5


class FailoverManager(LoggableMixin):
    """Comprehensive failover management system."""
    
    def __init__(self, config: Dict[str, Any], registry: ServerRegistry,
                 health_checker: HealthChecker, load_balancer: AdvancedLoadBalancer):
        self.config = config
        self.registry = registry
        self.health_checker = health_checker
        self.load_balancer = load_balancer
        self.failover_config = config.get('failover_manager', {})
        
        # Failover policy
        self.policy = FailoverPolicy(**self.failover_config.get('policy', {}))
        
        # State management
        self.server_states: Dict[str, FailoverState] = {}
        self.failure_counts: Dict[str, int] = {}
        self.failure_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        
        # Failover events
        self.failover_events: List[FailoverEvent] = []
        self.active_failovers: Dict[str, FailoverEvent] = {}
        
        # Recovery tracking
        self.recovery_attempts: Dict[str, int] = {}
        self.last_recovery_attempt: Dict[str, float] = {}
        
        # Callbacks
        self.failover_callbacks: List[Callable[[FailoverEvent], None]] = []
        self.recovery_callbacks: List[Callable[[FailoverEvent], None]] = []
        
        # Background tasks
        self.monitor_thread = None
        self.recovery_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_failovers': 0,
            'successful_failovers': 0,
            'failed_failovers': 0,
            'total_recoveries': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0,
            'average_failover_time': 0.0,
            'average_recovery_time': 0.0,
            'circuit_breaker_trips': 0
        }
        
        # Initialize failover manager
        self._initialize()
    
    def _initialize(self):
        """Initialize the failover manager."""
        try:
            # Initialize server states
            servers = self.registry.get_all_servers()
            for server in servers:
                self.server_states[server.server_id] = FailoverState.NORMAL
                self.failure_counts[server.server_id] = 0
                self.circuit_breakers[server.server_id] = {
                    'state': 'closed',
                    'failures': 0,
                    'last_failure': 0.0,
                    'trip_time': 0.0
                }
            
            # Start background monitoring
            self._start_monitoring_thread()
            self._start_recovery_thread()
            
            self.logger.info(f"Failover manager initialized for {len(servers)} servers")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize failover manager: {e}")
            raise
    
    def trigger_failover(self, server_id: str, trigger: FailoverTrigger, 
                        error_message: str = None, metrics: Dict[str, Any] = None) -> bool:
        """Trigger failover for a server."""
        try:
            # Check if failover is needed
            if not self._should_trigger_failover(server_id, trigger, metrics):
                return False
            
            # Create failover event
            event_id = f"failover_{int(time.time())}_{server_id}"
            event = FailoverEvent(
                event_id=event_id,
                server_id=server_id,
                trigger=trigger,
                state=FailoverState.FAILOVER_INITIATED,
                timestamp=time.time(),
                error_message=error_message,
                metrics=metrics or {}
            )
            
            # Update server state
            self.server_states[server_id] = FailoverState.FAILOVER_INITIATED
            self.active_failovers[server_id] = event
            
            # Execute failover
            success = self._execute_failover(event)
            
            if success:
                event.state = FailoverState.FAILOVER_COMPLETE
                self.stats['successful_failovers'] += 1
                
                # Trigger callbacks
                for callback in self.failover_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        self.logger.error(f"Failover callback failed: {e}")
                
                self.logger.info(f"Failover completed for server {server_id}")
            else:
                event.state = FailoverState.NORMAL
                self.stats['failed_failovers'] += 1
                self.logger.error(f"Failover failed for server {server_id}")
            
            # Record event
            self.failover_events.append(event)
            self.stats['total_failovers'] += 1
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to trigger failover for {server_id}: {e}")
            return False
    
    def _should_trigger_failover(self, server_id: str, trigger: FailoverTrigger,
                                metrics: Dict[str, Any]) -> bool:
        """Determine if failover should be triggered."""
        try:
            # Check circuit breaker
            if self.policy.enable_circuit_breaker:
                circuit_state = self.circuit_breakers.get(server_id, {})
                if circuit_state.get('state') == 'open':
                    # Check if circuit breaker should be half-open
                    if time.time() - circuit_state.get('trip_time', 0) > 60:  # 1 minute timeout
                        circuit_state['state'] = 'half-open'
                    else:
                        return False
            
            # Check failure count
            failure_count = self.failure_counts.get(server_id, 0)
            if failure_count >= self.policy.max_failures:
                return True
            
            # Check trigger-specific conditions
            if trigger == FailoverTrigger.HEALTH_CHECK_FAILURE:
                health_status = self.health_checker.get_server_health(server_id)
                return health_status in [HealthStatus.CRITICAL, HealthStatus.WARNING]
            
            elif trigger == FailoverTrigger.HIGH_ERROR_RATE:
                error_rate = metrics.get('error_rate', 0.0)
                return error_rate >= self.policy.error_rate_threshold
            
            elif trigger == FailoverTrigger.PERFORMANCE_DEGRADATION:
                response_time = metrics.get('response_time', 0.0)
                return response_time >= self.policy.response_time_threshold
            
            elif trigger == FailoverTrigger.CONNECTION_TIMEOUT:
                return True  # Always trigger on timeout
            
            elif trigger == FailoverTrigger.MANUAL_TRIGGER:
                return True  # Always trigger manual failover
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check failover conditions: {e}")
            return False
    
    def _execute_failover(self, event: FailoverEvent) -> bool:
        """Execute the failover process."""
        try:
            start_time = time.time()
            
            # Step 1: Find replacement server
            replacement_server = self._find_replacement_server(event.server_id)
            
            if not replacement_server:
                self.logger.error(f"No replacement server found for {event.server_id}")
                return False
            
            event.replacement_server_id = replacement_server.server_id
            
            # Step 2: Graceful failover if enabled
            if self.policy.enable_graceful_failover:
                success = self._graceful_failover(event.server_id, replacement_server.server_id)
            else:
                success = self._immediate_failover(event.server_id, replacement_server.server_id)
            
            if success:
                # Step 3: Update load balancer
                self.load_balancer.handle_server_failure(event.server_id, event.error_message)
                
                # Step 4: Update circuit breaker
                if self.policy.enable_circuit_breaker:
                    self._trip_circuit_breaker(event.server_id)
                
                # Update statistics
                failover_time = time.time() - start_time
                self.stats['average_failover_time'] = (
                    (self.stats['average_failover_time'] * (self.stats['total_failovers'] - 1) + failover_time) /
                    self.stats['total_failovers']
                )
                
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Failover execution failed: {e}")
            return False
    
    def _find_replacement_server(self, failed_server_id: str) -> Optional[VPNServer]:
        """Find the best replacement server."""
        try:
            # Get candidate servers (exclude failed and currently failing servers)
            exclude_servers = {failed_server_id}
            exclude_servers.update(self.active_failovers.keys())
            
            # Use load balancer to find best replacement
            replacement = self.load_balancer.select_server(
                exclude_servers=exclude_servers,
                algorithm=LoadBalanceAlgorithm.HEALTH_AWARE
            )
            
            return replacement
            
        except Exception as e:
            self.logger.error(f"Failed to find replacement server: {e}")
            return None
    
    def _graceful_failover(self, failed_server_id: str, replacement_server_id: str) -> bool:
        """Perform graceful failover."""
        try:
            # Step 1: Drain connections from failed server
            self._drain_server_connections(failed_server_id)
            
            # Step 2: Wait for existing connections to finish
            time.sleep(5)  # Grace period
            
            # Step 3: Mark failed server as offline
            server = self.registry.get_server(failed_server_id)
            if server:
                server.status = ServerStatus.OFFLINE
                self.registry.register_server(server)
            
            # Step 4: Verify replacement server is healthy
            health_result = self.health_checker.run_manual_check(replacement_server_id)
            
            if health_result and health_result.status == HealthStatus.HEALTHY:
                return True
            else:
                self.logger.error(f"Replacement server {replacement_server_id} is not healthy")
                return False
                
        except Exception as e:
            self.logger.error(f"Graceful failover failed: {e}")
            return False
    
    def _immediate_failover(self, failed_server_id: str, replacement_server_id: str) -> bool:
        """Perform immediate failover."""
        try:
            # Mark failed server as offline immediately
            server = self.registry.get_server(failed_server_id)
            if server:
                server.status = ServerStatus.OFFLINE
                self.registry.register_server(server)
            
            # Verify replacement server
            health_result = self.health_checker.run_manual_check(replacement_server_id)
            
            return health_result and health_result.status == HealthStatus.HEALTHY
            
        except Exception as e:
            self.logger.error(f"Immediate failover failed: {e}")
            return False
    
    def _drain_server_connections(self, server_id: str):
        """Drain connections from a server."""
        try:
            # This would integrate with the actual connection management
            # For now, we'll just log the action
            self.logger.info(f"Draining connections from server {server_id}")
            
            # In a real implementation, this would:
            # 1. Stop accepting new connections
            # 2. Wait for existing connections to complete
            # 3. Close idle connections
            # 4. Update connection counts
            
        except Exception as e:
            self.logger.error(f"Failed to drain connections from {server_id}: {e}")
    
    def _trip_circuit_breaker(self, server_id: str):
        """Trip the circuit breaker for a server."""
        try:
            circuit_breaker = self.circuit_breakers.get(server_id, {})
            circuit_breaker['state'] = 'open'
            circuit_breaker['failures'] += 1
            circuit_breaker['trip_time'] = time.time()
            
            self.circuit_breakers[server_id] = circuit_breaker
            self.stats['circuit_breaker_trips'] += 1
            
            self.logger.warning(f"Circuit breaker tripped for server {server_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to trip circuit breaker: {e}")
    
    def initiate_recovery(self, server_id: str) -> bool:
        """Initiate recovery for a failed server."""
        try:
            # Check if recovery is possible
            if server_id not in self.active_failovers:
                self.logger.warning(f"No active failover found for server {server_id}")
                return False
            
            # Check recovery attempt limit
            recovery_attempts = self.recovery_attempts.get(server_id, 0)
            if recovery_attempts >= self.policy.max_recovery_attempts:
                self.logger.error(f"Max recovery attempts reached for server {server_id}")
                return False
            
            # Check recovery interval
            last_attempt = self.last_recovery_attempt.get(server_id, 0)
            if time.time() - last_attempt < self.policy.recovery_check_interval:
                return False
            
            # Create recovery event
            event = self.active_failovers[server_id]
            event.state = FailoverState.RECOVERY_INITIATED
            
            # Update recovery tracking
            self.recovery_attempts[server_id] = recovery_attempts + 1
            self.last_recovery_attempt[server_id] = time.time()
            
            # Execute recovery
            success = self._execute_recovery(event)
            
            if success:
                event.state = FailoverState.RECOVERY_COMPLETE
                event.recovery_time = time.time()
                
                # Update server state
                self.server_states[server_id] = FailoverState.NORMAL
                self.failure_counts[server_id] = 0
                
                # Reset circuit breaker
                if self.policy.enable_circuit_breaker:
                    self.circuit_breakers[server_id]['state'] = 'closed'
                    self.circuit_breakers[server_id]['failures'] = 0
                
                # Remove from active failovers
                self.active_failovers.pop(server_id, None)
                
                # Trigger callbacks
                for callback in self.recovery_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        self.logger.error(f"Recovery callback failed: {e}")
                
                self.stats['successful_recoveries'] += 1
                self.logger.info(f"Recovery completed for server {server_id}")
                
            else:
                self.stats['failed_recoveries'] += 1
                self.logger.error(f"Recovery failed for server {server_id}")
            
            self.stats['total_recoveries'] += 1
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to initiate recovery for {server_id}: {e}")
            return False
    
    def _execute_recovery(self, event: FailoverEvent) -> bool:
        """Execute the recovery process."""
        try:
            start_time = time.time()
            
            # Step 1: Perform comprehensive health check
            health_result = self.health_checker.run_manual_check(event.server_id)
            
            if not health_result or health_result.status != HealthStatus.HEALTHY:
                self.logger.error(f"Server {event.server_id} is not healthy for recovery")
                return False
            
            # Step 2: Test server functionality
            if not self._test_server_functionality(event.server_id):
                self.logger.error(f"Server {event.server_id} functionality test failed")
                return False
            
            # Step 3: Mark server as online
            server = self.registry.get_server(event.server_id)
            if server:
                server.status = ServerStatus.ONLINE
                self.registry.register_server(server)
            
            # Step 4: Update load balancer
            self.load_balancer.failed_servers.discard(event.server_id)
            
            # Update statistics
            recovery_time = time.time() - start_time
            self.stats['average_recovery_time'] = (
                (self.stats['average_recovery_time'] * (self.stats['total_recoveries'] - 1) + recovery_time) /
                self.stats['total_recoveries']
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Recovery execution failed: {e}")
            return False
    
    def _test_server_functionality(self, server_id: str) -> bool:
        """Test server functionality."""
        try:
            # This would perform actual functionality tests
            # For now, we'll simulate basic tests
            
            server = self.registry.get_server(server_id)
            if not server:
                return False
            
            # Test 1: Basic connectivity
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((server.ip_address, server.port))
                sock.close()
                
                if result != 0:
                    return False
            except:
                return False
            
            # Test 2: Protocol-specific tests
            if server.protocol in ['openvpn', 'both']:
                # Test OpenVPN functionality
                pass  # Would implement OpenVPN-specific tests
            
            if server.protocol in ['wireguard', 'both']:
                # Test WireGuard functionality
                pass  # Would implement WireGuard-specific tests
            
            return True
            
        except Exception as e:
            self.logger.error(f"Server functionality test failed: {e}")
            return False
    
    def record_failure(self, server_id: str, trigger: FailoverTrigger, 
                      error_message: str = None, metrics: Dict[str, Any] = None):
        """Record a server failure."""
        try:
            # Update failure count
            self.failure_counts[server_id] = self.failure_counts.get(server_id, 0) + 1
            
            # Record failure in history
            self.failure_history[server_id].append({
                'timestamp': time.time(),
                'trigger': trigger.name,
                'error_message': error_message,
                'metrics': metrics or {}
            })
            
            # Update circuit breaker
            if self.policy.enable_circuit_breaker:
                circuit_breaker = self.circuit_breakers.get(server_id, {})
                circuit_breaker['failures'] += 1
                circuit_breaker['last_failure'] = time.time()
                
                # Check if circuit breaker should trip
                if circuit_breaker['failures'] >= self.policy.circuit_breaker_threshold:
                    self._trip_circuit_breaker(server_id)
            
            # Check if failover should be triggered
            if self.failure_counts[server_id] >= self.policy.max_failures:
                self.trigger_failover(server_id, trigger, error_message, metrics)
            
        except Exception as e:
            self.logger.error(f"Failed to record failure: {e}")
    
    def _start_monitoring_thread(self):
        """Start background monitoring thread."""
        def monitoring_worker():
            while self.running:
                try:
                    self._monitor_server_health()
                    time.sleep(30)  # Monitor every 30 seconds
                except Exception as e:
                    self.logger.error(f"Monitoring thread error: {e}")
                    time.sleep(10)
        
        self.monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Started failover monitoring thread")
    
    def _monitor_server_health(self):
        """Monitor server health and trigger failover if needed."""
        try:
            servers = self.registry.get_all_servers()
            
            for server in servers:
                # Skip servers that are already in failover
                if server.server_id in self.active_failovers:
                    continue
                
                # Get health status
                health_status = self.health_checker.get_server_health(server.server_id)
                
                # Check for health issues
                if health_status == HealthStatus.CRITICAL:
                    self.record_failure(
                        server.server_id,
                        FailoverTrigger.HEALTH_CHECK_FAILURE,
                        "Critical health status detected"
                    )
                elif health_status == HealthStatus.WARNING:
                    # Check performance metrics
                    if server.response_time > self.policy.response_time_threshold:
                        self.record_failure(
                            server.server_id,
                            FailoverTrigger.PERFORMANCE_DEGRADATION,
                            "High response time",
                            {'response_time': server.response_time}
                        )
                    
                    if server.load > 0.9:  # 90% load
                        self.record_failure(
                            server.server_id,
                            FailoverTrigger.PERFORMANCE_DEGRADATION,
                            "High server load",
                            {'load': server.load}
                        )
            
        except Exception as e:
            self.logger.error(f"Health monitoring failed: {e}")
    
    def _start_recovery_thread(self):
        """Start background recovery thread."""
        def recovery_worker():
            while self.running:
                try:
                    self._monitor_recovery()
                    time.sleep(self.policy.recovery_check_interval)
                except Exception as e:
                    self.logger.error(f"Recovery thread error: {e}")
                    time.sleep(30)
        
        self.recovery_thread = threading.Thread(target=recovery_worker, daemon=True)
        self.recovery_thread.start()
        self.logger.info("Started failover recovery thread")
    
    def _monitor_recovery(self):
        """Monitor and attempt recovery for failed servers."""
        try:
            for server_id in list(self.active_failovers.keys()):
                self.initiate_recovery(server_id)
            
        except Exception as e:
            self.logger.error(f"Recovery monitoring failed: {e}")
    
    def add_failover_callback(self, callback: Callable[[FailoverEvent], None]):
        """Add failover event callback."""
        self.failover_callbacks.append(callback)
    
    def add_recovery_callback(self, callback: Callable[[FailoverEvent], None]):
        """Add recovery event callback."""
        self.recovery_callbacks.append(callback)
    
    def get_failover_status(self) -> Dict[str, Any]:
        """Get comprehensive failover status."""
        return {
            'stats': self.stats,
            'active_failovers': len(self.active_failovers),
            'failed_servers': list(self.active_failovers.keys()),
            'server_states': {k: v.name for k, v in self.server_states.items()},
            'circuit_breakers': self.circuit_breakers,
            'recent_events': [event.to_dict() for event in self.failover_events[-10:]],
            'policy': {
                'max_failures': self.policy.max_failures,
                'failure_window': self.policy.failure_window,
                'health_check_threshold': self.policy.health_check_threshold,
                'error_rate_threshold': self.policy.error_rate_threshold,
                'response_time_threshold': self.policy.response_time_threshold
            }
        }
    
    def get_server_failover_history(self, server_id: str) -> List[Dict[str, Any]]:
        """Get failover history for a specific server."""
        events = [event for event in self.failover_events if event.server_id == server_id]
        return [event.to_dict() for event in events]
    
    def reset_failover_state(self, server_id: str):
        """Reset failover state for a server."""
        try:
            self.server_states[server_id] = FailoverState.NORMAL
            self.failure_counts[server_id] = 0
            self.failure_history[server_id].clear()
            self.recovery_attempts[server_id] = 0
            self.last_recovery_attempt.pop(server_id, None)
            
            if self.policy.enable_circuit_breaker:
                self.circuit_breakers[server_id] = {
                    'state': 'closed',
                    'failures': 0,
                    'last_failure': 0.0,
                    'trip_time': 0.0
                }
            
            self.logger.info(f"Reset failover state for server {server_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to reset failover state: {e}")
    
    def stop(self):
        """Stop the failover manager."""
        self.running = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)
        
        if self.recovery_thread and self.recovery_thread.is_alive():
            self.recovery_thread.join(timeout=10)
        
        self.logger.info("Failover manager stopped")
