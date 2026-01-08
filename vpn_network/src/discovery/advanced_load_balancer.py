"""
Advanced Load Balancing System for VPN Security Project.
This module provides comprehensive load balancing with geographic selection,
performance metrics, and automatic failover capabilities.
"""
import math
import time
import heapq
import statistics
import asyncio
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, deque

from discovery.server_discovery import VPNServer, ServerStatus
from discovery.server_registry import ServerRegistry, ServerMetrics
from discovery.health_checker import HealthChecker, HealthStatus
from utils.logger import LoggableMixin


class LoadBalanceAlgorithm(Enum):
    """Advanced load balancing algorithms."""
    WEIGHTED_ROUND_ROBIN = auto()
    LEAST_RESPONSE_TIME = auto()
    ADAPTIVE_WEIGHTED = auto()
    CONSISTENT_HASH = auto()
    MAGLEV_HASH = auto()
    POWER_OF_TWO_CHOICES = auto()
    LATENCY_BASED = auto()
    BANDWIDTH_AWARE = auto()
    PREDICTIVE_SCALING = auto()
    GEOGRAPHIC_AWARE = auto()
    HEALTH_AWARE = auto()


class FailoverStrategy(Enum):
    """Failover strategies."""
    ACTIVE_PASSIVE = auto()
    ACTIVE_ACTIVE = auto()
    GEOGRAPHIC_REDUNDANCY = auto()
    PERFORMANCE_BASED = auto()
    HEALTH_BASED = auto()
    WEIGHTED_FAILOVER = auto()


@dataclass
class ServerWeight:
    """Server weight for load balancing."""
    server_id: str
    weight: float
    response_time_weight: float
    bandwidth_weight: float
    load_weight: float
    health_weight: float
    geographic_weight: float
    last_updated: float
    
    def total_weight(self) -> float:
        """Calculate total weight."""
        return (self.response_time_weight + self.bandwidth_weight + 
                self.load_weight + self.health_weight + self.geographic_weight)


@dataclass
class FailoverConfig:
    """Failover configuration."""
    strategy: FailoverStrategy
    max_failover_attempts: int = 3
    failover_timeout: float = 30.0
    health_check_interval: float = 10.0
    recovery_check_interval: float = 60.0
    automatic_recovery: bool = True
    failover_cooldown: float = 300.0  # 5 minutes


@dataclass
class PerformanceMetrics:
    """Enhanced performance metrics."""
    server_id: str
    timestamp: float
    response_time: float
    bandwidth_mbps: float
    packet_loss: float
    jitter: float  # Network jitter
    throughput_mbps: float
    connection_rate: float  # Connections per second
    error_rate: float
    cpu_usage: float
    memory_usage: float
    disk_io: float  # Disk I/O percentage
    network_io: float  # Network I/O percentage
    uptime_percentage: float
    concurrent_connections: int
    total_connections: int
    failed_connections: int
    
    def performance_score(self) -> float:
        """Calculate overall performance score (0-1)."""
        # Weight different metrics
        weights = {
            'response_time': 0.25,
            'bandwidth': 0.20,
            'packet_loss': 0.15,
            'jitter': 0.10,
            'error_rate': 0.15,
            'resource_usage': 0.15
        }
        
        # Normalize metrics (lower is better for some, higher for others)
        response_score = max(0, 1 - (self.response_time / 1000))  # 1000ms = 0 score
        bandwidth_score = min(1, self.bandwidth_mbps / 1000)  # 1000Mbps = 1 score
        packet_loss_score = max(0, 1 - self.packet_loss)
        jitter_score = max(0, 1 - (self.jitter / 100))  # 100ms jitter = 0 score
        error_score = max(0, 1 - self.error_rate)
        resource_score = max(0, 1 - ((self.cpu_usage + self.memory_usage) / 2))
        
        return (response_score * weights['response_time'] +
                bandwidth_score * weights['bandwidth'] +
                packet_loss_score * weights['packet_loss'] +
                jitter_score * weights['jitter'] +
                error_score * weights['error_rate'] +
                resource_score * weights['resource_usage'])


class AdvancedLoadBalancer(LoggableMixin):
    """Advanced load balancing system with multiple algorithms."""
    
    def __init__(self, config: Dict[str, Any], registry: ServerRegistry, 
                 health_checker: HealthChecker):
        self.config = config
        self.registry = registry
        self.health_checker = health_checker
        self.lb_config = config.get('load_balancer', {})
        
        # Algorithm configuration
        self.default_algorithm = LoadBalanceAlgorithm[
            self.lb_config.get('algorithm', 'adaptive_weighted').upper()
        ]
        self.enable_adaptive = self.lb_config.get('enable_adaptive', True)
        self.adaptive_interval = self.lb_config.get('adaptive_interval', 300)
        
        # Server weights
        self.server_weights: Dict[str, ServerWeight] = {}
        self.weight_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Performance tracking
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.performance_trends: Dict[str, float] = {}
        
        # Geographic data
        self.client_locations: Dict[str, Tuple[float, float]] = {}
        self.server_clusters: Dict[str, List[str]] = defaultdict(list)
        
        # Failover configuration
        self.failover_config = FailoverConfig(
            strategy=FailoverStrategy[
                self.lb_config.get('failover_strategy', 'health_based').upper()
            ],
            **self.lb_config.get('failover', {})
        )
        
        # Failover state
        self.failed_servers: Set[str] = set()
        self.failover_history: List[Dict[str, Any]] = []
        self.recovery_attempts: Dict[str, float] = {}
        
        # Load balancing state
        self.round_robin_index = 0
        self.consistent_hash_ring: Dict[int, str] = {}
        self.maglev_ring: List[str] = []
        
        # Statistics
        self.stats = {
            'total_selections': 0,
            'algorithm_usage': defaultdict(int),
            'failover_events': 0,
            'recovery_events': 0,
            'performance_updates': 0,
            'weight_updates': 0,
            'average_response_time': 0.0,
            'average_bandwidth': 0.0,
            'selection_accuracy': 0.0
        }
        
        # Background tasks
        self.adaptive_thread = None
        self.failover_thread = None
        self.running = False
        
        # Initialize load balancer
        self._initialize()
    
    def _initialize(self):
        """Initialize the load balancer."""
        try:
            # Initialize server weights
            self._initialize_server_weights()
            
            # Initialize geographic clusters
            self._initialize_geographic_clusters()
            
            # Initialize hash rings
            self._initialize_hash_rings()
            
            # Start background tasks
            if self.enable_adaptive:
                self._start_adaptive_thread()
            
            self._start_failover_thread()
            
            self.logger.info(f"Advanced load balancer initialized with {self.default_algorithm.name}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize load balancer: {e}")
            raise
    
    def _initialize_server_weights(self):
        """Initialize server weights based on current metrics."""
        servers = self.registry.get_all_servers()
        
        for server in servers:
            weight = self._calculate_server_weight(server)
            self.server_weights[server.server_id] = weight
            
        self.logger.info(f"Initialized weights for {len(servers)} servers")
    
    def _calculate_server_weight(self, server: VPNServer) -> ServerWeight:
        """Calculate comprehensive server weight."""
        current_time = time.time()
        
        # Get recent metrics
        recent_metrics = self.performance_history.get(server.server_id, [])
        
        if recent_metrics:
            avg_metrics = statistics.mean([m.performance_score() for m in recent_metrics])
        else:
            avg_metrics = 0.5  # Default score
        
        # Calculate individual weights
        response_time_weight = max(0.1, 1.0 - (server.response_time / 1000))
        bandwidth_weight = min(1.0, server.bandwidth_mbps / 1000)
        load_weight = max(0.1, 1.0 - server.load)
        
        health_status = self.health_checker.get_server_health(server.server_id)
        if health_status == HealthStatus.HEALTHY:
            health_weight = 1.0
        elif health_status == HealthStatus.WARNING:
            health_weight = 0.7
        elif health_status == HealthStatus.CRITICAL:
            health_weight = 0.3
        else:
            health_weight = 0.5
        
        # Geographic weight (based on typical client locations)
        geographic_weight = self._calculate_geographic_weight(server)
        
        return ServerWeight(
            server_id=server.server_id,
            weight=avg_metrics,
            response_time_weight=response_time_weight,
            bandwidth_weight=bandwidth_weight,
            load_weight=load_weight,
            health_weight=health_weight,
            geographic_weight=geographic_weight,
            last_updated=current_time
        )
    
    def _calculate_geographic_weight(self, server: VPNServer) -> float:
        """Calculate geographic weight based on client distribution."""
        if not self.client_locations:
            return 0.5  # Neutral weight
        
        # Calculate average distance to all known client locations
        total_distance = 0
        count = 0
        
        for client_id, (lat, lon) in self.client_locations.items():
            distance = self._calculate_distance(server.latitude, server.longitude, lat, lon)
            total_distance += distance
            count += 1
        
        if count == 0:
            return 0.5
        
        avg_distance = total_distance / count
        
        # Convert distance to weight (closer = higher weight)
        # 0km = 1.0, 10000km = 0.1
        if avg_distance <= 0:
            return 1.0
        elif avg_distance >= 10000:
            return 0.1
        else:
            return 1.0 - ((avg_distance / 10000) * 0.9)
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in kilometers."""
        R = 6371.0  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def _initialize_geographic_clusters(self):
        """Initialize geographic server clusters."""
        servers = self.registry.get_all_servers()
        
        # Group servers by region
        for server in servers:
            region = server.region
            self.server_clusters[region].append(server.server_id)
        
        self.logger.info(f"Initialized {len(self.server_clusters)} geographic clusters")
    
    def _initialize_hash_rings(self):
        """Initialize consistent hash rings."""
        servers = self.registry.get_all_servers()
        
        # Consistent hash ring
        for server in servers:
            for i in range(100):  # 100 virtual nodes per server
                key = f"{server.server_id}:{i}"
                hash_value = hash(key) % (2**32)
                self.consistent_hash_ring[hash_value] = server.server_id
        
        # Maglev hash ring
        self.maglev_ring = [server.server_id for server in servers] * 100  # Simple implementation
        
        self.logger.info("Hash rings initialized")
    
    def select_server(self, client_id: str = None, client_location: Tuple[float, float] = None,
                     algorithm: LoadBalanceAlgorithm = None, 
                     exclude_servers: Set[str] = None) -> Optional[VPNServer]:
        """Select best server using specified algorithm."""
        try:
            algorithm = algorithm or self.default_algorithm
            exclude_servers = exclude_servers or self.failed_servers
            
            # Update client location if provided
            if client_id and client_location:
                self.client_locations[client_id] = client_location
            
            # Get candidate servers
            candidates = self._get_candidate_servers(exclude_servers)
            
            if not candidates:
                self.logger.warning("No candidate servers available")
                return None
            
            # Select server using algorithm
            if algorithm == LoadBalanceAlgorithm.WEIGHTED_ROUND_ROBIN:
                selected = self._weighted_round_robin_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.LEAST_RESPONSE_TIME:
                selected = self._least_response_time_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.ADAPTIVE_WEIGHTED:
                selected = self._adaptive_weighted_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.CONSISTENT_HASH:
                selected = self._consistent_hash_select(candidates, client_id)
            elif algorithm == LoadBalanceAlgorithm.MAGLEV_HASH:
                selected = self._maglev_hash_select(candidates, client_id)
            elif algorithm == LoadBalanceAlgorithm.POWER_OF_TWO_CHOICES:
                selected = self._power_of_two_choices_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.LATENCY_BASED:
                selected = self._latency_based_select(candidates, client_location)
            elif algorithm == LoadBalanceAlgorithm.BANDWIDTH_AWARE:
                selected = self._bandwidth_aware_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.PREDICTIVE_SCALING:
                selected = self._predictive_scaling_select(candidates)
            elif algorithm == LoadBalanceAlgorithm.GEOGRAPHIC_AWARE:
                selected = self._geographic_aware_select(candidates, client_location)
            elif algorithm == LoadBalanceAlgorithm.HEALTH_AWARE:
                selected = self._health_aware_select(candidates)
            else:
                selected = candidates[0]  # Fallback
            
            # Update statistics
            self.stats['total_selections'] += 1
            self.stats['algorithm_usage'][algorithm.name] += 1
            
            if selected:
                self.logger.debug(f"Selected server {selected.server_id} using {algorithm.name}")
            
            return selected
            
        except Exception as e:
            self.logger.error(f"Server selection failed: {e}")
            return None
    
    def _get_candidate_servers(self, exclude_servers: Set[str]) -> List[VPNServer]:
        """Get candidate servers for selection."""
        all_servers = self.registry.get_all_servers()
        
        # Filter out excluded and failed servers
        candidates = [s for s in all_servers 
                      if s.server_id not in exclude_servers and 
                      s.status == ServerStatus.ONLINE]
        
        return candidates
    
    def _weighted_round_robin_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Weighted round-robin selection."""
        if not candidates:
            return None
        
        # Calculate total weight
        total_weight = 0
        for server in candidates:
            weight = self.server_weights.get(server.server_id)
            if weight:
                total_weight += weight.total_weight()
        
        if total_weight == 0:
            # Fallback to simple round-robin
            selected = candidates[self.round_robin_index % len(candidates)]
            self.round_robin_index += 1
            return selected
        
        # Weighted selection
        random_weight = (hash(f"rr_{time.time()}") % 1000) / 1000.0 * total_weight
        current_weight = 0
        
        for server in candidates:
            weight = self.server_weights.get(server.server_id)
            if weight:
                current_weight += weight.total_weight()
                if current_weight >= random_weight:
                    return server
        
        # Fallback
        return candidates[0]
    
    def _least_response_time_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Select server with least response time."""
        if not candidates:
            return None
        
        # Sort by response time
        sorted_candidates = sorted(candidates, key=lambda s: s.response_time)
        return sorted_candidates[0]
    
    def _adaptive_weighted_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Adaptive weighted selection based on performance trends."""
        if not candidates:
            return None
        
        # Calculate adaptive scores
        scored_candidates = []
        
        for server in candidates:
            base_weight = self.server_weights.get(server.server_id)
            if not base_weight:
                continue
            
            # Get performance trend
            trend = self.performance_trends.get(server.server_id, 0.0)
            
            # Adjust weight based on trend
            adaptive_weight = base_weight.total_weight() * (1.0 + trend)
            
            scored_candidates.append((server, adaptive_weight))
        
        if not scored_candidates:
            return candidates[0]
        
        # Select highest weighted server
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        return scored_candidates[0][0]
    
    def _consistent_hash_select(self, candidates: List[VPNServer], client_id: str) -> VPNServer:
        """Consistent hash selection."""
        if not candidates or not client_id:
            return candidates[0] if candidates else None
        
        # Hash the client ID
        client_hash = hash(client_id) % (2**32)
        
        # Find next server in hash ring
        sorted_hashes = sorted(self.consistent_hash_ring.keys())
        
        for hash_value in sorted_hashes:
            if hash_value >= client_hash:
                server_id = self.consistent_hash_ring[hash_value]
                server = next((s for s in candidates if s.server_id == server_id), None)
                if server:
                    return server
        
        # Wrap around
        first_hash = sorted_hashes[0]
        server_id = self.consistent_hash_ring[first_hash]
        server = next((s for s in candidates if s.server_id == server_id), None)
        return server or candidates[0]
    
    def _maglev_hash_select(self, candidates: List[VPNServer], client_id: str) -> VPNServer:
        """Maglev hash selection."""
        if not candidates or not client_id:
            return candidates[0] if candidates else None
        
        # Simple Maglev implementation
        client_hash = hash(client_id) % len(self.maglev_ring)
        server_id = self.maglev_ring[client_hash]
        
        server = next((s for s in candidates if s.server_id == server_id), None)
        return server or candidates[0]
    
    def _power_of_two_choices_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Power of two choices selection."""
        if len(candidates) < 2:
            return candidates[0] if candidates else None
        
        # Randomly select two candidates
        import random
        candidate1, candidate2 = random.sample(candidates, 2)
        
        # Choose the one with better weight
        weight1 = self.server_weights.get(candidate1.server_id)
        weight2 = self.server_weights.get(candidate2.server_id)
        
        if weight1 and weight2:
            return candidate1 if weight1.total_weight() > weight2.total_weight() else candidate2
        else:
            return candidate1
    
    def _latency_based_select(self, candidates: List[VPNServer], 
                             client_location: Tuple[float, float]) -> VPNServer:
        """Latency-based selection considering geographic distance."""
        if not candidates or not client_location:
            return candidates[0] if candidates else None
        
        # Calculate estimated latency based on distance
        # Assume ~5ms per 1000km
        scored_candidates = []
        
        for server in candidates:
            distance = self._calculate_distance(
                server.latitude, server.longitude,
                client_location[0], client_location[1]
            )
            
            # Estimated latency = distance-based latency + server response time
            estimated_latency = (distance / 1000 * 5) + server.response_time
            
            scored_candidates.append((server, estimated_latency))
        
        # Select server with lowest estimated latency
        scored_candidates.sort(key=lambda x: x[1])
        return scored_candidates[0][0]
    
    def _bandwidth_aware_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Bandwidth-aware selection."""
        if not candidates:
            return None
        
        # Sort by available bandwidth
        sorted_candidates = sorted(candidates, 
                                 key=lambda s: s.bandwidth_mbps * (1 - s.load),
                                 reverse=True)
        return sorted_candidates[0]
    
    def _predictive_scaling_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Predictive scaling selection based on performance trends."""
        if not candidates:
            return None
        
        # Calculate predictive scores
        scored_candidates = []
        
        for server in candidates:
            # Get recent performance metrics
            recent_metrics = list(self.performance_history.get(server.server_id, []))
            
            if len(recent_metrics) < 5:
                # Not enough data, use current metrics
                score = server.bandwidth_mbps * (1 - server.load) / (server.response_time + 1)
            else:
                # Predict future performance based on trends
                recent_scores = [m.performance_score() for m in recent_metrics[-10:]]
                
                # Calculate trend (simple linear regression)
                if len(recent_scores) >= 2:
                    x = list(range(len(recent_scores)))
                    n = len(recent_scores)
                    sum_x = sum(x)
                    sum_y = sum(recent_scores)
                    sum_xy = sum(x[i] * recent_scores[i] for i in range(n))
                    sum_x2 = sum(x[i] ** 2 for i in range(n))
                    
                    slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
                    
                    # Predict next score
                    predicted_score = recent_scores[-1] + slope
                    score = max(0, min(1, predicted_score))
                else:
                    score = recent_scores[-1]
            
            scored_candidates.append((server, score))
        
        # Select server with highest predicted score
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        return scored_candidates[0][0]
    
    def _geographic_aware_select(self, candidates: List[VPNServer], 
                                client_location: Tuple[float, float]) -> VPNServer:
        """Geographic-aware selection with clustering."""
        if not candidates:
            return None
        
        if not client_location:
            # No location info, use regular weighted selection
            return self._weighted_round_robin_select(candidates)
        
        # Find servers in same region/country
        regional_servers = []
        for server in candidates:
            # Simple geographic clustering (same country)
            if hasattr(server, 'country'):
                # This would need actual country comparison
                regional_servers.append(server)
        
        if regional_servers:
            # Prefer regional servers
            return self._latency_based_select(regional_servers, client_location)
        else:
            # Fall back to global selection
            return self._latency_based_select(candidates, client_location)
    
    def _health_aware_select(self, candidates: List[VPNServer]) -> VPNServer:
        """Health-aware selection prioritizing healthy servers."""
        if not candidates:
            return None
        
        # Group by health status
        healthy_servers = []
        warning_servers = []
        
        for server in candidates:
            health_status = self.health_checker.get_server_health(server.server_id)
            if health_status == HealthStatus.HEALTHY:
                healthy_servers.append(server)
            elif health_status == HealthStatus.WARNING:
                warning_servers.append(server)
        
        # Prefer healthy servers
        if healthy_servers:
            return self._least_response_time_select(healthy_servers)
        elif warning_servers:
            return self._least_response_time_select(warning_servers)
        else:
            return candidates[0]
    
    def update_performance_metrics(self, server_id: str, metrics: PerformanceMetrics):
        """Update performance metrics for a server."""
        try:
            # Store metrics
            self.performance_history[server_id].append(metrics)
            
            # Update performance trend
            recent_metrics = list(self.performance_history[server_id])
            if len(recent_metrics) >= 10:
                # Calculate trend (improvement vs degradation)
                old_scores = [m.performance_score() for m in recent_metrics[-20:-10]]
                new_scores = [m.performance_score() for m in recent_metrics[-10:]]
                
                if old_scores and new_scores:
                    old_avg = statistics.mean(old_scores)
                    new_avg = statistics.mean(new_scores)
                    
                    # Trend: positive = improving, negative = degrading
                    trend = (new_avg - old_avg) / old_avg if old_avg > 0 else 0
                    self.performance_trends[server_id] = trend
            
            # Update server weight
            server = self.registry.get_server(server_id)
            if server:
                new_weight = self._calculate_server_weight(server)
                self.server_weights[server_id] = new_weight
                self.stats['weight_updates'] += 1
            
            self.stats['performance_updates'] += 1
            
        except Exception as e:
            self.logger.error(f"Failed to update performance metrics for {server_id}: {e}")
    
    def handle_server_failure(self, server_id: str, error: str = None):
        """Handle server failure and trigger failover."""
        try:
            if server_id not in self.failed_servers:
                self.failed_servers.add(server_id)
                self.failover_history.append({
                    'server_id': server_id,
                    'timestamp': time.time(),
                    'error': error,
                    'action': 'marked_as_failed'
                })
                
                self.stats['failover_events'] += 1
                
                self.logger.warning(f"Server {server_id} marked as failed: {error}")
                
                # Trigger failover if needed
                self._trigger_failover(server_id)
            
        except Exception as e:
            self.logger.error(f"Failed to handle server failure: {e}")
    
    def _trigger_failover(self, failed_server_id: str):
        """Trigger automatic failover."""
        try:
            # Select replacement server
            replacement = self.select_server(
                exclude_servers=self.failed_servers,
                algorithm=LoadBalanceAlgorithm.HEALTH_AWARE
            )
            
            if replacement:
                self.failover_history.append({
                    'server_id': failed_server_id,
                    'replacement_server_id': replacement.server_id,
                    'timestamp': time.time(),
                    'action': 'failover_triggered'
                })
                
                self.logger.info(f"Failover: {failed_server_id} -> {replacement.server_id}")
                
                # Start recovery monitoring
                self.recovery_attempts[failed_server_id] = time.time()
                
            else:
                self.logger.error("No suitable replacement server found for failover")
                
        except Exception as e:
            self.logger.error(f"Failover failed: {e}")
    
    def check_server_recovery(self, server_id: str) -> bool:
        """Check if a failed server has recovered."""
        try:
            # Check if enough time has passed since failure
            last_attempt = self.recovery_attempts.get(server_id, 0)
            if time.time() - last_attempt < self.failover_config.recovery_check_interval:
                return False
            
            # Perform health check
            health_result = self.health_checker.run_manual_check(server_id)
            
            if health_result and health_result.status == HealthStatus.HEALTHY:
                # Server has recovered
                self.failed_servers.discard(server_id)
                self.recovery_attempts.pop(server_id, None)
                
                self.failover_history.append({
                    'server_id': server_id,
                    'timestamp': time.time(),
                    'action': 'server_recovered'
                })
                
                self.stats['recovery_events'] += 1
                
                self.logger.info(f"Server {server_id} has recovered and is back online")
                return True
            
            # Update recovery attempt time
            self.recovery_attempts[server_id] = time.time()
            return False
            
        except Exception as e:
            self.logger.error(f"Recovery check failed for {server_id}: {e}")
            return False
    
    def _start_adaptive_thread(self):
        """Start adaptive weight adjustment thread."""
        def adaptive_worker():
            while self.running:
                try:
                    self._adaptive_weight_update()
                    time.sleep(self.adaptive_interval)
                except Exception as e:
                    self.logger.error(f"Adaptive thread error: {e}")
                    time.sleep(60)
        
        self.adaptive_thread = threading.Thread(target=adaptive_worker, daemon=True)
        self.adaptive_thread.start()
        self.logger.info("Started adaptive weight adjustment thread")
    
    def _adaptive_weight_update(self):
        """Perform adaptive weight updates."""
        try:
            servers = self.registry.get_all_servers()
            
            for server in servers:
                # Update weights based on recent performance
                new_weight = self._calculate_server_weight(server)
                old_weight = self.server_weights.get(server.server_id)
                
                if old_weight:
                    # Smooth weight changes to avoid oscillation
                    alpha = 0.3  # Learning rate
                    smoothed_weight = ServerWeight(
                        server_id=server.server_id,
                        weight=alpha * new_weight.weight + (1 - alpha) * old_weight.weight,
                        response_time_weight=alpha * new_weight.response_time_weight + (1 - alpha) * old_weight.response_time_weight,
                        bandwidth_weight=alpha * new_weight.bandwidth_weight + (1 - alpha) * old_weight.bandwidth_weight,
                        load_weight=alpha * new_weight.load_weight + (1 - alpha) * old_weight.load_weight,
                        health_weight=alpha * new_weight.health_weight + (1 - alpha) * old_weight.health_weight,
                        geographic_weight=alpha * new_weight.geographic_weight + (1 - alpha) * old_weight.geographic_weight,
                        last_updated=time.time()
                    )
                    self.server_weights[server.server_id] = smoothed_weight
                else:
                    self.server_weights[server.server_id] = new_weight
            
            self.logger.debug("Adaptive weight update completed")
            
        except Exception as e:
            self.logger.error(f"Adaptive weight update failed: {e}")
    
    def _start_failover_thread(self):
        """Start failover monitoring thread."""
        def failover_worker():
            while self.running:
                try:
                    self._monitor_failover_recovery()
                    time.sleep(self.failover_config.recovery_check_interval)
                except Exception as e:
                    self.logger.error(f"Failover thread error: {e}")
                    time.sleep(30)
        
        self.failover_thread = threading.Thread(target=failover_worker, daemon=True)
        self.failover_thread.start()
        self.logger.info("Started failover monitoring thread")
    
    def _monitor_failover_recovery(self):
        """Monitor failed servers for recovery."""
        if not self.failed_servers:
            return
        
        recovered_servers = []
        
        for server_id in list(self.failed_servers):
            if self.check_server_recovery(server_id):
                recovered_servers.append(server_id)
        
        if recovered_servers:
            self.logger.info(f"Recovered {len(recovered_servers)} servers: {recovered_servers}")
    
    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get comprehensive load balancer statistics."""
        return {
            'stats': dict(self.stats),
            'failed_servers': list(self.failed_servers),
            'total_servers': len(self.server_weights),
            'active_servers': len(self.server_weights) - len(self.failed_servers),
            'failover_history': self.failover_history[-10:],  # Last 10 events
            'performance_trends': dict(self.performance_trends),
            'algorithm_distribution': dict(self.stats['algorithm_usage']),
            'average_weights': {
                server_id: weight.total_weight()
                for server_id, weight in self.server_weights.items()
            }
        }
    
    def stop(self):
        """Stop the load balancer."""
        self.running = False
        
        if self.adaptive_thread and self.adaptive_thread.is_alive():
            self.adaptive_thread.join(timeout=10)
        
        if self.failover_thread and self.failover_thread.is_alive():
            self.failover_thread.join(timeout=10)
        
        self.logger.info("Advanced load balancer stopped")
