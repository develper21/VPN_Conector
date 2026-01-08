"""
Geographic Load Balancer for VPN Security Project.
This module provides intelligent server selection based on geographic location,
server load, and performance metrics.
"""
import math
import time
import statistics
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto

from discovery.server_discovery import VPNServer, ServerStatus
from discovery.server_registry import ServerRegistry
from discovery.health_checker import HealthChecker, HealthStatus
from utils.logger import LoggableMixin


class LoadBalanceStrategy(Enum):
    """Load balancing strategies."""
    GEOGRAPHIC = auto()
    PERFORMANCE = auto()
    ROUND_ROBIN = auto()
    LEAST_CONNECTIONS = auto()
    WEIGHTED_ROUND_ROBIN = auto()
    RESPONSE_TIME = auto()
    BANDWIDTH = auto()


@dataclass
class ServerScore:
    """Server selection score."""
    server_id: str
    server: VPNServer
    total_score: float
    geographic_score: float
    performance_score: float
    load_score: float
    health_score: float
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'server_id': self.server_id,
            'total_score': self.total_score,
            'geographic_score': self.geographic_score,
            'performance_score': self.performance_score,
            'load_score': self.load_score,
            'health_score': self.health_score,
            'details': self.details
        }


@dataclass
class ClientLocation:
    """Client geographic location."""
    latitude: float
    longitude: float
    country: str = "Unknown"
    region: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    accuracy: float = 1000.0  # meters
    
    @classmethod
    def from_ip(cls, ip_address: str, geoip_reader=None) -> 'ClientLocation':
        """Create client location from IP address."""
        # Default location if GeoIP not available
        location = cls(
            latitude=40.7128,  # New York
            longitude=-74.0060,
            country="Unknown",
            region="Unknown",
            city="Unknown"
        )
        
        if geoip_reader:
            try:
                import geoip2.database
                response = geoip_reader.city(ip_address)
                
                location.latitude = float(response.location.latitude)
                location.longitude = float(response.location.longitude)
                location.country = response.country.names.get('en', 'Unknown')
                location.region = response.continent.names.get('en', 'Unknown')
                location.city = response.city.names.get('en', 'Unknown')
                location.accuracy = response.location.accuracy_radius or 1000.0
                
            except Exception:
                pass  # Use default location
        
        return location


class GeographicLoadBalancer(LoggableMixin):
    """Geographic load balancer for VPN servers."""
    
    def __init__(self, config: Dict[str, Any], registry: ServerRegistry, 
                 health_checker: HealthChecker):
        self.config = config
        self.registry = registry
        self.health_checker = health_checker
        self.lb_config = config.get('load_balancer', {})
        
        # Load balancing settings
        self.default_strategy = LoadBalanceStrategy[
            self.lb_config.get('default_strategy', 'geographic').upper()
        ]
        self.max_servers_per_request = self.lb_config.get('max_servers_per_request', 10)
        self.enable_geo_fallback = self.lb_config.get('enable_geo_fallback', True)
        self.geo_fallback_distance = self.lb_config.get('geo_fallback_distance', 5000)  # km
        
        # Scoring weights
        self.weights = {
            'geographic': self.lb_config.get('geographic_weight', 0.3),
            'performance': self.lb_config.get('performance_weight', 0.3),
            'load': self.lb_config.get('load_weight', 0.2),
            'health': self.lb_config.get('health_weight', 0.2)
        }
        
        # Normalize weights
        total_weight = sum(self.weights.values())
        if total_weight > 0:
            self.weights = {k: v / total_weight for k, v in self.weights.items()}
        
        # Round-robin state
        self.round_robin_index = 0
        self.last_selection_time = {}
        
        # Statistics
        self.stats = {
            'total_selections': 0,
            'strategy_usage': {strategy.name: 0 for strategy in LoadBalanceStrategy},
            'average_score': 0.0,
            'selections_by_region': {},
            'selections_by_protocol': {}
        }
    
    def select_best_servers(self, client_location: Optional[ClientLocation] = None,
                           protocol: Optional[str] = None, region: Optional[str] = None,
                           count: int = 5, strategy: Optional[LoadBalanceStrategy] = None,
                           exclude_servers: List[str] = None) -> List[ServerScore]:
        """Select best servers based on strategy and criteria."""
        try:
            start_time = time.time()
            
            # Get candidate servers
            candidates = self._get_candidate_servers(protocol, region, exclude_servers)
            
            if not candidates:
                self.logger.warning("No candidate servers available")
                return []
            
            # Use default strategy if not specified
            if strategy is None:
                strategy = self.default_strategy
            
            # Score servers based on strategy
            scored_servers = self._score_servers(candidates, client_location, strategy)
            
            # Sort by score (descending)
            scored_servers.sort(key=lambda s: s.total_score, reverse=True)
            
            # Limit results
            result = scored_servers[:count]
            
            # Update statistics
            self._update_selection_stats(result, strategy, start_time)
            
            self.logger.info(f"Selected {len(result)} servers using {strategy.name} strategy")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Server selection failed: {e}")
            return []
    
    def _get_candidate_servers(self, protocol: Optional[str] = None,
                              region: Optional[str] = None,
                              exclude_servers: List[str] = None) -> List[VPNServer]:
        """Get candidate servers based on criteria."""
        candidates = self.registry.get_all_servers()
        
        # Filter by protocol
        if protocol:
            candidates = [s for s in candidates if s.protocol == protocol or s.protocol == 'both']
        
        # Filter by region
        if region:
            candidates = [s for s in candidates if s.region.lower() == region.lower()]
        
        # Filter by health status
        healthy_statuses = [ServerStatus.ONLINE]
        if self.enable_geo_fallback:
            healthy_statuses.extend([ServerStatus.OVERLOADED])  # Allow overloaded servers as fallback
        
        candidates = [s for s in candidates if s.status in healthy_statuses]
        
        # Exclude specific servers
        if exclude_servers:
            candidates = [s for s in candidates if s.server_id not in exclude_servers]
        
        # Limit to reasonable number
        return candidates[:self.max_servers_per_request]
    
    def _score_servers(self, servers: List[VPNServer], 
                      client_location: Optional[ClientLocation],
                      strategy: LoadBalanceStrategy) -> List[ServerScore]:
        """Score servers based on strategy."""
        scored_servers = []
        
        for server in servers:
            try:
                score = self._calculate_server_score(server, client_location, strategy)
                scored_servers.append(score)
            except Exception as e:
                self.logger.error(f"Failed to score server {server.server_id}: {e}")
                continue
        
        return scored_servers
    
    def _calculate_server_score(self, server: VPNServer, 
                               client_location: Optional[ClientLocation],
                               strategy: LoadBalanceStrategy) -> ServerScore:
        """Calculate comprehensive score for a server."""
        # Calculate individual scores
        geo_score = self._calculate_geographic_score(server, client_location)
        perf_score = self._calculate_performance_score(server)
        load_score = self._calculate_load_score(server)
        health_score = self._calculate_health_score(server)
        
        # Apply strategy-specific scoring
        if strategy == LoadBalanceStrategy.GEOGRAPHIC:
            total_score = geo_score * 0.6 + perf_score * 0.2 + load_score * 0.1 + health_score * 0.1
        elif strategy == LoadBalanceStrategy.PERFORMANCE:
            total_score = perf_score * 0.5 + geo_score * 0.2 + load_score * 0.2 + health_score * 0.1
        elif strategy == LoadBalanceStrategy.RESPONSE_TIME:
            total_score = perf_score * 0.7 + health_score * 0.2 + geo_score * 0.1
        elif strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            total_score = load_score * 0.6 + health_score * 0.2 + perf_score * 0.1 + geo_score * 0.1
        elif strategy == LoadBalanceStrategy.BANDWIDTH:
            bandwidth_score = self._calculate_bandwidth_score(server)
            total_score = bandwidth_score * 0.5 + perf_score * 0.3 + health_score * 0.2
        else:  # ROUND_ROBIN or default
            total_score = (geo_score * self.weights['geographic'] +
                          perf_score * self.weights['performance'] +
                          load_score * self.weights['load'] +
                          health_score * self.weights['health'])
        
        # Add round-robin bonus for distributed selection
        if strategy == LoadBalanceStrategy.ROUND_ROBIN:
            rr_bonus = self._calculate_round_robin_bonus(server)
            total_score += rr_bonus
        
        # Ensure score is between 0 and 1
        total_score = max(0.0, min(1.0, total_score))
        
        return ServerScore(
            server_id=server.server_id,
            server=server,
            total_score=total_score,
            geographic_score=geo_score,
            performance_score=perf_score,
            load_score=load_score,
            health_score=health_score,
            details={
                'strategy': strategy.name,
                'distance_km': self._calculate_distance(server, client_location) if client_location else 0,
                'response_time_ms': server.response_time,
                'load_percentage': server.load * 100,
                'bandwidth_mbps': server.bandwidth_mbps,
                'current_clients': server.current_clients,
                'max_clients': server.max_clients
            }
        )
    
    def _calculate_geographic_score(self, server: VPNServer, 
                                  client_location: Optional[ClientLocation]) -> float:
        """Calculate geographic proximity score."""
        if not client_location:
            return 0.5  # Neutral score if location unknown
        
        distance = self._calculate_distance(server, client_location)
        
        # Score based on distance (closer is better)
        # Score 1.0 for < 500km, 0.0 for > 10000km
        if distance <= 500:
            return 1.0
        elif distance >= 10000:
            return 0.0
        else:
            # Linear interpolation
            return 1.0 - ((distance - 500) / (10000 - 500))
    
    def _calculate_performance_score(self, server: VPNServer) -> float:
        """Calculate performance score based on response time and bandwidth."""
        # Response time score (lower is better)
        if server.response_time <= 0:
            response_score = 0.5  # Neutral if unknown
        elif server.response_time <= 50:  # Excellent
            response_score = 1.0
        elif server.response_time <= 200:  # Good
            response_score = 0.8
        elif server.response_time <= 500:  # Fair
            response_score = 0.6
        elif server.response_time <= 1000:  # Poor
            response_score = 0.4
        else:  # Very poor
            response_score = 0.2
        
        # Bandwidth score (higher is better)
        if server.bandwidth_mbps <= 0:
            bandwidth_score = 0.5  # Neutral if unknown
        elif server.bandwidth_mbps >= 100:  # Excellent
            bandwidth_score = 1.0
        elif server.bandwidth_mbps >= 50:  # Good
            bandwidth_score = 0.8
        elif server.bandwidth_mbps >= 20:  # Fair
            bandwidth_score = 0.6
        elif server.bandwidth_mbps >= 10:  # Poor
            bandwidth_score = 0.4
        else:  # Very poor
            bandwidth_score = 0.2
        
        # Combine scores
        return (response_score * 0.6 + bandwidth_score * 0.4)
    
    def _calculate_load_score(self, server: VPNServer) -> float:
        """Calculate load score (lower load is better)."""
        # Connection load
        if server.max_clients <= 0:
            connection_load = 0.5  # Neutral if unknown
        else:
            connection_ratio = server.current_clients / server.max_clients
            connection_load = 1.0 - connection_ratio  # Invert so lower load = higher score
        
        # Server load metric
        server_load = 1.0 - server.load  # Invert so lower load = higher score
        
        # Combine scores
        return (connection_load * 0.7 + server_load * 0.3)
    
    def _calculate_health_score(self, server: VPNServer) -> float:
        """Calculate health score."""
        health_status = self.health_checker.get_server_health(server.server_id)
        
        if health_status == HealthStatus.HEALTHY:
            return 1.0
        elif health_status == HealthStatus.WARNING:
            return 0.7
        elif health_status == HealthStatus.CRITICAL:
            return 0.3
        else:  # UNKNOWN
            return 0.5
    
    def _calculate_bandwidth_score(self, server: VPNServer) -> float:
        """Calculate bandwidth-specific score."""
        if server.bandwidth_mbps <= 0:
            return 0.5  # Neutral if unknown
        elif server.bandwidth_mbps >= 1000:  # Excellent (1 Gbps+)
            return 1.0
        elif server.bandwidth_mbps >= 500:  # Good (500 Mbps+)
            return 0.8
        elif server.bandwidth_mbps >= 100:  # Fair (100 Mbps+)
            return 0.6
        elif server.bandwidth_mbps >= 50:  # Poor (50 Mbps+)
            return 0.4
        else:  # Very poor
            return 0.2
    
    def _calculate_round_robin_bonus(self, server: VPNServer) -> float:
        """Calculate round-robin bonus for distributed selection."""
        current_time = time.time()
        last_selection = self.last_selection_time.get(server.server_id, 0)
        
        # Bonus increases with time since last selection
        time_since_selection = current_time - last_selection
        
        # Maximum bonus of 0.1 after 5 minutes
        if time_since_selection >= 300:
            return 0.1
        else:
            return (time_since_selection / 300) * 0.1
    
    def _calculate_distance(self, server: VPNServer, 
                           client_location: ClientLocation) -> float:
        """Calculate distance between server and client in kilometers."""
        # Haversine formula
        R = 6371.0  # Earth's radius in kilometers
        
        lat1 = math.radians(server.latitude)
        lon1 = math.radians(server.longitude)
        lat2 = math.radians(client_location.latitude)
        lon2 = math.radians(client_location.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def _update_selection_stats(self, selected_servers: List[ServerScore],
                               strategy: LoadBalanceStrategy, start_time: float):
        """Update selection statistics."""
        try:
            selection_time = time.time() - start_time
            
            # Update basic stats
            self.stats['total_selections'] += 1
            self.stats['strategy_usage'][strategy.name] += 1
            
            # Update average score
            if selected_servers:
                avg_score = statistics.mean([s.total_score for s in selected_servers])
                total_selections = self.stats['total_selections']
                self.stats['average_score'] = (
                    (self.stats['average_score'] * (total_selections - 1) + avg_score) /
                    total_selections
                )
            
            # Update region and protocol stats
            for server_score in selected_servers:
                server = server_score.server
                
                # Region stats
                region = server.region
                if region not in self.stats['selections_by_region']:
                    self.stats['selections_by_region'][region] = 0
                self.stats['selections_by_region'][region] += 1
                
                # Protocol stats
                protocol = server.protocol
                if protocol not in self.stats['selections_by_protocol']:
                    self.stats['selections_by_protocol'][protocol] = 0
                self.stats['selections_by_protocol'][protocol] += 1
                
                # Update last selection time
                self.last_selection_time[server.server_id] = time.time()
            
        except Exception as e:
            self.logger.error(f"Failed to update selection stats: {e}")
    
    def get_nearest_servers(self, client_location: ClientLocation, 
                           count: int = 5, protocol: Optional[str] = None) -> List[ServerScore]:
        """Get nearest servers to client location."""
        return self.select_best_servers(
            client_location=client_location,
            protocol=protocol,
            count=count,
            strategy=LoadBalanceStrategy.GEOGRAPHIC
        )
    
    def get_fastest_servers(self, count: int = 5, protocol: Optional[str] = None) -> List[ServerScore]:
        """Get fastest servers based on response time."""
        return self.select_best_servers(
            protocol=protocol,
            count=count,
            strategy=LoadBalanceStrategy.RESPONSE_TIME
        )
    
    def get_least_loaded_servers(self, count: int = 5, 
                                protocol: Optional[str] = None) -> List[ServerScore]:
        """Get least loaded servers."""
        return self.select_best_servers(
            protocol=protocol,
            count=count,
            strategy=LoadBalanceStrategy.LEAST_CONNECTIONS
        )
    
    def get_highest_bandwidth_servers(self, count: int = 5,
                                     protocol: Optional[str] = None) -> List[ServerScore]:
        """Get servers with highest bandwidth."""
        return self.select_best_servers(
            protocol=protocol,
            count=count,
            strategy=LoadBalanceStrategy.BANDWIDTH
        )
    
    def get_region_servers(self, region: str, count: int = 5,
                           client_location: Optional[ClientLocation] = None,
                           protocol: Optional[str] = None) -> List[ServerScore]:
        """Get best servers in a specific region."""
        return self.select_best_servers(
            client_location=client_location,
            protocol=protocol,
            region=region,
            count=count,
            strategy=LoadBalanceStrategy.GEOGRAPHIC
        )
    
    def get_server_recommendations(self, client_location: Optional[ClientLocation] = None,
                                 protocol: Optional[str] = None,
                                 preferences: Dict[str, Any] = None) -> Dict[str, List[ServerScore]]:
        """Get server recommendations for different categories."""
        preferences = preferences or {}
        
        recommendations = {
            'nearest': self.get_nearest_servers(client_location, 
                                              count=preferences.get('count', 3), 
                                              protocol=protocol),
            'fastest': self.get_fastest_servers(count=preferences.get('count', 3), 
                                               protocol=protocol),
            'least_loaded': self.get_least_loaded_servers(count=preferences.get('count', 3), 
                                                        protocol=protocol),
            'highest_bandwidth': self.get_highest_bandwidth_servers(count=preferences.get('count', 3), 
                                                                  protocol=protocol)
        }
        
        # Add regional recommendations if location is known
        if client_location:
            recommendations['regional'] = self.get_region_servers(
                client_location.region, 
                count=preferences.get('count', 3),
                client_location=client_location,
                protocol=protocol
            )
        
        return recommendations
    
    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics."""
        return {
            'stats': self.stats,
            'default_strategy': self.default_strategy.name,
            'weights': self.weights,
            'max_servers_per_request': self.max_servers_per_request,
            'enable_geo_fallback': self.enable_geo_fallback,
            'geo_fallback_distance': self.geo_fallback_distance
        }
    
    def update_weights(self, weights: Dict[str, float]):
        """Update scoring weights."""
        try:
            # Validate weights
            valid_keys = {'geographic', 'performance', 'load', 'health'}
            for key in weights:
                if key not in valid_keys:
                    raise ValueError(f"Invalid weight key: {key}")
                if not 0 <= weights[key] <= 1:
                    raise ValueError(f"Weight {key} must be between 0 and 1")
            
            # Normalize weights
            total_weight = sum(weights.values())
            if total_weight == 0:
                raise ValueError("Sum of weights cannot be zero")
            
            self.weights = {k: v / total_weight for k, v in weights.items()}
            
            self.logger.info(f"Updated load balancer weights: {self.weights}")
            
        except Exception as e:
            self.logger.error(f"Failed to update weights: {e}")
            raise
    
    def reset_statistics(self):
        """Reset load balancer statistics."""
        self.stats = {
            'total_selections': 0,
            'strategy_usage': {strategy.name: 0 for strategy in LoadBalanceStrategy},
            'average_score': 0.0,
            'selections_by_region': {},
            'selections_by_protocol': {}
        }
        self.last_selection_time.clear()
        
        self.logger.info("Load balancer statistics reset")
