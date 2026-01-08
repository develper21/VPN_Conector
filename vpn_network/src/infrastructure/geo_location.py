"""
Geographic Routing System for VPN Global Infrastructure.
This module provides intelligent geographic routing, location-based server selection,
and global traffic optimization for VPN infrastructure.
"""
import os
import sys
import time
import json
import math
import asyncio
import threading
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, deque
import statistics

# Add src to path for imports
sys.path.insert(0, str(os.path.dirname(os.path.dirname(__file__))))

from discovery import VPNServer, ServerStatus
from utils.logger import LoggableMixin


class RoutingStrategy(Enum):
    """Geographic routing strategies."""
    NEAREST = auto()
    LOWEST_LATENCY = auto()
    LOAD_BALANCED = auto()
    REGION_PREFERRED = auto()
    COST_OPTIMIZED = auto()
    PERFORMANCE_BASED = auto()
    REDUNDANCY_REQUIRED = auto()


class Continent(Enum):
    """Continents for geographic grouping."""
    NORTH_AMERICA = auto()
    SOUTH_AMERICA = auto()
    EUROPE = auto()
    ASIA = auto()
    AFRICA = auto()
    OCEANIA = auto()
    ANTARCTICA = auto()


@dataclass
class GeoLocation:
    """Geographic location information."""
    latitude: float
    longitude: float
    country: str
    region: str
    city: str
    continent: Continent
    timezone: str
    asn: Optional[str] = None
    isp: Optional[str] = None
    
    def distance_to(self, other: 'GeoLocation') -> float:
        """Calculate distance to another location."""
        R = 6371.0  # Earth's radius in kilometers
        
        lat1_rad = math.radians(self.latitude)
        lon1_rad = math.radians(self.longitude)
        lat2_rad = math.radians(other.latitude)
        lon2_rad = math.radians(other.longitude)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c


@dataclass
class RouteRule:
    """Routing rule for geographic decisions."""
    rule_id: str
    name: str
    source_regions: List[str]
    target_regions: List[str]
    strategy: RoutingStrategy
    priority: int
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    enabled: bool
    created_at: float
    hit_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'source_regions': self.source_regions,
            'target_regions': self.target_regions,
            'strategy': self.strategy.name,
            'priority': self.priority,
            'conditions': self.conditions,
            'actions': self.actions,
            'enabled': self.enabled,
            'created_at': self.created_at,
            'hit_count': self.hit_count
        }


@dataclass
class TrafficRoute:
    """Traffic routing information."""
    route_id: str
    client_location: GeoLocation
    selected_server: str
    strategy: RoutingStrategy
    latency_ms: float
    bandwidth_mbps: float
    success: bool
    timestamp: float
    route_quality: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'route_id': self.route_id,
            'client_location': {
                'latitude': self.client_location.latitude,
                'longitude': self.client_location.longitude,
                'country': self.client_location.country,
                'region': self.client_location.region
            },
            'selected_server': self.selected_server,
            'strategy': self.strategy.name,
            'latency_ms': self.latency_ms,
            'bandwidth_mbps': self.bandwidth_mbps,
            'success': self.success,
            'timestamp': self.timestamp,
            'route_quality': self.route_quality
        }


class GeographicRouter(LoggableMixin):
    """Intelligent geographic routing system."""
    
    def __init__(self, config_path: str = "config/vpn_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.routing_config = self.config.get('geographic_routing', {})
        
        # Data storage
        self.server_locations: Dict[str, GeoLocation] = {}
        self.routing_rules: Dict[str, RouteRule] = {}
        self.traffic_routes: deque = deque(maxlen=10000)
        self.regional_servers: Dict[str, List[str]] = defaultdict(list)
        
        # Geographic data
        self.continent_mapping = self._load_continent_mapping()
        self.region_hierarchy = self._load_region_hierarchy()
        self.latency_matrix: Dict[Tuple[str, str], float] = {}
        
        # Routing state
        self.routing_cache: Dict[str, TrafficRoute] = {}
        self.cache_ttl = self.routing_config.get('cache_ttl', 300)  # 5 minutes
        
        # Background tasks
        self.update_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_routes': 0,
            'successful_routes': 0,
            'average_latency': 0.0,
            'cache_hits': 0,
            'cache_misses': 0,
            'rule_matches': 0,
            'strategy_usage': defaultdict(int)
        }
        
        # Initialize router
        self._initialize()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration."""
        try:
            from utils.config_loader import Config
            return Config(self.config_path).to_dict()
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return {}
    
    def _initialize(self):
        """Initialize the geographic routing system."""
        try:
            # Create directories
            os.makedirs('data/infrastructure/geographic', exist_ok=True)
            
            # Load data
            self._load_server_locations()
            self._load_routing_rules()
            self._load_traffic_history()
            
            # Initialize geographic data
            self._initialize_geographic_data()
            
            # Start background tasks
            self._start_background_tasks()
            
            self.logger.info("Geographic routing system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize geographic routing: {e}")
            raise
    
    def _load_server_locations(self):
        """Load server geographic locations."""
        try:
            locations_file = 'data/infrastructure/geographic/server_locations.json'
            if os.path.exists(locations_file):
                with open(locations_file, 'r') as f:
                    data = json.load(f)
                    for server_data in data.get('locations', []):
                        location = GeoLocation(
                            latitude=server_data['latitude'],
                            longitude=server_data['longitude'],
                            country=server_data['country'],
                            region=server_data['region'],
                            city=server_data['city'],
                            continent=Continent(server_data['continent']),
                            timezone=server_data['timezone'],
                            asn=server_data.get('asn'),
                            isp=server_data.get('isp')
                        )
                        self.server_locations[server_data['server_id']] = location
                        
                        # Update regional mapping
                        self.regional_servers[server_data['region']].append(server_data['server_id'])
                
                self.logger.info(f"Loaded {len(self.server_locations)} server locations")
                
        except Exception as e:
            self.logger.error(f"Failed to load server locations: {e}")
    
    def _load_routing_rules(self):
        """Load routing rules."""
        try:
            rules_file = 'data/infrastructure/geographic/routing_rules.json'
            if os.path.exists(rules_file):
                with open(rules_file, 'r') as f:
                    data = json.load(f)
                    for rule_data in data.get('rules', []):
                        rule = RouteRule(
                            rule_id=rule_data['rule_id'],
                            name=rule_data['name'],
                            source_regions=rule_data['source_regions'],
                            target_regions=rule_data['target_regions'],
                            strategy=RoutingStrategy(rule_data['strategy']),
                            priority=rule_data['priority'],
                            conditions=rule_data.get('conditions', {}),
                            actions=rule_data.get('actions', {}),
                            enabled=rule_data.get('enabled', True),
                            created_at=rule_data['created_at'],
                            hit_count=rule_data.get('hit_count', 0)
                        )
                        self.routing_rules[rule.rule_id] = rule
                
                self.logger.info(f"Loaded {len(self.routing_rules)} routing rules")
                
        except Exception as e:
            self.logger.error(f"Failed to load routing rules: {e}")
    
    def _load_traffic_history(self):
        """Load traffic routing history."""
        try:
            history_file = 'data/infrastructure/geographic/traffic_history.json'
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    for route_data in data.get('routes', []):
                        client_loc = GeoLocation(
                            latitude=route_data['client_location']['latitude'],
                            longitude=route_data['client_location']['longitude'],
                            country=route_data['client_location']['country'],
                            region=route_data['client_location']['region'],
                            city=route_data['client_location']['city'],
                            continent=Continent(route_data['client_location']['continent']),
                            timezone=route_data['client_location']['timezone']
                        )
                        
                        route = TrafficRoute(
                            route_id=route_data['route_id'],
                            client_location=client_loc,
                            selected_server=route_data['selected_server'],
                            strategy=RoutingStrategy(route_data['strategy']),
                            latency_ms=route_data['latency_ms'],
                            bandwidth_mbps=route_data['bandwidth_mbps'],
                            success=route_data['success'],
                            timestamp=route_data['timestamp'],
                            route_quality=route_data['route_quality']
                        )
                        self.traffic_routes.append(route)
                
                self.logger.info(f"Loaded {len(self.traffic_routes)} traffic routes from history")
                
        except Exception as e:
            self.logger.error(f"Failed to load traffic history: {e}")
    
    def _load_continent_mapping(self) -> Dict[str, Continent]:
        """Load continent mapping."""
        return {
            'US': Continent.NORTH_AMERICA,
            'CA': Continent.NORTH_AMERICA,
            'MX': Continent.NORTH_AMERICA,
            'GB': Continent.EUROPE,
            'DE': Continent.EUROPE,
            'FR': Continent.EUROPE,
            'IT': Continent.EUROPE,
            'ES': Continent.EUROPE,
            'CN': Continent.ASIA,
            'JP': Continent.ASIA,
            'KR': Continent.ASIA,
            'IN': Continent.ASIA,
            'SG': Continent.ASIA,
            'AU': Continent.OCEANIA,
            'NZ': Continent.OCEANIA,
            'BR': Continent.SOUTH_AMERICA,
            'AR': Continent.SOUTH_AMERICA,
            'ZA': Continent.AFRICA,
            'EG': Continent.AFRICA
        }
    
    def _load_region_hierarchy(self) -> Dict[str, List[str]]:
        """Load region hierarchy for geographic routing."""
        return {
            'global': ['us-east-1', 'us-west-1', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'],
            'north_america': ['us-east-1', 'us-west-1', 'ca-central-1'],
            'europe': ['eu-west-1', 'eu-central-1', 'eu-north-1'],
            'asia': ['ap-southeast-1', 'ap-northeast-1', 'ap-south-1'],
            'oceania': ['ap-southeast-2', 'au-east-1']
        }
    
    def _initialize_geographic_data(self):
        """Initialize geographic data structures."""
        try:
            # Build latency matrix from historical data
            self._build_latency_matrix()
            
            # Optimize regional server mapping
            self._optimize_regional_mapping()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize geographic data: {e}")
    
    def _build_latency_matrix(self):
        """Build latency matrix from historical routes."""
        try:
            latency_data = defaultdict(list)
            
            for route in self.traffic_routes:
                if route.success:
                    client_region = route.client_location.region
                    server_region = self._get_server_region(route.selected_server)
                    
                    if server_region:
                        key = (client_region, server_region)
                        latency_data[key].append(route.latency_ms)
            
            # Calculate average latencies
            for key, latencies in latency_data.items():
                if latencies:
                    self.latency_matrix[key] = statistics.mean(latencies)
            
            self.logger.info(f"Built latency matrix with {len(self.latency_matrix)} entries")
            
        except Exception as e:
            self.logger.error(f"Failed to build latency matrix: {e}")
    
    def _get_server_region(self, server_id: str) -> Optional[str]:
        """Get region for a server."""
        location = self.server_locations.get(server_id)
        return location.region if location else None
    
    def _optimize_regional_mapping(self):
        """Optimize regional server mapping."""
        try:
            # Ensure all servers are properly mapped to regions
            for server_id, location in self.server_locations.items():
                if location.region not in self.regional_servers:
                    self.regional_servers[location.region] = []
                if server_id not in self.regional_servers[location.region]:
                    self.regional_servers[location.region].append(server_id)
            
            self.logger.info(f"Optimized regional mapping for {len(self.regional_servers)} regions")
            
        except Exception as e:
            self.logger.error(f"Failed to optimize regional mapping: {e}")
    
    def route_client(self, client_location: GeoLocation, 
                   available_servers: List[str], 
                   strategy: Optional[RoutingStrategy] = None) -> Optional[TrafficRoute]:
        """Route client to optimal server."""
        try:
            # Check cache first
            cache_key = self._generate_cache_key(client_location, available_servers)
            cached_route = self._get_cached_route(cache_key)
            
            if cached_route:
                self.stats['cache_hits'] += 1
                return cached_route
            
            self.stats['cache_misses'] += 1
            
            # Determine routing strategy
            if not strategy:
                strategy = self._determine_routing_strategy(client_location, available_servers)
            
            # Apply routing rules
            applicable_rules = self._find_applicable_rules(client_location, available_servers)
            if applicable_rules:
                strategy = applicable_rules[0].strategy
                applicable_rules[0].hit_count += 1
                self.stats['rule_matches'] += 1
            
            # Select server based on strategy
            selected_server = self._select_server_by_strategy(
                client_location, available_servers, strategy
            )
            
            if not selected_server:
                self.logger.warning("No server selected for routing")
                return None
            
            # Create route
            route = TrafficRoute(
                route_id=f"route_{int(time.time())}_{hash(str(client_location))[:8]}",
                client_location=client_location,
                selected_server=selected_server,
                strategy=strategy,
                latency_ms=self._estimate_latency(client_location, selected_server),
                bandwidth_mbps=self._estimate_bandwidth(selected_server),
                success=True,
                timestamp=time.time(),
                route_quality=self._calculate_route_quality(client_location, selected_server)
            )
            
            # Cache the route
            self._cache_route(cache_key, route)
            
            # Record the route
            self.traffic_routes.append(route)
            self._save_traffic_history()
            
            # Update statistics
            self.stats['total_routes'] += 1
            self.stats['successful_routes'] += 1
            self.stats['strategy_usage'][strategy.name] += 1
            
            self.logger.info(f"Routed client to {selected_server} using {strategy.name}")
            return route
            
        except Exception as e:
            self.logger.error(f"Failed to route client: {e}")
            return None
    
    def _determine_routing_strategy(self, client_location: GeoLocation, 
                               available_servers: List[str]) -> RoutingStrategy:
        """Determine optimal routing strategy."""
        try:
            # Check for specific rules
            applicable_rules = self._find_applicable_rules(client_location, available_servers)
            if applicable_rules:
                return applicable_rules[0].strategy
            
            # Default strategy based on configuration
            default_strategy = self.routing_config.get('default_strategy', 'NEAREST')
            return RoutingStrategy[default_strategy]
            
        except Exception as e:
            self.logger.error(f"Failed to determine routing strategy: {e}")
            return RoutingStrategy.NEAREST
    
    def _find_applicable_rules(self, client_location: GeoLocation, 
                              available_servers: List[str]) -> List[RouteRule]:
        """Find applicable routing rules."""
        try:
            applicable_rules = []
            
            for rule in self.routing_rules.values():
                if not rule.enabled:
                    continue
                
                # Check if rule applies
                if self._rule_applies(rule, client_location, available_servers):
                    applicable_rules.append(rule)
            
            # Sort by priority (lower number = higher priority)
            applicable_rules.sort(key=lambda r: r.priority)
            
            return applicable_rules
            
        except Exception as e:
            self.logger.error(f"Failed to find applicable rules: {e}")
            return []
    
    def _rule_applies(self, rule: RouteRule, client_location: GeoLocation, 
                     available_servers: List[str]) -> bool:
        """Check if a routing rule applies."""
        try:
            # Check source regions
            if rule.source_regions:
                if client_location.region not in rule.source_regions:
                    return False
            
            # Check conditions
            conditions = rule.conditions
            
            # Time-based conditions
            if 'time_range' in conditions:
                current_hour = time.localtime().tm_hour
                start_hour = conditions['time_range'].get('start', 0)
                end_hour = conditions['time_range'].get('end', 23)
                
                if start_hour <= end_hour:
                    if not (start_hour <= current_hour <= end_hour):
                        return False
                else:
                    if not (current_hour >= start_hour or current_hour <= end_hour):
                        return False
                    return True
            
            # Load-based conditions
            if 'max_load' in conditions:
                max_load = conditions['max_load']
                region_load = self._get_region_load(client_location.region)
                if region_load > max_load:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to check rule applicability: {e}")
            return False
    
    def _get_region_load(self, region: str) -> float:
        """Get current load for a region."""
        try:
            servers_in_region = self.regional_servers.get(region, [])
            if not servers_in_region:
                return 0.0
            
            total_load = 0.0
            server_count = 0
            
            for server_id in servers_in_region:
                # This would get actual server load from server manager
                # For now, simulate based on recent routes
                recent_routes = [r for r in self.traffic_routes 
                               if r.selected_server in servers_in_region and 
                               time.time() - r.timestamp < 300]  # Last 5 minutes
                
                if recent_routes:
                    avg_load = len(recent_routes) / len(servers_in_region)
                    total_load += avg_load
                    server_count += 1
            
            return total_load / server_count if server_count > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Failed to get region load: {e}")
            return 0.0
    
    def _select_server_by_strategy(self, client_location: GeoLocation,
                               available_servers: List[str],
                               strategy: RoutingStrategy) -> Optional[str]:
        """Select server based on routing strategy."""
        try:
            if strategy == RoutingStrategy.NEAREST:
                return self._select_nearest_server(client_location, available_servers)
            elif strategy == RoutingStrategy.LOWEST_LATENCY:
                return self._select_lowest_latency_server(client_location, available_servers)
            elif strategy == RoutingStrategy.LOAD_BALANCED:
                return self._select_load_balanced_server(available_servers)
            elif strategy == RoutingStrategy.REGION_PREFERRED:
                return self._select_region_preferred_server(client_location, available_servers)
            elif strategy == RoutingStrategy.PERFORMANCE_BASED:
                return self._select_performance_based_server(available_servers)
            else:
                return self._select_nearest_server(client_location, available_servers)
                
        except Exception as e:
            self.logger.error(f"Failed to select server by strategy: {e}")
            return None
    
    def _select_nearest_server(self, client_location: GeoLocation,
                             available_servers: List[str]) -> Optional[str]:
        """Select nearest server."""
        try:
            if not available_servers:
                return None
            
            nearest_server = None
            min_distance = float('inf')
            
            for server_id in available_servers:
                server_location = self.server_locations.get(server_id)
                if server_location:
                    distance = client_location.distance_to(server_location)
                    if distance < min_distance:
                        min_distance = distance
                        nearest_server = server_id
            
            return nearest_server
            
        except Exception as e:
            self.logger.error(f"Failed to select nearest server: {e}")
            return None
    
    def _select_lowest_latency_server(self, client_location: GeoLocation,
                                   available_servers: List[str]) -> Optional[str]:
        """Select server with lowest latency."""
        try:
            if not available_servers:
                return None
            
            best_server = None
            min_latency = float('inf')
            client_region = client_location.region
            
            for server_id in available_servers:
                server_region = self._get_server_region(server_id)
                if server_region:
                    key = (client_region, server_region)
                    latency = self.latency_matrix.get(key, float('inf'))
                    
                    if latency < min_latency:
                        min_latency = latency
                        best_server = server_id
            
            return best_server
            
        except Exception as e:
            self.logger.error(f"Failed to select lowest latency server: {e}")
            return None
    
    def _select_load_balanced_server(self, available_servers: List[str]) -> Optional[str]:
        """Select server using load balancing."""
        try:
            if not available_servers:
                return None
            
            # Simple round-robin for now
            # In a real implementation, this would consider actual server loads
            import random
            return random.choice(available_servers)
            
        except Exception as e:
            self.logger.error(f"Failed to select load balanced server: {e}")
            return None
    
    def _select_region_preferred_server(self, client_location: GeoLocation,
                                   available_servers: List[str]) -> Optional[str]:
        """Select server in preferred region."""
        try:
            if not available_servers:
                return None
            
            # Prefer servers in same continent
            same_continent_servers = []
            
            for server_id in available_servers:
                server_location = self.server_locations.get(server_id)
                if server_location and server_location.continent == client_location.continent:
                    same_continent_servers.append(server_id)
            
            if same_continent_servers:
                return self._select_nearest_server(client_location, same_continent_servers)
            else:
                return self._select_nearest_server(client_location, available_servers)
                
        except Exception as e:
            self.logger.error(f"Failed to select region preferred server: {e}")
            return None
    
    def _select_performance_based_server(self, available_servers: List[str]) -> Optional[str]:
        """Select server based on performance metrics."""
        try:
            if not available_servers:
                return None
            
            best_server = None
            best_score = 0.0
            
            for server_id in available_servers:
                # Calculate performance score based on recent routes
                recent_routes = [r for r in self.traffic_routes 
                               if r.selected_server == server_id and 
                               time.time() - r.timestamp < 3600]  # Last hour
                
                if recent_routes:
                    avg_quality = statistics.mean([r.route_quality for r in recent_routes])
                    if avg_quality > best_score:
                        best_score = avg_quality
                        best_server = server_id
            
            return best_server
            
        except Exception as e:
            self.logger.error(f"Failed to select performance based server: {e}")
            return None
    
    def _estimate_latency(self, client_location: GeoLocation, server_id: str) -> float:
        """Estimate latency between client and server."""
        try:
            server_location = self.server_locations.get(server_id)
            if not server_location:
                return 100.0  # Default high latency
            
            # Base latency from distance
            distance = client_location.distance_to(server_location)
            distance_latency = distance * 0.01  # 10ms per 1000km
            
            # Add historical latency if available
            client_region = client_location.region
            server_region = server_location.region
            key = (client_region, server_region)
            historical_latency = self.latency_matrix.get(key, 0.0)
            
            # Weighted average
            if historical_latency > 0:
                return (distance_latency * 0.3) + (historical_latency * 0.7)
            else:
                return distance_latency
                
        except Exception as e:
            self.logger.error(f"Failed to estimate latency: {e}")
            return 100.0
    
    def _estimate_bandwidth(self, server_id: str) -> float:
        """Estimate available bandwidth for server."""
        try:
            # This would get actual bandwidth from server metrics
            # For now, return a reasonable estimate
            return 100.0  # 100 Mbps default
            
        except Exception as e:
            self.logger.error(f"Failed to estimate bandwidth: {e}")
            return 10.0
    
    def _calculate_route_quality(self, client_location: GeoLocation, server_id: str) -> float:
        """Calculate quality score for a route."""
        try:
            latency = self._estimate_latency(client_location, server_id)
            bandwidth = self._estimate_bandwidth(server_id)
            
            # Normalize metrics
            latency_score = max(0, 1 - (latency / 200))  # 200ms = 0 score
            bandwidth_score = min(1, bandwidth / 1000)  # 1000Mbps = 1 score
            
            # Weighted combination
            quality = (latency_score * 0.7) + (bandwidth_score * 0.3)
            return quality
            
        except Exception as e:
            self.logger.error(f"Failed to calculate route quality: {e}")
            return 0.0
    
    def _generate_cache_key(self, client_location: GeoLocation, available_servers: List[str]) -> str:
        """Generate cache key for routing."""
        try:
            key_data = f"{client_location.latitude:.4f},{client_location.longitude:.4f}"
            key_data += f":{','.join(sorted(available_servers))}"
            return hashlib.md5(key_data.encode()).hexdigest()
            
        except Exception as e:
            self.logger.error(f"Failed to generate cache key: {e}")
            return ""
    
    def _get_cached_route(self, cache_key: str) -> Optional[TrafficRoute]:
        """Get cached route if available."""
        try:
            cached_route = self.routing_cache.get(cache_key)
            if cached_route:
                # Check if cache is still valid
                if time.time() - cached_route.timestamp < self.cache_ttl:
                    return cached_route
                else:
                    # Remove expired cache entry
                    del self.routing_cache[cache_key]
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get cached route: {e}")
            return None
    
    def _cache_route(self, cache_key: str, route: TrafficRoute):
        """Cache a routing decision."""
        try:
            self.routing_cache[cache_key] = route
            
            # Clean old cache entries
            current_time = time.time()
            expired_keys = [
                key for key, cached_route in self.routing_cache.items()
                if current_time - cached_route.timestamp > self.cache_ttl
            ]
            
            for key in expired_keys:
                del self.routing_cache[key]
            
        except Exception as e:
            self.logger.error(f"Failed to cache route: {e}")
    
    def add_routing_rule(self, rule_config: Dict[str, Any]) -> str:
        """Add a new routing rule."""
        try:
            rule_id = f"rule_{int(time.time())}_{hash(str(rule_config))[:8]}"
            
            rule = RouteRule(
                rule_id=rule_id,
                name=rule_config.get('name', f"Rule {rule_id[:8]}"),
                source_regions=rule_config.get('source_regions', []),
                target_regions=rule_config.get('target_regions', []),
                strategy=RoutingStrategy(rule_config.get('strategy', 'NEAREST')),
                priority=rule_config.get('priority', 100),
                conditions=rule_config.get('conditions', {}),
                actions=rule_config.get('actions', {}),
                enabled=rule_config.get('enabled', True),
                created_at=time.time()
            )
            
            self.routing_rules[rule_id] = rule
            self._save_routing_rules()
            
            self.logger.info(f"Added routing rule: {rule_id}")
            return rule_id
            
        except Exception as e:
            self.logger.error(f"Failed to add routing rule: {e}")
            raise
    
    def get_routing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive routing statistics."""
        try:
            # Calculate average latency
            if self.traffic_routes:
                recent_routes = [r for r in self.traffic_routes 
                               if time.time() - r.timestamp < 3600]  # Last hour
                if recent_routes:
                    self.stats['average_latency'] = statistics.mean([r.latency_ms for r in recent_routes])
            
            return {
                'statistics': self.stats,
                'cache_size': len(self.routing_cache),
                'rule_count': len(self.routing_rules),
                'traffic_routes_last_hour': len([r for r in self.traffic_routes 
                                                 if time.time() - r.timestamp < 3600]),
                'server_locations_count': len(self.server_locations),
                'regional_servers_count': len(self.regional_servers),
                'latency_matrix_size': len(self.latency_matrix),
                'strategy_distribution': dict(self.stats['strategy_usage'])
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get routing statistics: {e}")
            return {}
    
    def _save_traffic_history(self):
        """Save traffic routing history."""
        try:
            history_data = {
                'routes': [route.to_dict() for route in list(self.traffic_routes)[-1000]],  # Last 1000 routes
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/geographic/traffic_history.json', 'w') as f:
                json.dump(history_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save traffic history: {e}")
    
    def _save_routing_rules(self):
        """Save routing rules."""
        try:
            rules_data = {
                'rules': [rule.to_dict() for rule in self.routing_rules.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/geographic/routing_rules.json', 'w') as f:
                json.dump(rules_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save routing rules: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks."""
        if self.running:
            return
        
        self.running = True
        
        # Start update thread
        self.update_thread = threading.Thread(target=self._update_worker, daemon=True)
        self.update_thread.start()
        
        self.logger.info("Background tasks started")
    
    def _update_worker(self):
        """Background worker for updating geographic data."""
        while self.running:
            try:
                # Update statistics
                self.stats['total_routes'] = len(self.traffic_routes)
                
                # Clean old data
                current_time = time.time()
                cutoff_time = current_time - 86400  # 24 hours
                
                # Clean old traffic routes
                while (self.traffic_routes and 
                       self.traffic_routes[0].timestamp < cutoff_time):
                    self.traffic_routes.popleft()
                
                time.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Update worker error: {e}")
                time.sleep(30)
    
    def stop(self):
        """Stop the geographic routing system."""
        try:
            self.running = False
            
            if self.update_thread and self.update_thread.is_alive():
                self.update_thread.join(timeout=10)
            
            # Save final state
            self._save_traffic_history()
            self._save_routing_rules()
            
            self.logger.info("Geographic routing system stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop geographic routing system: {e}")
