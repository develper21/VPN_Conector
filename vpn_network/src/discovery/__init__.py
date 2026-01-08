"""
Discovery package for VPN Security Project.
"""

from .server_discovery import ServerDiscovery, VPNServer, ServerStatus, DiscoveryMethod
from .server_registry import ServerRegistry, ServerMetrics, ServerHistory
from .health_checker import HealthChecker, HealthCheckResult, HealthStatus, HealthCheckType
from .geographic_load_balancer import GeographicLoadBalancer, LoadBalanceStrategy, ClientLocation
from .advanced_load_balancer import (
    AdvancedLoadBalancer, LoadBalanceAlgorithm, ServerWeight, FailoverConfig,
    PerformanceMetrics, FailoverStrategy
)
from .failover_manager import (
    FailoverManager, FailoverEvent, FailoverState, FailoverTrigger,
    FailoverPolicy
)
from .performance_dashboard import (
    PerformanceDashboard, ServerPerformanceSnapshot, LoadBalancingMetrics,
    FailoverMetrics
)

__all__ = [
    'ServerDiscovery',
    'VPNServer',
    'ServerStatus',
    'DiscoveryMethod',
    'ServerRegistry',
    'ServerMetrics',
    'ServerHistory',
    'HealthChecker',
    'HealthCheckResult',
    'HealthStatus',
    'HealthCheckType',
    'GeographicLoadBalancer',
    'LoadBalanceStrategy',
    'ClientLocation',
    'AdvancedLoadBalancer',
    'LoadBalanceAlgorithm',
    'ServerWeight',
    'FailoverConfig',
    'PerformanceMetrics',
    'FailoverStrategy',
    'FailoverManager',
    'FailoverEvent',
    'FailoverState',
    'FailoverTrigger',
    'FailoverPolicy',
    'PerformanceDashboard',
    'ServerPerformanceSnapshot',
    'LoadBalancingMetrics',
    'FailoverMetrics'
]
