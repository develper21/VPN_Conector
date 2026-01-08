"""
Performance Monitoring Dashboard for VPN Security Project.
This module provides a comprehensive dashboard for monitoring server performance,
load balancing effectiveness, and failover events.
"""
import time
import json
import statistics
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta

from discovery.server_discovery import VPNServer, ServerStatus
from discovery.server_registry import ServerRegistry
from discovery.health_checker import HealthChecker, HealthStatus
from discovery.advanced_load_balancer import AdvancedLoadBalancer, LoadBalanceAlgorithm
from discovery.failover_manager import FailoverManager, FailoverState, FailoverTrigger
from utils.logger import LoggableMixin


@dataclass
class ServerPerformanceSnapshot:
    """Snapshot of server performance metrics."""
    timestamp: float
    server_id: str
    response_time: float
    bandwidth_mbps: float
    packet_loss: float
    cpu_usage: float
    memory_usage: float
    active_connections: int
    error_rate: float
    health_status: str
    load_percentage: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class LoadBalancingMetrics:
    """Load balancing performance metrics."""
    timestamp: float
    algorithm: str
    total_selections: int
    successful_selections: int
    failed_selections: int
    average_selection_time: float
    server_distribution: Dict[str, int]
    algorithm_effectiveness: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FailoverMetrics:
    """Failover performance metrics."""
    timestamp: float
    active_failovers: int
    total_failovers: int
    successful_failovers: int
    failed_failovers: int
    average_failover_time: float
    recovery_rate: float
    circuit_breaker_trips: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class PerformanceDashboard(LoggableMixin):
    """Performance monitoring dashboard."""
    
    def __init__(self, config: Dict[str, Any], registry: ServerRegistry,
                 health_checker: HealthChecker, load_balancer: AdvancedLoadBalancer,
                 failover_manager: FailoverManager):
        self.config = config
        self.registry = registry
        self.health_checker = health_checker
        self.load_balancer = load_balancer
        self.failover_manager = failover_manager
        self.dashboard_config = config.get('performance_dashboard', {})
        
        # Data retention
        self.retention_hours = self.dashboard_config.get('retention_hours', 24)
        self.max_snapshots = self.dashboard_config.get('max_snapshots', 1000)
        
        # Performance data storage
        self.server_snapshots: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.max_snapshots))
        self.load_balancing_metrics: deque = deque(maxlen=self.max_snapshots)
        self.failover_metrics: deque = deque(maxlen=self.max_snapshots)
        
        # Real-time statistics
        self.real_time_stats = {
            'total_servers': 0,
            'healthy_servers': 0,
            'unhealthy_servers': 0,
            'average_response_time': 0.0,
            'average_bandwidth': 0.0,
            'total_connections': 0,
            'total_failovers': 0,
            'system_health_score': 0.0
        }
        
        # Alert thresholds
        self.alert_thresholds = self.dashboard_config.get('alert_thresholds', {
            'response_time_warning': 500.0,
            'response_time_critical': 1000.0,
            'packet_loss_warning': 0.01,
            'packet_loss_critical': 0.05,
            'error_rate_warning': 0.05,
            'error_rate_critical': 0.1,
            'cpu_usage_warning': 0.8,
            'cpu_usage_critical': 0.95,
            'memory_usage_warning': 0.8,
            'memory_usage_critical': 0.95
        })
        
        # Alerts
        self.active_alerts: List[Dict[str, Any]] = []
        self.alert_history: deque = deque(maxlen=1000)
        
        # Performance trends
        self.performance_trends: Dict[str, Dict[str, float]] = {}
        
        # Initialize dashboard
        self._initialize()
    
    def _initialize(self):
        """Initialize the performance dashboard."""
        try:
            # Collect initial data
            self._collect_performance_data()
            
            self.logger.info("Performance dashboard initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize performance dashboard: {e}")
            raise
    
    def update_dashboard(self):
        """Update dashboard with latest performance data."""
        try:
            # Collect performance data
            self._collect_performance_data()
            
            # Update real-time statistics
            self._update_real_time_stats()
            
            # Check for alerts
            self._check_alerts()
            
            # Update performance trends
            self._update_performance_trends()
            
            # Clean old data
            self._cleanup_old_data()
            
        except Exception as e:
            self.logger.error(f"Failed to update dashboard: {e}")
    
    def _collect_performance_data(self):
        """Collect performance data from all components."""
        current_time = time.time()
        
        # Collect server performance data
        servers = self.registry.get_all_servers()
        
        for server in servers:
            snapshot = ServerPerformanceSnapshot(
                timestamp=current_time,
                server_id=server.server_id,
                response_time=server.response_time,
                bandwidth_mbps=server.bandwidth_mbps,
                packet_loss=0.0,  # Would get from health checker
                cpu_usage=server.load,
                memory_usage=0.0,  # Would get from health checker
                active_connections=server.current_clients,
                error_rate=0.0,  # Would calculate from connection history
                health_status=self.health_checker.get_server_health(server.server_id).name,
                load_percentage=server.load * 100
            )
            
            self.server_snapshots[server.server_id].append(snapshot)
        
        # Collect load balancing metrics
        lb_stats = self.load_balancer.get_load_balancer_stats()
        
        lb_metrics = LoadBalancingMetrics(
            timestamp=current_time,
            algorithm=self.load_balancer.default_algorithm.name,
            total_selections=lb_stats['stats']['total_selections'],
            successful_selections=lb_stats['stats'].get('successful_selections', 0),
            failed_selections=lb_stats['stats'].get('failed_selections', 0),
            average_selection_time=0.0,  # Would track actual selection time
            server_distribution=lb_stats.get('algorithm_usage', {}),
            algorithm_effectiveness=self._calculate_algorithm_effectiveness()
        )
        
        self.load_balancing_metrics.append(lb_metrics)
        
        # Collect failover metrics
        failover_stats = self.failover_manager.get_failover_status()
        
        failover_metrics = FailoverMetrics(
            timestamp=current_time,
            active_failovers=failover_stats['active_failovers'],
            total_failovers=failover_stats['stats']['total_failovers'],
            successful_failovers=failover_stats['stats']['successful_failovers'],
            failed_failovers=failover_stats['stats']['failed_failovers'],
            average_failover_time=failover_stats['stats']['average_failover_time'],
            recovery_rate=self._calculate_recovery_rate(),
            circuit_breaker_trips=failover_stats['stats']['circuit_breaker_trips']
        )
        
        self.failover_metrics.append(failover_metrics)
    
    def _calculate_algorithm_effectiveness(self) -> float:
        """Calculate load balancing algorithm effectiveness."""
        try:
            if not self.load_balancing_metrics:
                return 0.0
            
            # Get recent metrics
            recent_metrics = list(self.load_balancing_metrics)[-10:]
            
            if not recent_metrics:
                return 0.0
            
            # Calculate success rate
            total_selections = sum(m.total_selections for m in recent_metrics)
            successful_selections = sum(m.successful_selections for m in recent_metrics)
            
            if total_selections == 0:
                return 0.0
            
            success_rate = successful_selections / total_selections
            
            # Calculate server distribution balance
            server_counts = defaultdict(int)
            for metric in recent_metrics:
                for server_id, count in metric.server_distribution.items():
                    server_counts[server_id] += count
            
            if server_counts:
                # Calculate coefficient of variation (lower is better)
                counts = list(server_counts.values())
                mean_count = statistics.mean(counts)
                if mean_count > 0:
                    std_dev = statistics.stdev(counts) if len(counts) > 1 else 0
                    cv = std_dev / mean_count
                    balance_score = max(0, 1 - cv)  # Convert to 0-1 scale
                else:
                    balance_score = 0.0
            else:
                balance_score = 0.0
            
            # Combine success rate and balance
            effectiveness = (success_rate * 0.7 + balance_score * 0.3)
            
            return effectiveness
            
        except Exception as e:
            self.logger.error(f"Failed to calculate algorithm effectiveness: {e}")
            return 0.0
    
    def _calculate_recovery_rate(self) -> float:
        """Calculate failover recovery rate."""
        try:
            failover_stats = self.failover_manager.get_failover_status()
            
            total_failovers = failover_stats['stats']['total_failovers']
            successful_recoveries = failover_stats['stats']['successful_recoveries']
            
            if total_failovers == 0:
                return 1.0  # Perfect rate if no failovers
            
            return successful_recoveries / total_failovers
            
        except Exception as e:
            self.logger.error(f"Failed to calculate recovery rate: {e}")
            return 0.0
    
    def _update_real_time_stats(self):
        """Update real-time statistics."""
        try:
            servers = self.registry.get_all_servers()
            
            # Server counts
            self.real_time_stats['total_servers'] = len(servers)
            
            healthy_count = 0
            unhealthy_count = 0
            total_response_time = 0.0
            total_bandwidth = 0.0
            total_connections = 0
            
            for server in servers:
                health_status = self.health_checker.get_server_health(server.server_id)
                
                if health_status == HealthStatus.HEALTHY:
                    healthy_count += 1
                else:
                    unhealthy_count += 1
                
                total_response_time += server.response_time
                total_bandwidth += server.bandwidth_mbps
                total_connections += server.current_clients
            
            self.real_time_stats['healthy_servers'] = healthy_count
            self.real_time_stats['unhealthy_servers'] = unhealthy_count
            
            if servers:
                self.real_time_stats['average_response_time'] = total_response_time / len(servers)
                self.real_time_stats['average_bandwidth'] = total_bandwidth / len(servers)
            
            self.real_time_stats['total_connections'] = total_connections
            
            # Failover stats
            failover_stats = self.failover_manager.get_failover_status()
            self.real_time_stats['total_failovers'] = failover_stats['active_failovers']
            
            # System health score
            self.real_time_stats['system_health_score'] = self._calculate_system_health_score()
            
        except Exception as e:
            self.logger.error(f"Failed to update real-time stats: {e}")
    
    def _calculate_system_health_score(self) -> float:
        """Calculate overall system health score."""
        try:
            if self.real_time_stats['total_servers'] == 0:
                return 0.0
            
            # Server health component
            server_health_ratio = (self.real_time_stats['healthy_servers'] / 
                                 self.real_time_stats['total_servers'])
            
            # Performance component
            performance_score = 1.0
            if self.real_time_stats['average_response_time'] > 0:
                response_time_score = max(0, 1 - (self.real_time_stats['average_response_time'] / 1000))
                performance_score = response_time_score
            
            # Failover component (lower failovers = better health)
            failover_ratio = self.real_time_stats['total_failovers'] / max(1, self.real_time_stats['total_servers'])
            failover_score = max(0, 1 - failover_ratio)
            
            # Load balancing component
            if self.load_balancing_metrics:
                latest_lb = self.load_balancing_metrics[-1]
                lb_score = latest_lb.algorithm_effectiveness
            else:
                lb_score = 0.5
            
            # Weighted combination
            health_score = (
                server_health_ratio * 0.4 +
                performance_score * 0.3 +
                failover_score * 0.2 +
                lb_score * 0.1
            )
            
            return health_score
            
        except Exception as e:
            self.logger.error(f"Failed to calculate system health score: {e}")
            return 0.0
    
    def _check_alerts(self):
        """Check for performance alerts."""
        try:
            current_time = time.time()
            new_alerts = []
            
            # Check server performance alerts
            for server_id, snapshots in self.server_snapshots.items():
                if not snapshots:
                    continue
                
                latest = snapshots[-1]
                
                # Response time alerts
                if latest.response_time >= self.alert_thresholds['response_time_critical']:
                    alert = {
                        'timestamp': current_time,
                        'type': 'critical',
                        'category': 'response_time',
                        'server_id': server_id,
                        'value': latest.response_time,
                        'threshold': self.alert_thresholds['response_time_critical'],
                        'message': f"Critical response time: {latest.response_time:.2f}ms"
                    }
                    new_alerts.append(alert)
                
                elif latest.response_time >= self.alert_thresholds['response_time_warning']:
                    alert = {
                        'timestamp': current_time,
                        'type': 'warning',
                        'category': 'response_time',
                        'server_id': server_id,
                        'value': latest.response_time,
                        'threshold': self.alert_thresholds['response_time_warning'],
                        'message': f"High response time: {latest.response_time:.2f}ms"
                    }
                    new_alerts.append(alert)
                
                # CPU usage alerts
                if latest.cpu_usage >= self.alert_thresholds['cpu_usage_critical']:
                    alert = {
                        'timestamp': current_time,
                        'type': 'critical',
                        'category': 'cpu_usage',
                        'server_id': server_id,
                        'value': latest.cpu_usage,
                        'threshold': self.alert_thresholds['cpu_usage_critical'],
                        'message': f"Critical CPU usage: {latest.cpu_usage * 100:.1f}%"
                    }
                    new_alerts.append(alert)
                
                elif latest.cpu_usage >= self.alert_thresholds['cpu_usage_warning']:
                    alert = {
                        'timestamp': current_time,
                        'type': 'warning',
                        'category': 'cpu_usage',
                        'server_id': server_id,
                        'value': latest.cpu_usage,
                        'threshold': self.alert_thresholds['cpu_usage_warning'],
                        'message': f"High CPU usage: {latest.cpu_usage * 100:.1f}%"
                    }
                    new_alerts.append(alert)
                
                # Health status alerts
                if latest.health_status == 'CRITICAL':
                    alert = {
                        'timestamp': current_time,
                        'type': 'critical',
                        'category': 'health_status',
                        'server_id': server_id,
                        'value': latest.health_status,
                        'threshold': 'HEALTHY',
                        'message': f"Server health critical: {server_id}"
                    }
                    new_alerts.append(alert)
            
            # Check system-level alerts
            if self.real_time_stats['system_health_score'] < 0.5:
                alert = {
                    'timestamp': current_time,
                    'type': 'critical',
                    'category': 'system_health',
                    'server_id': 'system',
                    'value': self.real_time_stats['system_health_score'],
                    'threshold': 0.5,
                    'message': f"System health critical: {self.real_time_stats['system_health_score']:.2f}"
                }
                new_alerts.append(alert)
            
            # Update active alerts
            self.active_alerts.extend(new_alerts)
            
            # Keep only recent alerts (last hour)
            cutoff_time = current_time - 3600
            self.active_alerts = [a for a in self.active_alerts if a['timestamp'] > cutoff_time]
            
            # Add to history
            self.alert_history.extend(new_alerts)
            
        except Exception as e:
            self.logger.error(f"Failed to check alerts: {e}")
    
    def _update_performance_trends(self):
        """Update performance trends."""
        try:
            current_time = time.time()
            
            # Update server trends
            for server_id, snapshots in self.server_snapshots.items():
                if len(snapshots) < 10:
                    continue
                
                # Calculate trends for different metrics
                recent_snapshots = list(snapshots)[-10:]
                
                # Response time trend
                response_times = [s.response_time for s in recent_snapshots if s.response_time > 0]
                if len(response_times) >= 2:
                    old_avg = statistics.mean(response_times[:5])
                    new_avg = statistics.mean(response_times[5:])
                    trend = (new_avg - old_avg) / old_avg if old_avg > 0 else 0
                else:
                    trend = 0.0
                
                # Bandwidth trend
                bandwidths = [s.bandwidth_mbps for s in recent_snapshots if s.bandwidth_mbps > 0]
                if len(bandwidths) >= 2:
                    old_avg = statistics.mean(bandwidths[:5])
                    new_avg = statistics.mean(bandwidths[5:])
                    bandwidth_trend = (new_avg - old_avg) / old_avg if old_avg > 0 else 0
                else:
                    bandwidth_trend = 0.0
                
                # CPU usage trend
                cpu_usages = [s.cpu_usage for s in recent_snapshots]
                if len(cpu_usages) >= 2:
                    old_avg = statistics.mean(cpu_usages[:5])
                    new_avg = statistics.mean(cpu_usages[5:])
                    cpu_trend = (new_avg - old_avg) / old_avg if old_avg > 0 else 0
                else:
                    cpu_trend = 0.0
                
                self.performance_trends[server_id] = {
                    'response_time_trend': trend,
                    'bandwidth_trend': bandwidth_trend,
                    'cpu_trend': cpu_trend,
                    'last_updated': current_time
                }
            
        except Exception as e:
            self.logger.error(f"Failed to update performance trends: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old performance data."""
        try:
            cutoff_time = time.time() - (self.retention_hours * 3600)
            
            # Clean server snapshots
            for server_id in list(self.server_snapshots.keys()):
                snapshots = self.server_snapshots[server_id]
                while snapshots and snapshots[0].timestamp < cutoff_time:
                    snapshots.popleft()
                
                if not snapshots:
                    del self.server_snapshots[server_id]
            
            # Clean metrics
            while (self.load_balancing_metrics and 
                   self.load_balancing_metrics[0].timestamp < cutoff_time):
                self.load_balancing_metrics.popleft()
            
            while (self.failover_metrics and 
                   self.failover_metrics[0].timestamp < cutoff_time):
                self.failover_metrics.popleft()
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get comprehensive dashboard summary."""
        try:
            return {
                'real_time_stats': self.real_time_stats,
                'active_alerts': self.active_alerts,
                'alert_summary': self._get_alert_summary(),
                'performance_trends': self.performance_trends,
                'server_count': len(self.server_snapshots),
                'last_update': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get dashboard summary: {e}")
            return {}
    
    def _get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        try:
            if not self.active_alerts:
                return {
                    'total': 0,
                    'critical': 0,
                    'warning': 0,
                    'by_category': {}
                }
            
            summary = {
                'total': len(self.active_alerts),
                'critical': len([a for a in self.active_alerts if a['type'] == 'critical']),
                'warning': len([a for a in self.active_alerts if a['type'] == 'warning']),
                'by_category': defaultdict(int)
            }
            
            for alert in self.active_alerts:
                summary['by_category'][alert['category']] += 1
            
            return dict(summary)
            
        except Exception as e:
            self.logger.error(f"Failed to get alert summary: {e}")
            return {}
    
    def get_server_performance_history(self, server_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get performance history for a specific server."""
        try:
            snapshots = self.server_snapshots.get(server_id, deque())
            
            if not snapshots:
                return []
            
            cutoff_time = time.time() - (hours * 3600)
            filtered_snapshots = [s for s in snapshots if s.timestamp >= cutoff_time]
            
            return [s.to_dict() for s in filtered_snapshots]
            
        except Exception as e:
            self.logger.error(f"Failed to get server performance history: {e}")
            return []
    
    def get_load_balancing_performance(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get load balancing performance metrics."""
        try:
            if not self.load_balancing_metrics:
                return []
            
            cutoff_time = time.time() - (hours * 3600)
            filtered_metrics = [m for m in self.load_balancing_metrics if m.timestamp >= cutoff_time]
            
            return [m.to_dict() for m in filtered_metrics]
            
        except Exception as e:
            self.logger.error(f"Failed to get load balancing performance: {e}")
            return []
    
    def get_failover_performance(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get failover performance metrics."""
        try:
            if not self.failover_metrics:
                return []
            
            cutoff_time = time.time() - (hours * 3600)
            filtered_metrics = [m for m in self.failover_metrics if m.timestamp >= cutoff_time]
            
            return [m.to_dict() for m in filtered_metrics]
            
        except Exception as e:
            self.logger.error(f"Failed to get failover performance: {e}")
            return []
    
    def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            # Server performance summary
            server_summary = {}
            for server_id, snapshots in self.server_snapshots.items():
                recent_snapshots = [s for s in snapshots if s.timestamp >= cutoff_time]
                
                if recent_snapshots:
                    response_times = [s.response_time for s in recent_snapshots if s.response_time > 0]
                    bandwidths = [s.bandwidth_mbps for s in recent_snapshots if s.bandwidth_mbps > 0]
                    cpu_usages = [s.cpu_usage for s in recent_snapshots]
                    
                    server_summary[server_id] = {
                        'avg_response_time': statistics.mean(response_times) if response_times else 0,
                        'avg_bandwidth': statistics.mean(bandwidths) if bandwidths else 0,
                        'avg_cpu_usage': statistics.mean(cpu_usages) if cpu_usages else 0,
                        'max_response_time': max(response_times) if response_times else 0,
                        'min_bandwidth': min(bandwidths) if bandwidths else 0,
                        'uptime_percentage': len([s for s in recent_snapshots if s.health_status == 'HEALTHY']) / len(recent_snapshots) * 100
                    }
            
            # Load balancing summary
            lb_metrics = [m for m in self.load_balancing_metrics if m.timestamp >= cutoff_time]
            if lb_metrics:
                lb_summary = {
                    'total_selections': sum(m.total_selections for m in lb_metrics),
                    'success_rate': sum(m.successful_selections for m in lb_metrics) / max(1, sum(m.total_selections for m in lb_metrics)),
                    'avg_effectiveness': statistics.mean([m.algorithm_effectiveness for m in lb_metrics]),
                    'algorithm_distribution': defaultdict(int)
                }
                
                for metric in lb_metrics:
                    lb_summary['algorithm_distribution'][metric.algorithm] += 1
            else:
                lb_summary = {}
            
            # Failover summary
            failover_metrics = [m for m in self.failover_metrics if m.timestamp >= cutoff_time]
            if failover_metrics:
                failover_summary = {
                    'total_failovers': sum(m.total_failovers for m in failover_metrics),
                    'successful_failovers': sum(m.successful_failovers for m in failover_metrics),
                    'failed_failovers': sum(m.failed_failovers for m in failover_metrics),
                    'avg_failover_time': statistics.mean([m.average_failover_time for m in failover_metrics if m.average_failover_time > 0]),
                    'recovery_rate': statistics.mean([m.recovery_rate for m in failover_metrics])
                }
            else:
                failover_summary = {}
            
            # Alert summary
            recent_alerts = [a for a in self.alert_history if a['timestamp'] >= cutoff_time]
            alert_summary = {
                'total_alerts': len(recent_alerts),
                'critical_alerts': len([a for a in recent_alerts if a['type'] == 'critical']),
                'warning_alerts': len([a for a in recent_alerts if a['type'] == 'warning']),
                'alerts_by_category': defaultdict(int)
            }
            
            for alert in recent_alerts:
                alert_summary['alerts_by_category'][alert['category']] += 1
            
            return {
                'report_period_hours': hours,
                'generated_at': time.time(),
                'server_summary': server_summary,
                'load_balancing_summary': lb_summary,
                'failover_summary': failover_summary,
                'alert_summary': dict(alert_summary),
                'system_health_score': self.real_time_stats['system_health_score']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate performance report: {e}")
            return {}
    
    def export_dashboard_data(self, filepath: str, hours: int = 24):
        """Export dashboard data to JSON file."""
        try:
            data = {
                'export_time': time.time(),
                'period_hours': hours,
                'dashboard_summary': self.get_dashboard_summary(),
                'performance_report': self.get_performance_report(hours),
                'server_performance': {
                    server_id: self.get_server_performance_history(server_id, hours)
                    for server_id in self.server_snapshots.keys()
                },
                'load_balancing_performance': self.get_load_balancing_performance(hours),
                'failover_performance': self.get_failover_performance(hours),
                'alerts': [a for a in self.alert_history if a['timestamp'] >= (time.time() - hours * 3600)]
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.logger.info(f"Dashboard data exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to export dashboard data: {e}")
