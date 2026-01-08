"""
Bandwidth Monitoring System for VPN Global Infrastructure.
This module provides comprehensive bandwidth tracking, usage analysis,
and capacity management for VPN infrastructure.
"""
import os
import sys
import time
import json
import asyncio
import threading
import subprocess
import psutil
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from discovery import VPNServer, ServerStatus
from utils.logger import LoggableMixin
from utils.config_loader import Config


class BandwidthUnit(Enum):
    """Bandwidth measurement units."""
    BPS = auto()
    KBPS = auto()
    MBPS = auto()
    GBPS = auto()


class MonitoringType(Enum):
    """Types of bandwidth monitoring."""
    REAL_TIME = auto()
    PERIODIC = auto()
    ON_DEMAND = auto()
    HISTORICAL = auto()


class AlertType(Enum):
    """Bandwidth alert types."""
    THRESHOLD_EXCEEDED = auto()
    ANOMALY_DETECTED = auto()
    CAPACITY_LIMIT = auto()
    QUALITY_DEGRADED = auto()
    USAGE_SPIKE = auto()


@dataclass
class BandwidthMeasurement:
    """Single bandwidth measurement."""
    timestamp: float
    server_id: str
    interface: str
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    errors_in: int
    errors_out: int
    dropped_in: int
    dropped_out: int
    utilization: float  # 0.0 to 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class BandwidthStats:
    """Bandwidth statistics for a time period."""
    server_id: str
    start_time: float
    end_time: float
    total_bytes_in: int
    total_bytes_out: int
    total_packets_in: int
    total_packets_out: int
    peak_bps_in: float
    peak_bps_out: float
    average_bps_in: float
    average_bps_out: float
    utilization_percentage: float
    error_rate: float
    packet_loss_rate: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class BandwidthAlert:
    """Bandwidth monitoring alert."""
    alert_id: str
    server_id: str
    alert_type: AlertType
    severity: str  # low, medium, high, critical
    message: str
    threshold_value: float
    actual_value: float
    timestamp: float
    resolved: bool = False
    resolved_at: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class InterfaceConfig:
    """Network interface configuration."""
    interface_name: str
    server_id: str
    monitoring_enabled: bool
    sampling_interval: float  # seconds
    max_bandwidth_mbps: float
    alert_thresholds: Dict[str, float]
    retention_hours: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class BandwidthMonitor(LoggableMixin):
    """Comprehensive bandwidth monitoring system."""
    
    def __init__(self, config_path: str = "config/vpn_config.json"):
        self.config_path = config_path
        self.config = Config(config_path).to_dict()
        self.monitoring_config = self.config.get('bandwidth_monitoring', {})
        
        # Data storage
        self.measurements: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.stats: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.alerts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.interface_configs: Dict[str, InterfaceConfig] = {}
        
        # Monitoring state
        self.monitoring_active: Set[str] = set()
        self.monitoring_threads: Dict[str, threading.Thread] = {}
        self.running = False
        
        # Statistics
        self.global_stats = {
            'total_bytes_transferred': 0,
            'total_packets_transferred': 0,
            'peak_bandwidth_mbps': 0.0,
            'average_utilization': 0.0,
            'total_alerts': 0,
            'active_monitors': 0,
            'monitored_interfaces': 0
        }
        
        # Initialize monitoring system
        self._initialize()
    
    def _initialize(self):
        """Initialize the bandwidth monitoring system."""
        try:
            # Create directories
            os.makedirs('data/infrastructure/bandwidth', exist_ok=True)
            os.makedirs('data/infrastructure/bandwidth/measurements', exist_ok=True)
            os.makedirs('data/infrastructure/bandwidth/stats', exist_ok=True)
            os.makedirs('data/infrastructure/bandwidth/alerts', exist_ok=True)
            
            # Load existing configurations
            self._load_interface_configs()
            
            # Start background monitoring
            self._start_background_tasks()
            
            self.logger.info("Bandwidth monitoring system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize bandwidth monitoring: {e}")
            raise
    
    def _load_interface_configs(self):
        """Load interface monitoring configurations."""
        try:
            configs_file = 'data/infrastructure/bandwidth/interface_configs.json'
            if os.path.exists(configs_file):
                with open(configs_file, 'r') as f:
                    data = json.load(f)
                    for config_data in data.get('interfaces', []):
                        config = InterfaceConfig(
                            interface_name=config_data['interface_name'],
                            server_id=config_data['server_id'],
                            monitoring_enabled=config_data.get('monitoring_enabled', True),
                            sampling_interval=config_data.get('sampling_interval', 1.0),
                            max_bandwidth_mbps=config_data.get('max_bandwidth_mbps', 1000.0),
                            alert_thresholds=config_data.get('alert_thresholds', {}),
                            retention_hours=config_data.get('retention_hours', 24)
                        )
                        self.interface_configs[config.interface_name] = config
                
                self.logger.info(f"Loaded {len(self.interface_configs)} interface configurations")
                
        except Exception as e:
            self.logger.error(f"Failed to load interface configs: {e}")
    
    def add_interface_monitoring(self, interface_config: Dict[str, Any]) -> str:
        """Add interface monitoring configuration."""
        try:
            interface_name = interface_config.get('interface_name')
            if not interface_name:
                raise ValueError("Interface name is required")
            
            config = InterfaceConfig(
                interface_name=interface_name,
                server_id=interface_config.get('server_id', 'unknown'),
                monitoring_enabled=interface_config.get('monitoring_enabled', True),
                sampling_interval=interface_config.get('sampling_interval', 1.0),
                max_bandwidth_mbps=interface_config.get('max_bandwidth_mbps', 1000.0),
                alert_thresholds=interface_config.get('alert_thresholds', {
                    'utilization_high': 0.8,
                    'utilization_critical': 0.95,
                    'bandwidth_low': 10.0,  # Mbps
                    'error_rate_high': 0.01,
                    'packet_loss_high': 0.005
                }),
                retention_hours=interface_config.get('retention_hours', 24)
            )
            
            self.interface_configs[interface_name] = config
            self._save_interface_configs()
            
            # Start monitoring if enabled
            if config.monitoring_enabled:
                self._start_interface_monitoring(interface_name)
            
            self.logger.info(f"Added interface monitoring: {interface_name}")
            return interface_name
            
        except Exception as e:
            self.logger.error(f"Failed to add interface monitoring: {e}")
            raise
    
    def _start_interface_monitoring(self, interface_name: str):
        """Start monitoring for a specific interface."""
        try:
            if interface_name in self.monitoring_active:
                return
            
            config = self.interface_configs.get(interface_name)
            if not config or not config.monitoring_enabled:
                return
            
            self.monitoring_active.add(interface_name)
            
            # Start monitoring thread
            thread = threading.Thread(
                target=self._monitor_interface_worker,
                args=(interface_name, config),
                daemon=True
            )
            
            self.monitoring_threads[interface_name] = thread
            thread.start()
            
            self.logger.info(f"Started monitoring for interface: {interface_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to start interface monitoring: {e}")
    
    def _monitor_interface_worker(self, interface_name: str, config: InterfaceConfig):
        """Worker thread for monitoring a specific interface."""
        try:
            while self.running and interface_name in self.monitoring_active:
                measurement = self._collect_interface_measurement(interface_name)
                if measurement:
                    self.measurements[interface_name].append(measurement)
                    self._check_alerts(interface_name, measurement)
                
                time.sleep(config.sampling_interval)
                
        except Exception as e:
            self.logger.error(f"Interface monitoring worker error for {interface_name}: {e}")
    
    def _collect_interface_measurement(self, interface_name: str) -> Optional[BandwidthMeasurement]:
        """Collect bandwidth measurement for an interface."""
        try:
            # Get network interface statistics
            stats = psutil.net_io_counters(pernic=True)
            interface_stats = stats.get(interface_name)
            
            if not interface_stats:
                return None
            
            # Calculate rates since last measurement
            measurement = BandwidthMeasurement(
                timestamp=time.time(),
                server_id=self.interface_configs.get(interface_name, InterfaceConfig(interface_name, '', True)).server_id,
                interface=interface_name,
                bytes_in=interface_stats.bytes_recv,
                bytes_out=interface_stats.bytes_sent,
                packets_in=interface_stats.packets_recv,
                packets_out=interface_stats.packets_sent,
                errors_in=interface_stats.errin,
                errors_out=interface_stats.errout,
                dropped_in=interface_stats.dropin,
                dropped_out=interface_stats.dropout,
                utilization=0.0  # Will be calculated
            )
            
            # Calculate utilization
            config = self.interface_configs.get(interface_name)
            if config and config.max_bandwidth_mbps > 0:
                # Calculate utilization based on recent measurements
                recent_measurements = list(self.measurements[interface_name])[-10:]  # Last 10 measurements
                if len(recent_measurements) >= 2:
                    time_diff = measurement.timestamp - recent_measurements[-1].timestamp
                    if time_diff > 0:
                        bytes_diff = measurement.bytes_in - recent_measurements[-1].bytes_in
                        bps = (bytes_diff * 8) / time_diff  # Convert to bits per second
                        measurement.utilization = min(1.0, bps / (config.max_bandwidth_mbps * 1000000))
            
            return measurement
            
        except Exception as e:
            self.logger.error(f"Failed to collect interface measurement: {e}")
            return None
    
    def _check_alerts(self, interface_name: str, measurement: BandwidthMeasurement):
        """Check for bandwidth alerts."""
        try:
            config = self.interface_configs.get(interface_name)
            if not config:
                return
            
            thresholds = config.alert_thresholds
            
            # Check utilization alerts
            if measurement.utilization >= thresholds.get('utilization_critical', 0.95):
                self._create_alert(
                    interface_name,
                    AlertType.THRESHOLD_EXCEEDED,
                    'critical',
                    f"Critical utilization: {measurement.utilization:.1%}",
                    thresholds.get('utilization_critical'),
                    measurement.utilization
                )
            elif measurement.utilization >= thresholds.get('utilization_high', 0.8):
                self._create_alert(
                    interface_name,
                    AlertType.THRESHOLD_EXCEEDED,
                    'high',
                    f"High utilization: {measurement.utilization:.1%}",
                    thresholds.get('utilization_high'),
                    measurement.utilization
                )
            
            # Check bandwidth alerts
            current_bandwidth = self._calculate_current_bandwidth(interface_name)
            if current_bandwidth < thresholds.get('bandwidth_low', 10.0):
                self._create_alert(
                    interface_name,
                    AlertType.QUALITY_DEGRADED,
                    'medium',
                    f"Low bandwidth: {current_bandwidth:.1f} Mbps",
                    thresholds.get('bandwidth_low'),
                    current_bandwidth
                )
            
            # Check error rate alerts
            error_rate = self._calculate_error_rate(interface_name)
            if error_rate > thresholds.get('error_rate_high', 0.01):
                self._create_alert(
                    interface_name,
                    AlertType.QUALITY_DEGRADED,
                    'high',
                    f"High error rate: {error_rate:.3f}",
                    thresholds.get('error_rate_high'),
                    error_rate
                )
            
        except Exception as e:
            self.logger.error(f"Failed to check alerts for {interface_name}: {e}")
    
    def _calculate_current_bandwidth(self, interface_name: str) -> float:
        """Calculate current bandwidth in Mbps."""
        try:
            recent_measurements = list(self.measurements[interface_name])[-5:]  # Last 5 measurements
            if len(recent_measurements) < 2:
                return 0.0
            
            # Calculate average bandwidth over recent measurements
            total_bytes = sum(m.bytes_in for m in recent_measurements)
            time_span = recent_measurements[-1].timestamp - recent_measurements[0].timestamp
            
            if time_span > 0:
                avg_bps = (total_bytes * 8) / time_span
                return avg_bps / 1000000  # Convert to Mbps
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Failed to calculate current bandwidth: {e}")
            return 0.0
    
    def _calculate_error_rate(self, interface_name: str) -> float:
        """Calculate error rate for an interface."""
        try:
            recent_measurements = list(self.measurements[interface_name])[-100:]  # Last 100 measurements
            if not recent_measurements:
                return 0.0
            
            total_errors = sum(m.errors_in + m.errors_out for m in recent_measurements)
            total_packets = sum(m.packets_in + m.packets_out for m in recent_measurements)
            
            if total_packets > 0:
                return total_errors / total_packets
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Failed to calculate error rate: {e}")
            return 0.0
    
    def _create_alert(self, interface_name: str, alert_type: AlertType, 
                     severity: str, message: str, threshold: float, actual: float):
        """Create and store a bandwidth alert."""
        try:
            alert_id = f"alert_{int(time.time())}_{interface_name}"
            
            alert = BandwidthAlert(
                alert_id=alert_id,
                server_id=self.interface_configs.get(interface_name, InterfaceConfig(interface_name, '', True)).server_id,
                alert_type=alert_type,
                severity=severity,
                message=message,
                threshold_value=threshold,
                actual_value=actual,
                timestamp=time.time()
            )
            
            self.alerts[interface_name].append(alert)
            self.global_stats['total_alerts'] += 1
            
            self.logger.warning(f"Bandwidth alert [{severity}]: {message}")
            
        except Exception as e:
            self.logger.error(f"Failed to create alert: {e}")
    
    def get_interface_stats(self, interface_name: str, hours: int = 1) -> Optional[BandwidthStats]:
        """Get bandwidth statistics for an interface."""
        try:
            measurements = list(self.measurements[interface_name])
            
            if not measurements:
                return None
            
            # Filter by time period
            cutoff_time = time.time() - (hours * 3600)
            recent_measurements = [m for m in measurements if m.timestamp >= cutoff_time]
            
            if not recent_measurements:
                return None
            
            # Calculate statistics
            start_time = recent_measurements[0].timestamp
            end_time = recent_measurements[-1].timestamp
            
            total_bytes_in = sum(m.bytes_in for m in recent_measurements)
            total_bytes_out = sum(m.bytes_out for m in recent_measurements)
            total_packets_in = sum(m.packets_in for m in recent_measurements)
            total_packets_out = sum(m.packets_out for m in recent_measurements)
            
            # Calculate peak and average bandwidth
            if len(recent_measurements) >= 2:
                time_span = end_time - start_time
                if time_span > 0:
                    peak_bps_in = max(
                        (m.bytes_in - recent_measurements[i-1].bytes_in) * 8 / 
                        (m.timestamp - recent_measurements[i-1].timestamp)
                        for i in range(1, len(recent_measurements))
                    ) if time_span > 0 else 0
                    
                    peak_bps_out = max(
                        (m.bytes_out - recent_measurements[i-1].bytes_out) * 8 / 
                        (m.timestamp - recent_measurements[i-1].timestamp)
                        for i in range(1, len(recent_measurements))
                    ) if time_span > 0 else 0
                    
                    average_bps_in = (total_bytes_in * 8) / time_span
                    average_bps_out = (total_bytes_out * 8) / time_span
                else:
                    peak_bps_in = average_bps_in = 0.0
                    peak_bps_out = average_bps_out = 0.0
            else:
                peak_bps_in = average_bps_in = 0.0
                peak_bps_out = average_bps_out = 0.0
            
            # Calculate utilization
            config = self.interface_configs.get(interface_name)
            max_bandwidth = config.max_bandwidth_mbps if config else 1000.0
            
            total_bytes = total_bytes_in + total_bytes_out
            utilization = min(1.0, (total_bytes * 8) / (time_span * max_bandwidth * 1000000)) if time_span > 0 else 0.0
            
            # Calculate error and packet loss rates
            total_errors = sum(m.errors_in + m.errors_out for m in recent_measurements)
            total_dropped = sum(m.dropped_in + m.dropped_out for m in recent_measurements)
            total_packets = total_packets_in + total_packets_out
            
            error_rate = total_errors / total_packets if total_packets > 0 else 0.0
            packet_loss_rate = total_dropped / total_packets if total_packets > 0 else 0.0
            
            stats = BandwidthStats(
                server_id=config.server_id if config else 'unknown',
                start_time=start_time,
                end_time=end_time,
                total_bytes_in=total_bytes_in,
                total_bytes_out=total_bytes_out,
                total_packets_in=total_packets_in,
                total_packets_out=total_packets_out,
                peak_bps_in=peak_bps_in / 1000000,  # Convert to Mbps
                peak_bps_out=peak_bps_out / 1000000,
                average_bps_in=average_bps_in / 1000000,
                average_bps_out=average_bps_out / 1000000,
                utilization_percentage=utilization,
                error_rate=error_rate,
                packet_loss_rate=packet_loss_rate
            )
            
            # Store stats
            self.stats[interface_name].append(stats)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get interface stats: {e}")
            return None
    
    def get_global_bandwidth_stats(self, hours: int = 1) -> Dict[str, Any]:
        """Get global bandwidth statistics."""
        try:
            all_stats = []
            
            for interface_name in self.interface_configs.keys():
                stats = self.get_interface_stats(interface_name, hours)
                if stats:
                    all_stats.append(stats)
            
            if not all_stats:
                return {
                    'total_interfaces': len(self.interface_configs),
                    'monitoring_active': len(self.monitoring_active),
                    'time_period_hours': hours,
                    'timestamp': time.time()
                }
            
            # Calculate global statistics
            total_bytes_in = sum(s.total_bytes_in for s in all_stats)
            total_bytes_out = sum(s.total_bytes_out for s in all_stats)
            total_bandwidth_mbps = sum(s.average_bps_in + s.average_bps_out for s in all_stats) / len(all_stats)
            peak_bandwidth_mbps = max(s.peak_bps_in + s.peak_bps_out for s in all_stats)
            average_utilization = sum(s.utilization_percentage for s in all_stats) / len(all_stats)
            
            return {
                'total_interfaces': len(self.interface_configs),
                'monitoring_active': len(self.monitoring_active),
                'time_period_hours': hours,
                'total_bytes_in': total_bytes_in,
                'total_bytes_out': total_bytes_out,
                'total_bandwidth_mbps': total_bandwidth_mbps,
                'peak_bandwidth_mbps': peak_bandwidth_mbps,
                'average_utilization': average_utilization,
                'interface_breakdown': {
                    interface_name: {
                        'server_id': s.server_id,
                        'total_bytes_in': s.total_bytes_in,
                        'total_bytes_out': s.total_bytes_out,
                        'average_bps_in': s.average_bps_in / 1000000,
                        'average_bps_out': s.average_bps_out / 1000000,
                        'utilization': s.utilization_percentage
                    }
                    for interface_name, s in [(self.interface_configs.get(i, InterfaceConfig(i, '', True)).interface_name, s) 
                                           for i, s in zip(self.interface_configs.keys(), all_stats)]
                },
                'alerts': {
                    'total': self.global_stats['total_alerts'],
                    'active': len([a for alerts in self.alerts.values() for a in alerts if not a.resolved]),
                    'by_type': self._get_alert_breakdown()
                },
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get global bandwidth stats: {e}")
            return {}
    
    def _get_alert_breakdown(self) -> Dict[str, int]:
        """Get alert breakdown by type."""
        try:
            alert_counts = defaultdict(int)
            
            for alerts in self.alerts.values():
                for alert in alerts:
                    if not alert.resolved:
                        alert_counts[alert.alert_type.name] += 1
            
            return dict(alert_counts)
            
        except Exception as e:
            self.logger.error(f"Failed to get alert breakdown: {e}")
            return {}
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve a bandwidth alert."""
        try:
            for interface_name, alerts in self.alerts.items():
                for alert in alerts:
                    if alert.alert_id == alert_id:
                        alert.resolved = True
                        alert.resolved_at = time.time()
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to resolve alert {alert_id}: {e}")
            return False
    
    def stop_interface_monitoring(self, interface_name: str):
        """Stop monitoring for a specific interface."""
        try:
            if interface_name in self.monitoring_active:
                self.monitoring_active.remove(interface_name)
            
            # Stop thread
            thread = self.monitoring_threads.get(interface_name)
            if thread and thread.is_alive():
                thread.join(timeout=5)
            
            self.logger.info(f"Stopped monitoring for interface: {interface_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to stop interface monitoring: {e}")
    
    def _save_interface_configs(self):
        """Save interface configurations."""
        try:
            configs_data = {
                'interfaces': [config.to_dict() for config in self.interface_configs.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/bandwidth/interface_configs.json', 'w') as f:
                json.dump(configs_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save interface configs: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks."""
        if self.running:
            return
        
        self.running = True
        
        # Update global statistics
        self.global_stats['monitored_interfaces'] = len(self.interface_configs)
        
        self.logger.info("Background tasks started")
    
    def _start_background_tasks(self):
        """Start background tasks."""
        if self.running:
            return
        
        self.running = True
        
        # Update global statistics
        self.global_stats['monitored_interfaces'] = len(self.interface_configs)
        
        self.logger.info("Background tasks started")
    
    def stop(self):
        """Stop the bandwidth monitoring system."""
        try:
            self.running = False
            
            # Stop all interface monitoring
            for interface_name in list(self.monitoring_active):
                self.stop_interface_monitoring(interface_name)
            
            # Wait for threads to finish
            for thread in self.monitoring_threads.values():
                if thread and thread.is_alive():
                    thread.join(timeout=10)
            
            # Save final state
            self._save_interface_configs()
            
            self.logger.info("Bandwidth monitoring system stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop bandwidth monitoring: {e}")
