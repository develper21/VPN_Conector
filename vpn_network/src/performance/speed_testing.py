#!/usr/bin/env python3
"""
Speed Testing Integration for VPN
Real-time performance monitoring and speed testing capabilities.
Measures latency, bandwidth, packet loss, and connection quality.
"""
import asyncio
import json
import logging
import socket
import statistics
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import ping3
import psutil
import speedtest

from utils.logger import setup_logger


@dataclass
class SpeedTestResult:
    """Represents a speed test result."""
    timestamp: float
    download_speed: float  # Mbps
    upload_speed: float    # Mbps
    ping: float           # ms
    jitter: float         # ms
    packet_loss: float    # percentage
    server_latency: float # ms
    connection_quality: str  # excellent, good, fair, poor


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics."""
    cpu_usage: float
    memory_usage: float
    network_io: Dict[str, float]
    disk_io: Dict[str, float]
    active_connections: int
    vpn_throughput: float
    latency: float
    packet_loss: float


class SpeedTestManager:
    """Manages speed testing and performance monitoring."""
    
    def __init__(self, config_path: str = "config/speed_testing.json"):
        self.logger = setup_logger("speed_testing", "INFO")
        self.config_path = Path(config_path)
        self.is_monitoring = False
        self.monitoring_thread = None
        self.speed_test_results: List[SpeedTestResult] = []
        self.performance_history: List[PerformanceMetrics] = []
        self.max_history_size = 1000
        
        # Configuration
        self.config = {
            'auto_test_interval': 300,  # 5 minutes
            'monitoring_interval': 5,   # 5 seconds
            'enable_continuous_monitoring': True,
            'test_servers': ['auto'],   # speedtest.net servers
            'ping_targets': ['8.8.8.8', '1.1.1.1', '208.67.222.222'],
            'bandwidth_test_duration': 10,  # seconds
            'enable_detailed_logging': True,
            'alert_thresholds': {
                'min_download_speed': 5.0,    # Mbps
                'max_latency': 200.0,         # ms
                'max_packet_loss': 5.0,       # percentage
                'max_cpu_usage': 80.0,        # percentage
                'max_memory_usage': 85.0       # percentage
            }
        }
        
        # Load configuration
        self.load_configuration()
        
        # Performance monitoring state
        self.last_network_stats = None
        self.last_disk_stats = None
        
        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    def load_configuration(self) -> None:
        """Load speed testing configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                self.config.update(loaded_config)
                self.logger.info("Speed testing configuration loaded")
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
    
    def start_monitoring(self) -> bool:
        """Start continuous performance monitoring."""
        try:
            if self.is_monitoring:
                self.logger.warning("Monitoring is already active")
                return False
            
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            # Start auto speed testing if enabled
            if self.config['enable_continuous_monitoring']:
                threading.Thread(target=self._auto_speed_test_loop, daemon=True).start()
            
            self.logger.info("Performance monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop performance monitoring."""
        try:
            if not self.is_monitoring:
                self.logger.warning("Monitoring is not active")
                return False
            
            self.is_monitoring = False
            
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=10)
            
            self.logger.info("Performance monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
            return False
    
    def run_speed_test(self, server_id: Optional[str] = None) -> Optional[SpeedTestResult]:
        """Run a comprehensive speed test."""
        try:
            self.logger.info("Starting speed test...")
            
            # Initialize speedtest client
            st = speedtest.Speedtest()
            
            # Get best server
            if server_id and server_id != 'auto':
                st.get_servers([server_id])
            else:
                st.get_best_server()
            
            # Test download speed
            start_time = time.time()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            
            # Test upload speed
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            
            # Get ping and jitter
            results = st.results.dict()
            ping = results['ping']
            
            # Calculate jitter
            jitter = self._calculate_jitter(st.results.ping)
            
            # Test packet loss
            packet_loss = self._measure_packet_loss()
            
            # Test server latency
            server_latency = self._measure_server_latency()
            
            # Determine connection quality
            connection_quality = self._determine_connection_quality(
                download_speed, upload_speed, ping, packet_loss
            )
            
            # Create result
            test_result = SpeedTestResult(
                timestamp=time.time(),
                download_speed=download_speed,
                upload_speed=upload_speed,
                ping=ping,
                jitter=jitter,
                packet_loss=packet_loss,
                server_latency=server_latency,
                connection_quality=connection_quality
            )
            
            # Store result
            self.speed_test_results.append(test_result)
            if len(self.speed_test_results) > self.max_history_size:
                self.speed_test_results.pop(0)
            
            # Check alerts
            self._check_performance_alerts(test_result)
            
            self.logger.info(f"Speed test completed - Download: {download_speed:.2f} Mbps, "
                           f"Upload: {upload_speed:.2f} Mbps, Ping: {ping:.2f} ms")
            
            return test_result
            
        except Exception as e:
            self.logger.error(f"Speed test failed: {e}")
            return None
    
    def _calculate_jitter(self, ping_samples: List[float]) -> float:
        """Calculate jitter from ping samples."""
        try:
            if len(ping_samples) < 2:
                return 0.0
            
            # Calculate differences between consecutive pings
            differences = []
            for i in range(1, len(ping_samples)):
                differences.append(abs(ping_samples[i] - ping_samples[i-1]))
            
            # Jitter is the standard deviation of ping differences
            return statistics.stdev(differences) if differences else 0.0
            
        except Exception:
            return 0.0
    
    def _measure_packet_loss(self, target: str = "8.8.8.8", count: int = 10) -> float:
        """Measure packet loss to a target."""
        try:
            lost = 0
            for _ in range(count):
                response_time = ping3.ping(target, timeout=2)
                if response_time is None:
                    lost += 1
                time.sleep(0.1)
            
            return (lost / count) * 100
            
        except Exception:
            return 0.0
    
    def _measure_server_latency(self, target: str = "8.8.8.8") -> float:
        """Measure server latency."""
        try:
            latencies = []
            for _ in range(5):
                response_time = ping3.ping(target, timeout=2)
                if response_time is not None:
                    latencies.append(response_time * 1000)  # Convert to ms
                time.sleep(0.1)
            
            return statistics.mean(latencies) if latencies else 0.0
            
        except Exception:
            return 0.0
    
    def _determine_connection_quality(self, download: float, upload: float, 
                                    ping: float, packet_loss: float) -> str:
        """Determine overall connection quality."""
        try:
            score = 0
            
            # Download speed scoring
            if download >= 50:
                score += 25
            elif download >= 25:
                score += 20
            elif download >= 10:
                score += 15
            elif download >= 5:
                score += 10
            else:
                score += 5
            
            # Upload speed scoring
            if upload >= 25:
                score += 25
            elif upload >= 10:
                score += 20
            elif upload >= 5:
                score += 15
            elif upload >= 2:
                score += 10
            else:
                score += 5
            
            # Latency scoring
            if ping <= 50:
                score += 25
            elif ping <= 100:
                score += 20
            elif ping <= 150:
                score += 15
            elif ping <= 200:
                score += 10
            else:
                score += 5
            
            # Packet loss scoring
            if packet_loss <= 1:
                score += 25
            elif packet_loss <= 3:
                score += 20
            elif packet_loss <= 5:
                score += 15
            elif packet_loss <= 10:
                score += 10
            else:
                score += 5
            
            # Determine quality based on score
            if score >= 90:
                return "excellent"
            elif score >= 75:
                return "good"
            elif score >= 60:
                return "fair"
            else:
                return "poor"
                
        except Exception:
            return "unknown"
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop for performance metrics."""
        while self.is_monitoring:
            try:
                metrics = self._collect_performance_metrics()
                if metrics:
                    self.performance_history.append(metrics)
                    if len(self.performance_history) > self.max_history_size:
                        self.performance_history.pop(0)
                    
                    # Check for performance alerts
                    self._check_resource_alerts(metrics)
                
                time.sleep(self.config['monitoring_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
    
    def _auto_speed_test_loop(self) -> None:
        """Automatic speed testing loop."""
        while self.is_monitoring:
            try:
                time.sleep(self.config['auto_test_interval'])
                
                if self.is_monitoring:  # Double check after sleep
                    self.executor.submit(self.run_speed_test)
                
            except Exception as e:
                self.logger.error(f"Error in auto speed test loop: {e}")
    
    def _collect_performance_metrics(self) -> Optional[PerformanceMetrics]:
        """Collect current performance metrics."""
        try:
            # CPU and memory usage
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            
            # Network I/O
            net_io = psutil.net_io_counters()
            current_network_stats = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
            
            network_io = {}
            if self.last_network_stats:
                network_io = {
                    'upload_speed': (current_network_stats['bytes_sent'] - 
                                    self.last_network_stats['bytes_sent']) / self.config['monitoring_interval'],
                    'download_speed': (current_network_stats['bytes_recv'] - 
                                     self.last_network_stats['bytes_recv']) / self.config['monitoring_interval'],
                    'upload_pps': (current_network_stats['packets_sent'] - 
                                  self.last_network_stats['packets_sent']) / self.config['monitoring_interval'],
                    'download_pps': (current_network_stats['packets_recv'] - 
                                   self.last_network_stats['packets_recv']) / self.config['monitoring_interval']
                }
            
            self.last_network_stats = current_network_stats
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            current_disk_stats = {
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count
            }
            
            disk_io_metrics = {}
            if self.last_disk_stats:
                disk_io_metrics = {
                    'read_speed': (current_disk_stats['read_bytes'] - 
                                 self.last_disk_stats['read_bytes']) / self.config['monitoring_interval'],
                    'write_speed': (current_disk_stats['write_bytes'] - 
                                  self.last_disk_stats['write_bytes']) / self.config['monitoring_interval']
                }
            
            self.last_disk_stats = current_disk_stats
            
            # Active connections
            active_connections = len(psutil.net_connections())
            
            # VPN throughput (simplified - would need VPN-specific monitoring)
            vpn_throughput = network_io.get('download_speed', 0) + network_io.get('upload_speed', 0)
            
            # Latency and packet loss
            latency = self._measure_server_latency()
            packet_loss = self._measure_packet_loss()
            
            return PerformanceMetrics(
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                network_io=network_io,
                disk_io=disk_io_metrics,
                active_connections=active_connections,
                vpn_throughput=vpn_throughput,
                latency=latency,
                packet_loss=packet_loss
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance metrics: {e}")
            return None
    
    def _check_performance_alerts(self, result: SpeedTestResult) -> None:
        """Check for performance alerts based on speed test results."""
        try:
            alerts = []
            thresholds = self.config['alert_thresholds']
            
            if result.download_speed < thresholds['min_download_speed']:
                alerts.append(f"Low download speed: {result.download_speed:.2f} Mbps")
            
            if result.ping > thresholds['max_latency']:
                alerts.append(f"High latency: {result.ping:.2f} ms")
            
            if result.packet_loss > thresholds['max_packet_loss']:
                alerts.append(f"High packet loss: {result.packet_loss:.2f}%")
            
            if alerts:
                self.logger.warning(f"Performance alerts: {'; '.join(alerts)}")
                
        except Exception as e:
            self.logger.error(f"Error checking performance alerts: {e}")
    
    def _check_resource_alerts(self, metrics: PerformanceMetrics) -> None:
        """Check for resource usage alerts."""
        try:
            alerts = []
            thresholds = self.config['alert_thresholds']
            
            if metrics.cpu_usage > thresholds['max_cpu_usage']:
                alerts.append(f"High CPU usage: {metrics.cpu_usage:.1f}%")
            
            if metrics.memory_usage > thresholds['max_memory_usage']:
                alerts.append(f"High memory usage: {metrics.memory_usage:.1f}%")
            
            if alerts:
                self.logger.warning(f"Resource alerts: {'; '.join(alerts)}")
                
        except Exception as e:
            self.logger.error(f"Error checking resource alerts: {e}")
    
    def get_performance_summary(self, hours: int = 24) -> Dict:
        """Get performance summary for the specified time period."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            # Filter recent speed test results
            recent_tests = [r for r in self.speed_test_results if r.timestamp > cutoff_time]
            
            # Filter recent performance metrics
            recent_metrics = [m for m in self.performance_history if 
                            hasattr(m, 'timestamp') and m.timestamp > cutoff_time]
            
            summary = {
                'period_hours': hours,
                'speed_tests': {
                    'count': len(recent_tests),
                    'avg_download': statistics.mean([r.download_speed for r in recent_tests]) if recent_tests else 0,
                    'avg_upload': statistics.mean([r.upload_speed for r in recent_tests]) if recent_tests else 0,
                    'avg_ping': statistics.mean([r.ping for r in recent_tests]) if recent_tests else 0,
                    'avg_packet_loss': statistics.mean([r.packet_loss for r in recent_tests]) if recent_tests else 0,
                    'quality_distribution': self._get_quality_distribution(recent_tests)
                },
                'performance_metrics': {
                    'avg_cpu_usage': statistics.mean([m.cpu_usage for m in recent_metrics]) if recent_metrics else 0,
                    'avg_memory_usage': statistics.mean([m.memory_usage for m in recent_metrics]) if recent_metrics else 0,
                    'max_connections': max([m.active_connections for m in recent_metrics]) if recent_metrics else 0,
                    'avg_throughput': statistics.mean([m.vpn_throughput for m in recent_metrics]) if recent_metrics else 0
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate performance summary: {e}")
            return {}
    
    def _get_quality_distribution(self, tests: List[SpeedTestResult]) -> Dict[str, int]:
        """Get distribution of connection quality ratings."""
        distribution = {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0}
        for test in tests:
            if test.connection_quality in distribution:
                distribution[test.connection_quality] += 1
        return distribution
    
    def export_data(self, filepath: str, format: str = 'json') -> bool:
        """Export performance data to file."""
        try:
            data = {
                'speed_test_results': [asdict(r) for r in self.speed_test_results],
                'performance_metrics': [asdict(m) for m in self.performance_history],
                'config': self.config,
                'export_timestamp': time.time()
            }
            
            if format.lower() == 'json':
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                self.logger.error(f"Unsupported export format: {format}")
                return False
            
            self.logger.info(f"Data exported to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export data: {e}")
            return False
    
    def get_real_time_status(self) -> Dict:
        """Get current real-time status."""
        try:
            latest_metrics = self.performance_history[-1] if self.performance_history else None
            latest_test = self.speed_test_results[-1] if self.speed_test_results else None
            
            return {
                'monitoring_active': self.is_monitoring,
                'latest_metrics': asdict(latest_metrics) if latest_metrics else None,
                'latest_speed_test': asdict(latest_test) if latest_test else None,
                'total_speed_tests': len(self.speed_test_results),
                'total_metrics_samples': len(self.performance_history),
                'config': self.config
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get real-time status: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    # Create speed test manager
    speed_manager = SpeedTestManager()
    
    # Start monitoring
    speed_manager.start_monitoring()
    
    # Run a speed test
    result = speed_manager.run_speed_test()
    if result:
        print(f"Speed test result: {result}")
    
    # Get performance summary
    summary = speed_manager.get_performance_summary(hours=1)
    print(f"Performance summary: {summary}")
    
    # Get real-time status
    status = speed_manager.get_real_time_status()
    print(f"Real-time status: {status}")
    
    # Stop monitoring
    time.sleep(10)
    speed_manager.stop_monitoring()
