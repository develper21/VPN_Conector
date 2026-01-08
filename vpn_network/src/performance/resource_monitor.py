#!/usr/bin/env python3
"""
Resource Monitoring and Optimization for VPN
Advanced memory and CPU usage monitoring with intelligent resource management.
Includes process profiling, memory leak detection, and CPU optimization.
"""
import gc
import json
import logging
import os
import psutil
import resource
import threading
import time
import tracemalloc
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
import numpy as np
import signal

from utils.logger import setup_logger


@dataclass
class ResourceSnapshot:
    """Snapshot of system resource usage."""
    timestamp: float
    cpu_percent: float
    cpu_count: int
    memory_percent: float
    memory_available_mb: float
    memory_used_mb: float
    memory_total_mb: float
    swap_percent: float
    disk_usage_percent: float
    disk_read_mb_s: float
    disk_write_mb_s: float
    network_sent_mb_s: float
    network_recv_mb_s: float
    process_count: int
    thread_count: int
    open_files: int
    load_average: Tuple[float, float, float]


@dataclass
class ProcessResourceInfo:
    """Resource information for a specific process."""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    num_threads: int
    num_files: int
    status: str
    create_time: float
    parent_pid: int


@dataclass
class MemoryLeakDetection:
    """Memory leak detection result."""
    timestamp: float
    process_name: str
    pid: int
    memory_growth_rate: float  # MB per hour
    leak_detected: bool
    confidence: float  # 0-1
    memory_snapshots: List[Tuple[float, float]]  # (timestamp, memory_mb)


@dataclass
class CpuOptimization:
    """CPU optimization action."""
    timestamp: float
    action_type: str
    target_pid: Optional[int]
    description: str
    before_usage: float
    after_usage: float
    success: bool


class ResourceMonitor:
    """Advanced resource monitoring and optimization."""
    
    def __init__(self, config_path: str = "config/resource_monitor.json"):
        self.logger = setup_logger("resource_monitor", "INFO")
        self.config_path = Path(config_path)
        self.is_monitoring = False
        self.monitoring_thread = None
        
        # Resource tracking
        self.resource_history: deque = deque(maxlen=2000)
        self.process_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        self.memory_leak_detections: List[MemoryLeakDetection] = []
        self.cpu_optimizations: List[CpuOptimization] = []
        
        # Memory tracking
        self.tracemalloc_started = False
        self.memory_snapshots: deque = deque(maxlen=1000)
        
        # Configuration
        self.config = {
            'monitoring_interval': 2,  # seconds
            'deep_monitoring_interval': 30,  # seconds
            'enable_memory_leak_detection': True,
            'enable_cpu_optimization': True,
            'enable_process_monitoring': True,
            'memory_leak_threshold': 50.0,  # MB per hour
            'cpu_optimization_threshold': 80.0,  # percentage
            'max_process_memory': 500.0,  # MB
            'max_process_cpu': 90.0,  # percentage
            'enable_auto_kill': False,  # Auto-kill problematic processes
            'monitored_processes': ['python', 'openvpn', 'wireguard'],
            'excluded_processes': ['systemd', 'kernel', 'kthreadd'],
            'alert_thresholds': {
                'system_cpu': 85.0,
                'system_memory': 90.0,
                'process_memory': 200.0,
                'process_cpu': 80.0,
                'disk_usage': 95.0,
                'load_average': 10.0
            }
        }
        
        # Optimization callbacks
        self.optimization_callbacks: Dict[str, Callable] = {
            'high_cpu': self._handle_high_cpu,
            'high_memory': self._handle_high_memory,
            'memory_leak': self._handle_memory_leak,
            'disk_full': self._handle_disk_full
        }
        
        # Load configuration
        self.load_configuration()
        
        # Initialize tracking
        self.last_disk_io = None
        self.last_net_io = None
        self.last_time = time.time()
    
    def load_configuration(self) -> None:
        """Load resource monitoring configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                self.config.update(loaded_config)
                self.logger.info("Resource monitoring configuration loaded")
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
        """Start resource monitoring."""
        try:
            if self.is_monitoring:
                self.logger.warning("Resource monitoring is already active")
                return False
            
            # Start memory tracking
            if not tracemalloc.is_tracing():
                tracemalloc.start()
                self.tracemalloc_started = True
                self.logger.info("Memory tracing started")
            
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info("Resource monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start resource monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> bool:
        """Stop resource monitoring."""
        try:
            if not self.is_monitoring:
                self.logger.warning("Resource monitoring is not active")
                return False
            
            self.is_monitoring = False
            
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=10)
            
            # Stop memory tracking
            if tracemalloc.is_tracing():
                tracemalloc.stop()
                self.tracemalloc_started = False
                self.logger.info("Memory tracing stopped")
            
            self.logger.info("Resource monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop resource monitoring: {e}")
            return False
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        deep_monitoring_counter = 0
        
        while self.is_monitoring:
            try:
                # Collect basic resource snapshot
                snapshot = self._collect_resource_snapshot()
                if snapshot:
                    self.resource_history.append(snapshot)
                
                # Deep monitoring (process-level)
                deep_monitoring_counter += 1
                if deep_monitoring_counter >= self.config['deep_monitoring_interval'] // self.config['monitoring_interval']:
                    if self.config['enable_process_monitoring']:
                        self._monitor_processes()
                    
                    # Memory leak detection
                    if self.config['enable_memory_leak_detection']:
                        self._detect_memory_leaks()
                    
                    deep_monitoring_counter = 0
                
                # Check for optimization opportunities
                if self.config['enable_cpu_optimization']:
                    self._check_optimization_opportunities(snapshot)
                
                time.sleep(self.config['monitoring_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def _collect_resource_snapshot(self) -> Optional[ResourceSnapshot]:
        """Collect current system resource snapshot."""
        try:
            current_time = time.time()
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available_mb = memory.available / (1024**2)
            memory_used_mb = memory.used / (1024**2)
            memory_total_mb = memory.total / (1024**2)
            
            # Swap metrics
            swap = psutil.swap_memory()
            swap_percent = swap.percent
            
            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            disk_usage_percent = disk_usage.percent
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if self.last_disk_io and self.last_time:
                time_diff = current_time - self.last_time
                disk_read_mb_s = (disk_io.read_bytes - self.last_disk_io.read_bytes) / (1024**2) / time_diff
                disk_write_mb_s = (disk_io.write_bytes - self.last_disk_io.write_bytes) / (1024**2) / time_diff
            else:
                disk_read_mb_s = 0
                disk_write_mb_s = 0
            
            self.last_disk_io = disk_io
            
            # Network I/O
            net_io = psutil.net_io_counters()
            if self.last_net_io and self.last_time:
                time_diff = current_time - self.last_time
                network_sent_mb_s = (net_io.bytes_sent - self.last_net_io.bytes_sent) / (1024**2) / time_diff
                network_recv_mb_s = (net_io.bytes_recv - self.last_net_io.bytes_recv) / (1024**2) / time_diff
            else:
                network_sent_mb_s = 0
                network_recv_mb_s = 0
            
            self.last_net_io = net_io
            self.last_time = current_time
            
            # Process and thread counts
            process_count = len(psutil.pids())
            thread_count = threading.active_count()
            
            # Open files count
            try:
                open_files = len(psutil.Process().open_files())
            except:
                open_files = 0
            
            # Load average (Unix-like systems)
            try:
                load_average = os.getloadavg()
            except:
                load_average = (0.0, 0.0, 0.0)
            
            return ResourceSnapshot(
                timestamp=current_time,
                cpu_percent=cpu_percent,
                cpu_count=cpu_count,
                memory_percent=memory_percent,
                memory_available_mb=memory_available_mb,
                memory_used_mb=memory_used_mb,
                memory_total_mb=memory_total_mb,
                swap_percent=swap_percent,
                disk_usage_percent=disk_usage_percent,
                disk_read_mb_s=disk_read_mb_s,
                disk_write_mb_s=disk_write_mb_s,
                network_sent_mb_s=network_sent_mb_s,
                network_recv_mb_s=network_recv_mb_s,
                process_count=process_count,
                thread_count=thread_count,
                open_files=open_files,
                load_average=load_average
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect resource snapshot: {e}")
            return None
    
    def _monitor_processes(self) -> None:
        """Monitor individual processes."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                           'memory_info', 'num_threads', 'num_handles', 
                                           'status', 'create_time', 'ppid']):
                try:
                    proc_info = proc.info
                    
                    # Filter processes
                    if not self._should_monitor_process(proc_info):
                        continue
                    
                    # Create process resource info
                    process_info = ProcessResourceInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'],
                        cpu_percent=proc_info['cpu_percent'] or 0,
                        memory_percent=proc_info['memory_percent'] or 0,
                        memory_mb=(proc_info['memory_info'].rss / (1024**2)) if proc_info['memory_info'] else 0,
                        num_threads=proc_info['num_threads'] or 0,
                        num_files=proc_info['num_handles'] or 0,
                        status=proc_info['status'] or 'unknown',
                        create_time=proc_info['create_time'] or 0,
                        parent_pid=proc_info['ppid'] or 0
                    )
                    
                    # Store in history
                    self.process_history[process_info.pid].append(process_info)
                    
                    # Check for resource violations
                    self._check_process_violations(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process monitoring failed: {e}")
    
    def _should_monitor_process(self, proc_info: Dict) -> bool:
        """Check if a process should be monitored."""
        try:
            name = proc_info.get('name', '').lower()
            
            # Check if in monitored processes
            if self.config['monitored_processes']:
                if not any(monitor in name for monitor in self.config['monitored_processes']):
                    return False
            
            # Check if in excluded processes
            if self.config['excluded_processes']:
                if any(exclude in name for exclude in self.config['excluded_processes']):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _check_process_violations(self, process_info: ProcessResourceInfo) -> None:
        """Check if process violates resource limits."""
        try:
            thresholds = self.config['alert_thresholds']
            
            # Check memory usage
            if process_info.memory_mb > thresholds['process_memory']:
                self.logger.warning(f"Process {process_info.name} (PID: {process_info.pid}) "
                                 f"exceeds memory limit: {process_info.memory_mb:.1f}MB > {thresholds['process_memory']}MB")
                
                if self.config['enable_auto_kill'] and process_info.memory_mb > self.config['max_process_memory']:
                    self._terminate_process(process_info.pid, "Excessive memory usage")
            
            # Check CPU usage
            if process_info.cpu_percent > thresholds['process_cpu']:
                self.logger.warning(f"Process {process_info.name} (PID: {process_info.pid}) "
                                 f"exceeds CPU limit: {process_info.cpu_percent:.1f}% > {thresholds['process_cpu']}%")
                
                if self.config['enable_auto_kill'] and process_info.cpu_percent > self.config['max_process_cpu']:
                    self._terminate_process(process_info.pid, "Excessive CPU usage")
                    
        except Exception as e:
            self.logger.error(f"Process violation check failed: {e}")
    
    def _terminate_process(self, pid: int, reason: str) -> None:
        """Terminate a process."""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            # Try graceful termination first
            process.terminate()
            
            # Wait a bit and check if it's still running
            time.sleep(2)
            if process.is_running():
                # Force kill if still running
                process.kill()
            
            self.logger.info(f"Terminated process {process_name} (PID: {pid}) - Reason: {reason}")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Failed to terminate process {pid}: {e}")
    
    def _detect_memory_leaks(self) -> None:
        """Detect memory leaks in monitored processes."""
        try:
            current_time = time.time()
            
            for pid, history in self.process_history.items():
                if len(history) < 10:  # Need enough data points
                    continue
                
                # Get recent memory snapshots
                recent_snapshots = list(history)[-20:]  # Last 20 snapshots
                
                # Calculate memory growth rate
                timestamps = [s.create_time for s in recent_snapshots]
                memory_values = [s.memory_mb for s in recent_snapshots]
                
                if len(timestamps) < 2:
                    continue
                
                # Linear regression to find growth rate
                time_diff = timestamps[-1] - timestamps[0]
                if time_diff > 0:
                    memory_diff = memory_values[-1] - memory_values[0]
                    growth_rate = (memory_diff / time_diff) * 3600  # MB per hour
                    
                    # Check for leak
                    threshold = self.config['memory_leak_threshold']
                    if growth_rate > threshold:
                        process_name = recent_snapshots[-1].name
                        
                        # Calculate confidence based on consistency
                        if len(memory_values) > 5:
                            correlation = np.corrcoef(range(len(memory_values)), memory_values)[0, 1]
                            confidence = max(0, correlation) if not np.isnan(correlation) else 0
                        else:
                            confidence = 0.5
                        
                        leak_detection = MemoryLeakDetection(
                            timestamp=current_time,
                            process_name=process_name,
                            pid=pid,
                            memory_growth_rate=growth_rate,
                            leak_detected=True,
                            confidence=confidence,
                            memory_snapshots=list(zip(timestamps, memory_values))
                        )
                        
                        self.memory_leak_detections.append(leak_detection)
                        
                        # Trigger optimization callback
                        if 'memory_leak' in self.optimization_callbacks:
                            self.optimization_callbacks['memory_leak'](leak_detection)
                        
                        self.logger.warning(f"Memory leak detected in {process_name} (PID: {pid}): "
                                         f"{growth_rate:.2f}MB/hour, confidence: {confidence:.2f}")
                        
        except Exception as e:
            self.logger.error(f"Memory leak detection failed: {e}")
    
    def _check_optimization_opportunities(self, snapshot: ResourceSnapshot) -> None:
        """Check for optimization opportunities."""
        try:
            thresholds = self.config['alert_thresholds']
            
            # High CPU usage
            if snapshot.cpu_percent > thresholds['system_cpu']:
                if 'high_cpu' in self.optimization_callbacks:
                    self.optimization_callbacks['high_cpu'](snapshot)
            
            # High memory usage
            if snapshot.memory_percent > thresholds['system_memory']:
                if 'high_memory' in self.optimization_callbacks:
                    self.optimization_callbacks['high_memory'](snapshot)
            
            # High disk usage
            if snapshot.disk_usage_percent > thresholds['disk_usage']:
                if 'disk_full' in self.optimization_callbacks:
                    self.optimization_callbacks['disk_full'](snapshot)
                    
        except Exception as e:
            self.logger.error(f"Optimization opportunity check failed: {e}")
    
    def _handle_high_cpu(self, snapshot: ResourceSnapshot) -> None:
        """Handle high CPU usage."""
        try:
            # Find high CPU processes
            high_cpu_processes = []
            for pid, history in self.process_history.items():
                if history:
                    latest = history[-1]
                    if latest.cpu_percent > self.config['cpu_optimization_threshold']:
                        high_cpu_processes.append(latest)
            
            # Sort by CPU usage
            high_cpu_processes.sort(key=lambda x: x.cpu_percent, reverse=True)
            
            # Take action on top processes
            for process in high_cpu_processes[:3]:  # Top 3
                self._optimize_process_cpu(process)
                
        except Exception as e:
            self.logger.error(f"High CPU handling failed: {e}")
    
    def _handle_high_memory(self, snapshot: ResourceSnapshot) -> None:
        """Handle high memory usage."""
        try:
            # Force garbage collection
            before_memory = snapshot.memory_percent
            gc.collect()
            
            # Check if it helped
            time.sleep(1)
            new_snapshot = self._collect_resource_snapshot()
            if new_snapshot:
                after_memory = new_snapshot.memory_percent
                memory_freed = before_memory - after_memory
                
                if memory_freed > 1:  # At least 1% freed
                    self.logger.info(f"Garbage collection freed {memory_freed:.1f}% memory")
                
                # Record optimization
                optimization = CpuOptimization(
                    timestamp=time.time(),
                    action_type="garbage_collection",
                    target_pid=None,
                    description="Forced garbage collection to free memory",
                    before_usage=before_memory,
                    after_usage=after_memory,
                    success=memory_freed > 0
                )
                self.cpu_optimizations.append(optimization)
            
            # Kill high memory processes if auto-kill is enabled
            if self.config['enable_auto_kill']:
                for pid, history in self.process_history.items():
                    if history:
                        latest = history[-1]
                        if latest.memory_mb > self.config['max_process_memory']:
                            self._terminate_process(pid, "Excessive memory usage during high memory condition")
                            
        except Exception as e:
            self.logger.error(f"High memory handling failed: {e}")
    
    def _handle_memory_leak(self, leak_detection: MemoryLeakDetection) -> None:
        """Handle detected memory leak."""
        try:
            if leak_detection.confidence > 0.7:  # High confidence
                self.logger.critical(f"High confidence memory leak detected: {leak_detection.process_name} "
                                   f"(PID: {leak_detection.pid}) - {leak_detection.memory_growth_rate:.2f}MB/hour")
                
                # Option to restart the process
                if self.config['enable_auto_kill']:
                    self._terminate_process(leak_detection.pid, "Memory leak detected")
                    
        except Exception as e:
            self.logger.error(f"Memory leak handling failed: {e}")
    
    def _handle_disk_full(self, snapshot: ResourceSnapshot) -> None:
        """Handle full disk condition."""
        try:
            self.logger.critical(f"Disk usage critical: {snapshot.disk_usage_percent:.1f}%")
            
            # Clean up temporary files
            import tempfile
            temp_dir = tempfile.gettempdir()
            
            try:
                # Remove old temp files
                for filename in os.listdir(temp_dir):
                    filepath = os.path.join(temp_dir, filename)
                    try:
                        if os.path.isfile(filepath):
                            file_age = time.time() - os.path.getmtime(filepath)
                            if file_age > 86400:  # Older than 1 day
                                os.remove(filepath)
                                self.logger.info(f"Removed old temp file: {filename}")
                    except:
                        continue
                        
            except Exception as e:
                self.logger.error(f"Temp file cleanup failed: {e}")
                
        except Exception as e:
            self.logger.error(f"Disk full handling failed: {e}")
    
    def _optimize_process_cpu(self, process: ProcessResourceInfo) -> None:
        """Optimize CPU usage for a specific process."""
        try:
            before_usage = process.cpu_percent
            
            # Try to reduce process priority
            try:
                proc = psutil.Process(process.pid)
                current_nice = proc.nice()
                new_nice = min(19, current_nice + 5)  # Lower priority
                proc.nice(new_nice)
                
                # Check if it helped
                time.sleep(2)
                proc.cpu_percent()
                time.sleep(1)
                after_usage = proc.cpu_percent()
                
                optimization = CpuOptimization(
                    timestamp=time.time(),
                    action_type="priority_adjustment",
                    target_pid=process.pid,
                    description=f"Reduced priority of {process.name} from {current_nice} to {new_nice}",
                    before_usage=before_usage,
                    after_usage=after_usage,
                    success=after_usage < before_usage
                )
                self.cpu_optimizations.append(optimization)
                
                self.logger.info(f"Reduced priority of {process.name} (PID: {process.pid}) "
                               f"from {current_nice} to {new_nice}")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.logger.warning(f"Cannot adjust priority for process {process.pid}")
                
        except Exception as e:
            self.logger.error(f"Process CPU optimization failed: {e}")
    
    def get_resource_summary(self, hours: int = 1) -> Dict:
        """Get resource usage summary for the specified time period."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            # Filter recent snapshots
            recent_snapshots = [s for s in self.resource_history if s.timestamp > cutoff_time]
            
            if not recent_snapshots:
                return {}
            
            # Calculate statistics
            cpu_values = [s.cpu_percent for s in recent_snapshots]
            memory_values = [s.memory_percent for s in recent_snapshots]
            
            summary = {
                'period_hours': hours,
                'snapshots_count': len(recent_snapshots),
                'cpu': {
                    'average': np.mean(cpu_values),
                    'maximum': np.max(cpu_values),
                    'minimum': np.min(cpu_values),
                    'current': cpu_values[-1] if cpu_values else 0
                },
                'memory': {
                    'average': np.mean(memory_values),
                    'maximum': np.max(memory_values),
                    'minimum': np.min(memory_values),
                    'current': memory_values[-1] if memory_values else 0
                },
                'processes': {
                    'monitored_count': len(self.process_history),
                    'memory_leaks_detected': len(self.memory_leak_detections),
                    'optimizations_applied': len(self.cpu_optimizations)
                }
            }
            
            # Add current snapshot details
            if recent_snapshots:
                latest = recent_snapshots[-1]
                summary['current_snapshot'] = asdict(latest)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate resource summary: {e}")
            return {}
    
    def get_top_processes(self, metric: str = 'memory', limit: int = 10) -> List[Dict]:
        """Get top processes by specified metric."""
        try:
            processes = []
            
            for pid, history in self.process_history.items():
                if history:
                    latest = history[-1]
                    processes.append({
                        'pid': pid,
                        'name': latest.name,
                        'cpu_percent': latest.cpu_percent,
                        'memory_mb': latest.memory_mb,
                        'memory_percent': latest.memory_percent,
                        'num_threads': latest.num_threads,
                        'status': latest.status
                    })
            
            # Sort by metric
            if metric == 'memory':
                processes.sort(key=lambda x: x['memory_mb'], reverse=True)
            elif metric == 'cpu':
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            return processes[:limit]
            
        except Exception as e:
            self.logger.error(f"Failed to get top processes: {e}")
            return []
    
    def export_resource_report(self, filepath: str) -> bool:
        """Export comprehensive resource report."""
        try:
            report_data = {
                'export_timestamp': time.time(),
                'monitoring_active': self.is_monitoring,
                'config': self.config,
                'resource_summary': self.get_resource_summary(hours=24),
                'top_processes': {
                    'by_memory': self.get_top_processes('memory', 10),
                    'by_cpu': self.get_top_processes('cpu', 10)
                },
                'memory_leak_detections': [asdict(d) for d in self.memory_leak_detections],
                'cpu_optimizations': [asdict(o) for o in self.cpu_optimizations],
                'total_snapshots': len(self.resource_history),
                'monitored_processes': len(self.process_history)
            }
            
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Resource report exported to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export resource report: {e}")
            return False
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status."""
        try:
            return {
                'monitoring_active': self.is_monitoring,
                'tracemalloc_active': self.tracemalloc_started,
                'snapshots_collected': len(self.resource_history),
                'processes_monitored': len(self.process_history),
                'memory_leaks_detected': len(self.memory_leak_detections),
                'optimizations_applied': len(self.cpu_optimizations),
                'config': self.config
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get monitoring status: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    # Create resource monitor
    monitor = ResourceMonitor()
    
    # Start monitoring
    monitor.start_monitoring()
    
    # Let it run for a while
    time.sleep(60)
    
    # Get resource summary
    summary = monitor.get_resource_summary(hours=1)
    print(f"Resource summary: {summary}")
    
    # Get top processes
    top_memory = monitor.get_top_processes('memory', 5)
    print(f"Top memory processes: {top_memory}")
    
    # Export report
    monitor.export_resource_report('resource_report.json')
    
    # Get status
    status = monitor.get_monitoring_status()
    print(f"Monitoring status: {status}")
    
    # Stop monitoring
    monitor.stop_monitoring()
