"""
Dynamic Configuration Manager for VPN Infrastructure.
This module provides real-time configuration updates, regional settings,
and dynamic optimization for global VPN infrastructure.
"""
import os
import sys
import time
import json
import asyncio
import threading
import watchdog.observers
from typing import Dict, Any, Optional, List, Callable, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import LoggableMixin


class ConfigChangeType(Enum):
    """Types of configuration changes."""
    SERVER_ADDED = auto()
    SERVER_REMOVED = auto()
    SERVER_UPDATED = auto()
    ROUTING_RULE_ADDED = auto()
    ROUTING_RULE_UPDATED = auto()
    ROUTING_RULE_REMOVED = auto()
    BANDWIDTH_CONFIG_UPDATED = auto()
    ALERT_CONFIG_UPDATED = auto()
    REGION_CONFIG_UPDATED = auto()
    PROTOCOL_CONFIG_UPDATED = auto()


@dataclass
class ConfigChange:
    """Configuration change record."""
    change_id: str
    change_type: ConfigChangeType
    timestamp: float
    server_id: Optional[str]
    config_key: str
    old_value: Any
    new_value: Any
    applied: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'change_id': self.change_id,
            'change_type': self.change_type.name,
            'timestamp': self.timestamp,
            'server_id': self.server_id,
            'config_key': self.config_key,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'applied': self.applied,
            'error_message': self.error_message
        }


@dataclass
class RegionalConfig:
    """Regional configuration settings."""
    region: str
    protocol_settings: Dict[str, Any]
    routing_preferences: Dict[str, Any]
    bandwidth_limits: Dict[str, float]
    performance_thresholds: Dict[str, float]
    optimization_settings: Dict[str, Any]
    created_at: float
    updated_at: float
    version: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'region': self.region,
            'protocol_settings': self.protocol_settings,
            'routing_preferences': self.routing_preferences,
            'bandwidth_limits': self.bandwidth_limits,
            'performance_thresholds': self.performance_thresholds,
            'optimization_settings': self.optimization_settings,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'version': self.version
        }


@dataclass
class DynamicConfig:
    """Dynamic configuration for real-time updates."""
    config_id: str
    config_type: str
    target_id: str  # server_id or region_id
    value: Any
    timestamp: float
    ttl: float  # Time to live
    applied: bool
    rollback_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'config_id': self.config_id,
            'config_type': self.config_type,
            'target_id': self.target_id,
            'value': self.value,
            'timestamp': self.timestamp,
            'ttl': self.ttl,
            'applied': self.applied,
            'rollback_data': self.rollback_data
        }


class DynamicConfigManager(LoggableMixin):
    """Dynamic configuration manager for real-time updates."""
    
    def __init__(self, config_path: str = "config/vpn_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.dynamic_config = self.config.get('dynamic_config', {})
        
        # Data storage
        self.regional_configs: Dict[str, RegionalConfig] = {}
        self.dynamic_configs: Dict[str, DynamicConfig] = {}
        self.config_changes: List[ConfigChange] = []
        self.config_subscribers: Dict[str, List[Callable]] = defaultdict(list)
        
        # File watchers
        self.file_watchers: Dict[str, watchdog.observers.Observer] = {}
        
        # State management
        self.running = False
        self.update_thread = None
        self.cleanup_thread = None
        
        # Statistics
        self.stats = {
            'total_changes': 0,
            'successful_changes': 0,
            'failed_changes': 0,
            'active_configs': 0,
            'regional_configs': 0,
            'dynamic_configs': 0,
            'subscribers': 0,
            'file_watches': 0
        }
        
        # Initialize
        self._initialize()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        try:
            from utils.config_loader import Config
            return Config(self.config_path).to_dict()
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return {}
    
    def _initialize(self):
        """Initialize dynamic configuration manager."""
        try:
            # Create directories
            os.makedirs('data/infrastructure/config', exist_ok=True)
            os.makedirs('data/infrastructure/config/regions', exist_ok=True)
            os.makedirs('data/infrastructure/config/dynamic', exist_ok=True)
            os.makedirs('data/infrastructure/config/changes', exist_ok=True)
            
            # Load existing configurations
            self._load_regional_configs()
            self._load_dynamic_configs()
            self._load_config_changes()
            
            # Start background tasks
            self._start_background_tasks()
            
            self.logger.info("Dynamic configuration manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize dynamic config manager: {e}")
            raise
    
    def _load_regional_configs(self):
        """Load regional configurations."""
        try:
            regions_file = 'data/infrastructure/config/regions/regional_configs.json'
            if os.path.exists(regions_file):
                with open(regions_file, 'r') as f:
                    data = json.load(f)
                    for region_data in data.get('regions', []):
                        config = RegionalConfig(
                            region=region_data['region'],
                            protocol_settings=region_data.get('protocol_settings', {}),
                            routing_preferences=region_data.get('routing_preferences', {}),
                            bandwidth_limits=region_data.get('bandwidth_limits', {}),
                            performance_thresholds=region_data.get('performance_thresholds', {}),
                            optimization_settings=region_data.get('optimization_settings', {}),
                            created_at=region_data.get('created_at', time.time()),
                            updated_at=region_data.get('updated_at', time.time()),
                            version=region_data.get('version', 1)
                        )
                        self.regional_configs[config.region] = config
                
                self.logger.info(f"Loaded {len(self.regional_configs)} regional configurations")
                
        except Exception as e:
            self.logger.error(f"Failed to load regional configs: {e}")
    
    def _load_dynamic_configs(self):
        """Load dynamic configurations."""
        try:
            dynamic_file = 'data/infrastructure/config/dynamic/dynamic_configs.json'
            if os.path.exists(dynamic_file):
                with open(dynamic_file, 'r') as f:
                    data = json.load(f)
                    for config_data in data.get('configs', []):
                        config = DynamicConfig(
                            config_id=config_data['config_id'],
                            config_type=config_data['config_type'],
                            target_id=config_data['target_id'],
                            value=config_data['value'],
                            timestamp=config_data['timestamp'],
                            ttl=config_data.get('ttl', 300),
                            applied=config_data.get('applied', True),
                            rollback_data=config_data.get('rollback_data')
                        )
                        self.dynamic_configs[config.config_id] = config
                
                self.logger.info(f"Loaded {len(self.dynamic_configs)} dynamic configurations")
                
        except Exception as e:
            self.logger.error(f"Failed to load dynamic configs: {e}")
    
    def _load_config_changes(self):
        """Load configuration changes history."""
        try:
            changes_file = 'data/infrastructure/config/changes/config_changes.json'
            if os.path.exists(changes_file):
                with open(changes_file, 'r') as f:
                    data = json.load(f)
                    for change_data in data.get('changes', []):
                        change = ConfigChange(
                            change_id=change_data['change_id'],
                            change_type=ConfigChangeType(change_data['change_type']),
                            timestamp=change_data['timestamp'],
                            server_id=change_data.get('server_id'),
                            config_key=change_data['config_key'],
                            old_value=change_data['old_value'],
                            new_value=change_data['new_value'],
                            applied=change_data.get('applied', True),
                            error_message=change_data.get('error_message')
                        )
                        self.config_changes.append(change)
                
                self.logger.info(f"Loaded {len(self.config_changes)} configuration changes")
                
        except Exception as e:
            self.logger.error(f"Failed to load config changes: {e}")
    
    def update_regional_config(self, region: str, updates: Dict[str, Any]) -> bool:
        """Update regional configuration."""
        try:
            if region not in self.regional_configs:
                self.logger.error(f"Region {region} not found")
                return False
            
            config = self.regional_configs[region]
            old_config = config.to_dict()
            
            # Apply updates
            for key, value in updates.items():
                if key == 'protocol_settings':
                    config.protocol_settings.update(value)
                elif key == 'routing_preferences':
                    config.routing_preferences.update(value)
                elif key == 'bandwidth_limits':
                    config.bandwidth_limits.update(value)
                elif key == 'performance_thresholds':
                    config.performance_thresholds.update(value)
                elif key == 'optimization_settings':
                    config.optimization_settings.update(value)
            
            config.updated_at = time.time()
            config.version += 1
            
            # Record change
            change = ConfigChange(
                change_id=f"region_change_{int(time.time())}_{region}",
                change_type=ConfigChangeType.REGION_CONFIG_UPDATED,
                timestamp=time.time(),
                server_id=None,
                config_key=f"region.{region}",
                old_value=old_config,
                new_value=config.to_dict(),
                applied=True
            )
            
            self.config_changes.append(change)
            self._save_regional_configs()
            self._save_config_changes()
            
            # Notify subscribers
            self._notify_subscribers('region_config_updated', {
                'region': region,
                'updates': updates,
                'config': config.to_dict()
            })
            
            self.stats['total_changes'] += 1
            self.stats['successful_changes'] += 1
            
            self.logger.info(f"Updated regional config for {region}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update regional config: {e}")
            return False
    
    def update_server_config(self, server_id: str, updates: Dict[str, Any]) -> bool:
        """Update server-specific configuration."""
        try:
            config_id = f"server_{server_id}"
            
            # Create dynamic config
            config = DynamicConfig(
                config_id=config_id,
                config_type='server_config',
                target_id=server_id,
                value=updates,
                timestamp=time.time(),
                ttl=3600,  # 1 hour
                applied=False
            )
            
            self.dynamic_configs[config_id] = config
            self._save_dynamic_configs()
            
            # Record change
            change = ConfigChange(
                change_id=f"server_change_{int(time.time())}_{server_id}",
                change_type=ConfigChangeType.SERVER_UPDATED,
                timestamp=time.time(),
                server_id=server_id,
                config_key=f"server.{server_id}",
                old_value=None,
                new_value=updates,
                applied=False
            )
            
            self.config_changes.append(change)
            self._save_config_changes()
            
            # Notify subscribers
            self._notify_subscribers('server_config_updated', {
                'server_id': server_id,
                'updates': updates
            })
            
            self.stats['total_changes'] += 1
            self.stats['successful_changes'] += 1
            self.stats['dynamic_configs'] += 1
            
            self.logger.info(f"Updated server config for {server_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update server config: {e}")
            return False
    
    def apply_dynamic_config(self, config_id: str) -> bool:
        """Apply a dynamic configuration."""
        try:
            config = self.dynamic_configs.get(config_id)
            if not config:
                self.logger.error(f"Dynamic config {config_id} not found")
                return False
            
            if config.applied:
                self.logger.warning(f"Dynamic config {config_id} already applied")
                return True
            
            # Apply configuration based on type
            success = False
            if config.config_type == 'server_config':
                success = self._apply_server_config(config)
            elif config.config_type == 'region_config':
                success = self._apply_region_config(config)
            
            if success:
                config.applied = True
                config.applied_at = time.time()
                self._save_dynamic_configs()
                
                # Record change
                change = ConfigChange(
                    change_id=config.config_id,
                    change_type=ConfigChangeType.SERVER_UPDATED,
                    timestamp=time.time(),
                    server_id=config.target_id,
                    config_key=config.config_type,
                    old_value=None,
                    new_value=config.value,
                    applied=True
                )
                
                self.config_changes.append(change)
                self._save_config_changes()
            
            self.stats['successful_changes'] += 1
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to apply dynamic config {config_id}: {e}")
            return False
    
    def _apply_server_config(self, config: DynamicConfig) -> bool:
        """Apply server configuration."""
        try:
            # This would integrate with the server manager
            # For now, simulate successful application
            self.logger.info(f"Applied server config to {config.target_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply server config: {e}")
            return False
    
    def _apply_region_config(self, config: DynamicConfig) -> bool:
        """Apply regional configuration."""
        try:
            # This would integrate with the geographic router
            # For now, simulate successful application
            self.logger.info(f"Applied regional config to {config.target_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply region config: {e}")
            return False
    
    def optimize_protocol_settings(self, region: str) -> Dict[str, Any]:
        """Optimize protocol settings for a region based on performance metrics."""
        try:
            if region not in self.regional_configs:
                return {}
            
            config = self.regional_configs[region]
            current_settings = config.protocol_settings
            
            # Get performance metrics for the region
            region_metrics = self._get_region_performance_metrics(region)
            
            optimized_settings = {}
            
            # Optimize based on latency
            if 'latency' in region_metrics:
                avg_latency = region_metrics['latency']
                if avg_latency > 100:  # High latency
                    optimized_settings['prefer_udp'] = True
                    optimized_settings['reduce_overhead'] = True
                    optimized_settings['buffer_size'] = min(2048, current_settings.get('buffer_size', 4096))
                else:
                    optimized_settings['prefer_tcp'] = True
                    optimized_settings['buffer_size'] = max(8192, current_settings.get('buffer_size', 4096))
            
            # Optimize based on bandwidth
            if 'bandwidth' in region_metrics:
                avg_bandwidth = region_metrics['bandwidth']
                if avg_bandwidth < 50:  # Low bandwidth
                    optimized_settings['compression_enabled'] = True
                    optimized_settings['compression_level'] = 9
                else:
                    optimized_settings['compression_enabled'] = False
                    optimized_settings['compression_level'] = 6
            
            # Optimize based on error rate
            if 'error_rate' in region_metrics:
                error_rate = region_metrics['error_rate']
                if error_rate > 0.01:  # High error rate
                    optimized_settings['retries'] = min(5, current_settings.get('retries', 3))
                    optimized_settings['timeout'] = min(30, current_settings.get('timeout', 10))
                else:
                    optimized_settings['retries'] = current_settings.get('retries', 3)
                    optimized_settings['timeout'] = current_settings.get('timeout', 10)
            
            return optimized_settings
            
        except Exception as e:
            self.logger.error(f"Failed to optimize protocol settings for {region}: {e}")
            return {}
    
    def _get_region_performance_metrics(self, region: str) -> Dict[str, float]:
        """Get performance metrics for a region."""
        try:
            # This would integrate with the bandwidth monitor and server manager
            # For now, return simulated metrics
            return {
                'latency': 120.0,  # ms
                'bandwidth': 500.0,  # Mbps
                'error_rate': 0.005,
                'packet_loss': 0.002,
                'throughput': 450.0  # Mbps
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get region performance metrics: {e}")
            return {}
    
    def subscribe_to_changes(self, change_type: str, callback: Callable):
        """Subscribe to configuration changes."""
        self.config_subscribers[change_type].append(callback)
        self.stats['subscribers'] += 1
    
    def _notify_subscribers(self, change_type: str, data: Dict[str, Any]):
        """Notify subscribers of configuration changes."""
        try:
            for callback in self.config_subscribers[change_type]:
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Subscriber callback error: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to notify subscribers: {e}")
    
    def get_regional_config(self, region: str) -> Optional[RegionalConfig]:
        """Get regional configuration."""
        return self.regional_configs.get(region)
    
    def get_server_dynamic_config(self, server_id: str) -> Optional[DynamicConfig]:
        """Get dynamic server configuration."""
        return self.dynamic_configs.get(f"server_{server_id}")
    
    def get_config_changes(self, hours: int = 24) -> List[ConfigChange]:
        """Get recent configuration changes."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            recent_changes = [c for c in self.config_changes if c.timestamp >= cutoff_time]
            return sorted(recent_changes, key=lambda x: x.timestamp, reverse=True)
            
        except Exception as e:
            self.logger.error(f"Failed to get config changes: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        try:
            return {
                'statistics': self.stats,
                'regional_configs': len(self.regional_configs),
                'dynamic_configs': len(self.dynamic_configs),
                'config_changes': len(self.config_changes),
                'active_subscribers': sum(len(subs) for subs in self.config_subscribers.values()),
                'file_watches': len(self.file_watchers),
                'last_updated': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _save_regional_configs(self):
        """Save regional configurations."""
        try:
            configs_data = {
                'regions': [config.to_dict() for config in self.regional_configs.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/config/regions/regional_configs.json', 'w') as f:
                json.dump(configs_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save regional configs: {e}")
    
    def _save_dynamic_configs(self):
        """Save dynamic configurations."""
        try:
            configs_data = {
                'configs': [config.to_dict() for config in self.dynamic_configs.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/config/dynamic/dynamic_configs.json', 'w') as f:
                json.dump(configs_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save dynamic configs: {e}")
    
    def _save_config_changes(self):
        """Save configuration changes."""
        try:
            changes_data = {
                'changes': [change.to_dict() for change in self.config_changes],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/config/changes/config_changes.json', 'w') as f:
                json.dump(changes_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save config changes: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks."""
        if self.running:
            return
        
        self.running = True
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        self.logger.info("Background tasks started")
    
    def _cleanup_worker(self):
        """Background worker for cleaning up expired configurations."""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean expired dynamic configs
                expired_configs = [
                    config_id for config_id, config in self.dynamic_configs.items()
                    if current_time - config.timestamp > config.ttl
                ]
                
                for config_id in expired_configs:
                    del self.dynamic_configs[config_id]
                    self.logger.info(f"Cleaned up expired dynamic config: {config_id}")
                
                # Clean old config changes
                cutoff_time = current_time - (24 * 3600)  # 24 hours
                self.config_changes = [c for c in self.config_changes if c.timestamp >= cutoff_time]
                
                time.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Cleanup worker error: {e}")
                time.sleep(60)
    
    def stop(self):
        """Stop the dynamic configuration manager."""
        try:
            self.running = False
            
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=10)
            
            # Save final state
            self._save_regional_configs()
            self._save_dynamic_configs()
            self._save_config_changes()
            
            self.logger.info("Dynamic configuration manager stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop dynamic config manager: {e}")
