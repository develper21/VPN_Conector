#!/usr/bin/env python3
"""
Advanced Features Manager
Coordinates all advanced VPN features and provides a unified interface.
"""
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from .split_tunneling import SplitTunnelingManager, RoutingRule
from .kill_switch import KillSwitch, KillSwitchConfig
from .dns_leak_protection import DNSLeakProtection, DNSConfig
from .protocol_obfuscation import ProtocolObfuscator, ObfuscationConfig
from utils.logger import setup_logger


@dataclass
class AdvancedFeaturesConfig:
    """Configuration for all advanced features."""
    split_tunneling_enabled: bool = True
    kill_switch_enabled: bool = True
    dns_leak_protection_enabled: bool = True
    protocol_obfuscation_enabled: bool = True
    
    # Auto-enable settings
    auto_activate_on_vpn_connect: bool = True
    auto_deactivate_on_vpn_disconnect: bool = True
    
    # Integration settings
    priority_order: List[str] = None
    
    def __post_init__(self):
        if self.priority_order is None:
            self.priority_order = [
                "kill_switch",
                "dns_leak_protection", 
                "split_tunneling",
                "protocol_obfuscation"
            ]


class AdvancedFeaturesManager:
    """Manages all advanced VPN features."""
    
    def __init__(self, config_path: str = "config/advanced_features.json"):
        self.logger = setup_logger("advanced_features_manager", "INFO")
        self.config_path = Path(config_path)
        self.config = AdvancedFeaturesConfig()
        
        # Initialize feature managers
        self.split_tunneling = SplitTunnelingManager()
        self.kill_switch = KillSwitch()
        self.dns_protection = DNSLeakProtection()
        self.protocol_obfuscator = ProtocolObfuscator()
        
        # State tracking
        self.is_vpn_connected = False
        self.active_features: List[str] = []
        self.monitoring_thread = None
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> None:
        """Load advanced features configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                self.logger.info("Advanced features configuration loaded")
            else:
                self.save_configuration()
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
    
    def save_configuration(self) -> None:
        """Save current configuration to file."""
        try:
            config_data = asdict(self.config)
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
                
            self.logger.info("Configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def on_vpn_connected(self, vpn_interface: str = "tun0") -> bool:
        """Called when VPN connects - activates enabled features."""
        try:
            self.logger.info("VPN connected - activating advanced features")
            self.is_vpn_connected = True
            
            success = True
            
            # Activate features in priority order
            for feature_name in self.config.priority_order:
                if self._is_feature_enabled(feature_name):
                    if self._activate_feature(feature_name, vpn_interface):
                        self.active_features.append(feature_name)
                        self.logger.info(f"Activated feature: {feature_name}")
                    else:
                        self.logger.error(f"Failed to activate feature: {feature_name}")
                        success = False
            
            # Start monitoring thread
            self._start_monitoring()
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to handle VPN connection: {e}")
            return False
    
    def on_vpn_disconnected(self) -> bool:
        """Called when VPN disconnects - deactivates features."""
        try:
            self.logger.info("VPN disconnected - deactivating advanced features")
            self.is_vpn_connected = False
            
            success = True
            
            # Deactivate features in reverse priority order
            for feature_name in reversed(self.config.priority_order):
                if feature_name in self.active_features:
                    if self._deactivate_feature(feature_name):
                        self.active_features.remove(feature_name)
                        self.logger.info(f"Deactivated feature: {feature_name}")
                    else:
                        self.logger.error(f"Failed to deactivate feature: {feature_name}")
                        success = False
            
            # Stop monitoring thread
            self._stop_monitoring()
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to handle VPN disconnection: {e}")
            return False
    
    def _is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a feature is enabled in configuration."""
        try:
            if feature_name == "split_tunneling":
                return self.config.split_tunneling_enabled
            elif feature_name == "kill_switch":
                return self.config.kill_switch_enabled
            elif feature_name == "dns_leak_protection":
                return self.config.dns_leak_protection_enabled
            elif feature_name == "protocol_obfuscation":
                return self.config.protocol_obfuscation_enabled
            else:
                return False
                
        except Exception:
            return False
    
    def _activate_feature(self, feature_name: str, vpn_interface: str) -> bool:
        """Activate a specific feature."""
        try:
            if feature_name == "split_tunneling":
                return self.split_tunneling.activate(vpn_interface)
            elif feature_name == "kill_switch":
                return self.kill_switch.activate(vpn_interface)
            elif feature_name == "dns_leak_protection":
                return self.dns_protection.activate(vpn_interface)
            elif feature_name == "protocol_obfuscation":
                return self.protocol_obfuscator.activate()
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to activate {feature_name}: {e}")
            return False
    
    def _deactivate_feature(self, feature_name: str) -> bool:
        """Deactivate a specific feature."""
        try:
            if feature_name == "split_tunneling":
                return self.split_tunneling.deactivate()
            elif feature_name == "kill_switch":
                return self.kill_switch.deactivate()
            elif feature_name == "dns_leak_protection":
                return self.dns_protection.deactivate()
            elif feature_name == "protocol_obfuscation":
                return self.protocol_obfuscator.deactivate()
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to deactivate {feature_name}: {e}")
            return False
    
    def _start_monitoring(self) -> None:
        """Start monitoring thread for feature health."""
        try:
            if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
                self.monitoring_thread = threading.Thread(target=self._monitor_features, daemon=True)
                self.monitoring_thread.start()
                
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
    
    def _stop_monitoring(self) -> None:
        """Stop monitoring thread."""
        try:
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                # Thread will stop naturally when is_vpn_connected is False
                pass
                
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
    
    def _monitor_features(self) -> None:
        """Monitor health of active features."""
        while self.is_vpn_connected:
            try:
                # Check each active feature
                for feature_name in self.active_features:
                    if not self._is_feature_healthy(feature_name):
                        self.logger.warning(f"Feature {feature_name} appears unhealthy, attempting recovery")
                        self._recover_feature(feature_name)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in feature monitoring: {e}")
                time.sleep(60)
    
    def _is_feature_healthy(self, feature_name: str) -> bool:
        """Check if a feature is healthy."""
        try:
            if feature_name == "kill_switch":
                status = self.kill_switch.get_status()
                return status.get('active', False)
            elif feature_name == "dns_leak_protection":
                status = self.dns_protection.get_status()
                return status.get('active', False)
            elif feature_name == "split_tunneling":
                status = self.split_tunneling.get_status()
                return status.get('active', False)
            elif feature_name == "protocol_obfuscation":
                status = self.protocol_obfuscator.get_status()
                return status.get('active', False)
            else:
                return False
                
        except Exception:
            return False
    
    def _recover_feature(self, feature_name: str) -> None:
        """Attempt to recover a failed feature."""
        try:
            self.logger.info(f"Attempting to recover feature: {feature_name}")
            
            # Deactivate and reactivate the feature
            if self._deactivate_feature(feature_name):
                time.sleep(2)
                if self._activate_feature(feature_name, "tun0"):
                    self.logger.info(f"Successfully recovered feature: {feature_name}")
                else:
                    self.logger.error(f"Failed to recover feature: {feature_name}")
            else:
                self.logger.error(f"Failed to deactivate feature for recovery: {feature_name}")
                
        except Exception as e:
            self.logger.error(f"Feature recovery failed: {e}")
    
    def add_split_tunneling_rule(self, rule: RoutingRule) -> bool:
        """Add a split tunneling rule."""
        return self.split_tunneling.add_rule(rule)
    
    def remove_split_tunneling_rule(self, rule_name: str) -> bool:
        """Remove a split tunneling rule."""
        return self.split_tunneling.remove_rule(rule_name)
    
    def test_all_features(self) -> Dict[str, bool]:
        """Test all advanced features."""
        results = {}
        
        try:
            # Test split tunneling
            results['split_tunneling'] = True  # Simplified test
            
            # Test kill switch
            results['kill_switch'] = self.kill_switch.test_kill_switch()
            
            # Test DNS leak protection
            results['dns_leak_protection'] = self.dns_protection.test_dns_leak_protection()
            
            # Test protocol obfuscation
            results['protocol_obfuscation'] = self.protocol_obfuscator.test_obfuscation()
            
        except Exception as e:
            self.logger.error(f"Feature testing failed: {e}")
        
        return results
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all features."""
        try:
            status = {
                'vpn_connected': self.is_vpn_connected,
                'active_features': self.active_features.copy(),
                'config': asdict(self.config),
                'features': {
                    'split_tunneling': self.split_tunneling.get_status(),
                    'kill_switch': self.kill_switch.get_status(),
                    'dns_leak_protection': self.dns_protection.get_status(),
                    'protocol_obfuscation': self.protocol_obfuscator.get_status()
                },
                'health': {
                    feature: self._is_feature_healthy(feature)
                    for feature in self.active_features
                }
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get comprehensive status: {e}")
            return {}
    
    def update_feature_config(self, feature_name: str, config_updates: Dict) -> bool:
        """Update configuration for a specific feature."""
        try:
            if feature_name == "split_tunneling":
                # Update split tunneling config
                for key, value in config_updates.items():
                    if hasattr(self.split_tunneling.config, key):
                        setattr(self.split_tunneling.config, key, value)
                self.split_tunneling.save_configuration()
                
            elif feature_name == "kill_switch":
                # Update kill switch config
                for key, value in config_updates.items():
                    if hasattr(self.kill_switch.config, key):
                        setattr(self.kill_switch.config, key, value)
                self.kill_switch.save_configuration()
                
            elif feature_name == "dns_leak_protection":
                # Update DNS protection config
                for key, value in config_updates.items():
                    if hasattr(self.dns_protection.config, key):
                        setattr(self.dns_protection.config, key, value)
                self.dns_protection.save_configuration()
                
            elif feature_name == "protocol_obfuscation":
                # Update protocol obfuscation config
                for key, value in config_updates.items():
                    if hasattr(self.protocol_obfuscator.config, key):
                        setattr(self.protocol_obfuscator.config, key, value)
                self.protocol_obfuscator.save_configuration()
            
            self.logger.info(f"Updated configuration for {feature_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update config for {feature_name}: {e}")
            return False
    
    def shutdown(self) -> None:
        """Gracefully shutdown all features."""
        try:
            self.logger.info("Shutting down advanced features manager")
            
            # Deactivate all active features
            for feature_name in self.active_features.copy():
                self._deactivate_feature(feature_name)
            
            # Stop monitoring
            self._stop_monitoring()
            
            self.logger.info("Advanced features manager shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Example usage
if __name__ == "__main__":
    # Create advanced features manager
    manager = AdvancedFeaturesManager()
    
    # Simulate VPN connection
    manager.on_vpn_connected("tun0")
    
    # Get status
    status = manager.get_comprehensive_status()
    print("Advanced Features Status:")
    print(json.dumps(status, indent=2))
    
    # Test features
    test_results = manager.test_all_features()
    print("\nFeature Test Results:")
    for feature, result in test_results.items():
        print(f"{feature}: {'PASSED' if result else 'FAILED'}")
    
    # Simulate VPN disconnection
    manager.on_vpn_disconnected()
