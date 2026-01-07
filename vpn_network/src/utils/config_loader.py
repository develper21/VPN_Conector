"""
Configuration loader for the VPN Security Project.

This module provides functionality to load and validate configuration
from JSON files with support for environment variable overrides.
"""
import json
import os
from copy import deepcopy
from typing import Any, Dict, Optional

class Config:
    """
    Configuration manager that loads settings from a JSON file.
    
    This class handles loading configuration from a JSON file and provides
    methods to access configuration values with support for nested keys.
    """
    
    def __init__(self, config_path: str):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the JSON configuration file.
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist.
            json.JSONDecodeError: If the configuration file contains invalid JSON.
        """
        self.config_path = os.path.abspath(config_path)
        self._config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from the JSON file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self._config = json.load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation for nested keys.
        
        Args:
            key: The configuration key in dot notation (e.g., 'server.port').
            default: Default value to return if the key is not found.
            
        Returns:
            The configuration value or the default if not found.
        """
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section as a dictionary.
        
        Args:
            section: The section name to retrieve.
            
        Returns:
            A dictionary containing the section's configuration.
            
        Raises:
            KeyError: If the section doesn't exist.
        """
        if section not in self._config:
            raise KeyError(f"Configuration section not found: {section}")
        return self._config[section]
    
    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access to configuration values."""
        return self.get(key)
    
    def __contains__(self, key: str) -> bool:
        """Check if a configuration key exists."""
        try:
            self.get(key)
            return True
        except KeyError:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Return a deep copy of the underlying configuration dictionary."""
        return deepcopy(self._config)
    
    def reload(self) -> None:
        """Reload the configuration from disk."""
        self._load_config()
    
    def __str__(self) -> str:
        """Return a string representation of the configuration."""
        return json.dumps(self._config, indent=2, sort_keys=True)
