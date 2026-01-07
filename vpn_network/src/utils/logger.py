"""
Logging configuration for the VPN Security Project.

This module provides a centralized logging configuration that can be used
throughout the application. It supports both console and file logging with
configurable log levels and formatting.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional, Union, Dict, Any

def setup_logger(
    name: str,
    level: Union[str, int] = logging.INFO,
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    log_format: Optional[str] = None,
    date_format: Optional[str] = None
) -> logging.Logger:
    """
    Configure and return a logger with the specified settings.
    
    Args:
        name: The name of the logger.
        level: The logging level (e.g., 'DEBUG', 'INFO', 'WARNING').
        log_file: Path to the log file. If None, logs will only go to console.
        max_bytes: Maximum size of the log file before rotation.
        backup_count: Number of backup log files to keep.
        log_format: Custom log format string.
        date_format: Custom date format string.
        
    Returns:
        A configured logger instance.
    """
    # Default log format
    if log_format is None:
        log_format = (
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s '
            '[%(filename)s:%(lineno)d]'
        )
    
    # Default date format
    if date_format is None:
        date_format = '%Y-%m-%d %H:%M:%S'
    
    # Create formatter
    formatter = logging.Formatter(fmt=log_format, datefmt=date_format)
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Don't propagate to root logger to avoid duplicate logs
    logger.propagate = False
    
    # Set log level
    if isinstance(level, str):
        level = level.upper()
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if log file is specified
    if log_file:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=max_bytes, 
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    This is a convenience function that returns a logger with the default
    configuration. For more control, use setup_logger() directly.
    
    Args:
        name: The name of the logger.
        
    Returns:
        A configured logger instance.
    """
    return logging.getLogger(name)

class LoggableMixin:
    """Mixin class that provides logging capabilities to other classes."""
    
    def __init__(self, logger: Optional[logging.Logger] = None, **kwargs):
        """
        Initialize the LoggableMixin.
        
        Args:
            logger: An optional logger instance. If not provided, a new logger
                   will be created using the class name.
            **kwargs: Additional keyword arguments.
        """
        self._logger = logger or logging.getLogger(self.__class__.__name__)
        super().__init__(**kwargs)
    
    @property
    def logger(self) -> logging.Logger:
        """Get the logger instance."""
        return self._logger
    
    def log(self, level: Union[str, int], msg: str, *args, **kwargs) -> None:
        """
        Log a message with the specified level.
        
        Args:
            level: The logging level (e.g., 'DEBUG', 'INFO', 'WARNING').
            msg: The message to log.
            *args: Arguments to format into the message.
            **kwargs: Additional keyword arguments to pass to the logger.
        """
        self._logger.log(level, msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs) -> None:
        """Log a debug message."""
        self._logger.debug(msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs) -> None:
        """Log an info message."""
        self._logger.info(msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs) -> None:
        """Log a warning message."""
        self._logger.warning(msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs) -> None:
        """Log an error message."""
        self._logger.error(msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs) -> None:
        """Log a critical message."""
        self._logger.critical(msg, *args, **kwargs)
    
    def exception(self, msg: str, *args, exc_info: bool = True, **kwargs) -> None:
        """
        Log an exception with stack trace.
        
        Args:
            msg: The message to log.
            *args: Arguments to format into the message.
            exc_info: Whether to include exception information.
            **kwargs: Additional keyword arguments to pass to the logger.
        """
        self._logger.exception(msg, *args, exc_info=exc_info, **kwargs)
