import logging
import logging.handlers
import os
import re
import json
import datetime
from typing import Optional


class SensitiveDataFilter(logging.Filter):
    """Filter to sanitize sensitive data from log messages."""
    
    SENSITIVE_PATTERNS = [
        (r'token["\s]*[:=]["\s]*([^"\s]+)', r'token="***"'),
        (r'password["\s]*[:=]["\s]*([^"\s]+)', r'password="***"'),
        (r'secret["\s]*[:=]["\s]*([^"\s]+)', r'secret="***"'),
        (r'key["\s]*[:=]["\s]*([^"\s]+)', r'key="***"'),
        (r'Authorization:\s*Bearer\s+([^\s]+)', r'Authorization: Bearer ***'),
        (r'client_secret["\s]*[:=]["\s]*([^"\s]+)', r'client_secret="***"'),
    ]
    
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            message = record.msg
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
            record.msg = message
        return True


def setup_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True,
    json_format: bool = False
) -> None:
    """Configure logging for server.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, only console logging)
        max_file_size: Maximum log file size in bytes before rotation
        backup_count: Number of backup files to keep
        enable_console: Whether to enable console logging
        json_format: Whether to use JSON structured logging
    """
    # Set log level
    if level is None:
        level = os.environ.get('VECTRA_LOG_LEVEL', 'INFO')
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    if json_format:
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    'timestamp': datetime.datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno,
                }
                if hasattr(record, 'exc_info') and record.exc_info:
                    log_entry['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_entry)
        
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Add sensitive data filter
    sensitive_filter = SensitiveDataFilter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(sensitive_filter)
        root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        # Check log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)
    
    # Set specific logger levels for high volume libraries
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance with optional custom level.
    
    Args:
        name: Logger name (typically __name__)
        level: Optional custom log level for this logger
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    if level:
        log_level = getattr(logging, level.upper(), logging.INFO)
        logger.setLevel(log_level)
    
    return logger


def configure_debug_logging():
    """Enable debug logging for troubleshooting."""
    logging.getLogger().setLevel(logging.DEBUG)
    for handler in logging.getLogger().handlers:
        handler.setLevel(logging.DEBUG)