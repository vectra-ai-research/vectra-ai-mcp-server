"""Validation utilities for Vectra MCP Server."""

import ipaddress
import re
from datetime import datetime
from typing import Optional, Tuple, Union


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_date_range(
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Validate and parse date range.
    
    Args:
        start_date: Start date in ISO format
        end_date: End date in ISO format
        
    Returns:
        Tuple of parsed start and end datetime objects
        
    Raises:
        ValueError: If date format is invalid or range is invalid
    """
    parsed_start = None
    parsed_end = None
    
    if start_date:
        try:
            parsed_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Invalid start_date format: {start_date}. Expected ISO format.")
    
    if end_date:
        try:
            parsed_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Invalid end_date format: {end_date}. Expected ISO format.")
    
    if parsed_start and parsed_end and parsed_start > parsed_end:
        raise ValueError("start_date must be before end_date")
    
    return parsed_start, parsed_end


def validate_severity(severity: str) -> bool:
    """Validate severity level.
    
    Args:
        severity: Severity level string
        
    Returns:
        True if valid severity, False otherwise
    """
    valid_severities = {"low", "medium", "high", "critical"}
    return severity.lower() in valid_severities


def validate_entity_type(entity_type: str) -> bool:
    """Validate entity type.
    
    Args:
        entity_type: Entity type string
        
    Returns:
        True if valid entity type, False otherwise
    """
    valid_types = {"account", "host"}
    return entity_type.lower() in valid_types


def validate_detection_category(category: str) -> bool:
    """Validate detection category.
    
    Args:
        category: Detection category string
        
    Returns:
        True if valid category, False otherwise
    """
    valid_categories = {
        "botnet_activity",
        "command_and_control",
        "exfiltration",
        "lateral_movement",
        "reconnaissance",
        "info"
    }
    return category.lower() in valid_categories


def validate_state(state: str) -> bool:
    """Validate entity or detection state.
    
    Args:
        state: State string
        
    Returns:
        True if valid state, False otherwise
    """
    valid_states = {"active", "inactive", "fixed"}
    return state.lower() in valid_states


def validate_score_range(score: Union[int, str], min_val: int = 0, max_val: int = 100) -> bool:
    """Validate score is within valid range.
    
    Args:
        score: Score value
        min_val: Minimum valid value
        max_val: Maximum valid value
        
    Returns:
        True if valid score, False otherwise
    """
    try:
        score_int = int(score)
        return min_val <= score_int <= max_val
    except (ValueError, TypeError):
        return False


def validate_id(entity_id: Union[int, str]) -> bool:
    """Validate entity ID format.
    
    Args:
        entity_id: Entity ID
        
    Returns:
        True if valid ID, False otherwise
    """
    try:
        id_int = int(entity_id)
        return id_int > 0
    except (ValueError, TypeError):
        return False


def validate_email(email: str) -> bool:
    """Validate email address format.
    
    Args:
        email: Email address string
        
    Returns:
        True if valid email, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_privilege_level(level: Union[int, str]) -> bool:
    """Validate privilege level.
    
    Args:
        level: Privilege level (1-10)
        
    Returns:
        True if valid privilege level, False otherwise
    """
    return validate_score_range(level, min_val=1, max_val=10)


def validate_urgency_score(score: Union[int, str]) -> bool:
    """Validate urgency score.
    
    Args:
        score: Urgency score
        
    Returns:
        True if valid urgency score, False otherwise
    """
    return validate_score_range(score, min_val=0, max_val=100)


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input.
    
    Args:
        value: String value to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        ValueError: If string is too long
    """
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    
    # Remove control characters
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
    
    # Truncate if too long
    if len(sanitized) > max_length:
        raise ValueError(f"String too long: {len(sanitized)} > {max_length}")
    
    return sanitized.strip()


def validate_limit_offset(limit: Optional[int] = None, offset: Optional[int] = None) -> Tuple[int, int]:
    """Validate and normalize limit and offset parameters.
    
    Args:
        limit: Result limit
        offset: Result offset
        
    Returns:
        Tuple of validated limit and offset
        
    Raises:
        ValueError: If limit or offset are invalid
    """
    if limit is not None:
        if not isinstance(limit, int) or limit < 1 or limit > 1000:
            raise ValueError("Limit must be between 1 and 1000")
    else:
        limit = 50  # Default limit
    
    if offset is not None:
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("Offset must be non-negative")
    else:
        offset = 0  # Default offset
    
    return limit, offset