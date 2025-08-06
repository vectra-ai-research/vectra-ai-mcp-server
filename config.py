"""Configuration management for Vectra MCP Server."""

import os
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class VectraConfig(BaseSettings):
    """Configuration settings for Vectra MCP Server."""
    
    # Vectra API Configuration
    base_url: str = Field(alias="VECTRA_BASE_URL")
    client_id: str = Field(alias="VECTRA_CLIENT_ID")
    client_secret: str = Field(alias="VECTRA_CLIENT_SECRET")
    api_version: str = Field(default="v3.4", alias="VECTRA_API_VERSION")
    oauth_token_url_override: Optional[str] = Field(default=None, alias="VECTRA_OAUTH_TOKEN_URL")
    
    # Request Configuration
    request_timeout: int = Field(default=30, alias="VECTRA_REQUEST_TIMEOUT")
    rate_limit_requests: int = Field(default=100, alias="VECTRA_RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(default=60, alias="VECTRA_RATE_LIMIT_PERIOD")
    
    # Cache Configuration
    cache_ttl: int = Field(default=300, alias="VECTRA_CACHE_TTL")
    
    # Logging Configuration
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    
    # Development Configuration
    dev_mode: bool = Field(default=False, alias="DEV_MODE")
    
    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Validate and normalize the base URL."""
        if not v:
            raise ValueError("VECTRA_BASE_URL is required")
        
        # Remove trailing slash
        v = v.rstrip("/")
        
        # Ensure HTTPS
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        
        return v
    
    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        """Validate the API version."""
        supported_versions = ["v3", "v3.1", "v3.2", "v3.3", "v3.4"]
        if v not in supported_versions:
            raise ValueError(f"Unsupported API version: {v}. Supported versions: {supported_versions}")
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate the log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Valid levels: {valid_levels}")
        return v
    
    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        """Validate the log format."""
        valid_formats = ["json", "text"]
        v = v.lower()
        if v not in valid_formats:
            raise ValueError(f"Invalid log format: {v}. Valid formats: {valid_formats}")
        return v
    
    @property
    def api_base_url(self) -> str:
        """Get the full API base URL."""
        return f"{self.base_url}/api/{self.api_version}"
    
    @property
    def oauth_token_url(self) -> str:
        """Get the OAuth token URL."""
        if self.oauth_token_url_override:
            return self.oauth_token_url_override
        
        # Try common OAuth endpoints for Vectra tenants
        return f"{self.base_url}/oauth2/token"
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
        "populate_by_name": True
    }


def get_config() -> VectraConfig:
    """Get the configuration instance."""
    return VectraConfig()


def load_config_from_env() -> VectraConfig:
    """Load configuration from environment variables."""
    try:
        return VectraConfig()
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration: {e}")


# Global configuration instance
config: Optional[VectraConfig] = None


def init_config() -> VectraConfig:
    """Initialize global configuration."""
    global config
    if config is None:
        config = load_config_from_env()
    return config


def get_global_config() -> VectraConfig:
    """Get the global configuration instance."""
    if config is None:
        return init_config()
    return config