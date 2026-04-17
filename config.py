"""Configuration management for Vectra MCP Server.

Supports two modes:
  1. Legacy single-tenant: reads from environment variables / .env file (backward compatible).
  2. Multi-tenant YAML: reads tenants from a YAML config file, with per-tenant env var overrides.
"""

import os
import re
import logging
from typing import Optional, List

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

_SUPPORTED_API_VERSIONS = ["v3", "v3.1", "v3.2", "v3.3", "v3.4"]
_VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_VALID_LOG_FORMATS = ["json", "text"]
# Tenant names must be safe for MCP tool name prefixes (alphanumeric + underscore, 1-20 chars)
_TENANT_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,19}$")


def _validate_base_url(v: str) -> str:
    """Validate and normalize a base URL."""
    if not v:
        raise ValueError("base_url is required")
    v = v.rstrip("/")
    if not v.startswith(("http://", "https://")):
        v = f"https://{v}"
    return v


def _validate_api_version(v: str) -> str:
    if v not in _SUPPORTED_API_VERSIONS:
        raise ValueError(f"Unsupported API version: {v}. Supported versions: {_SUPPORTED_API_VERSIONS}")
    return v


# ---------------------------------------------------------------------------
# Legacy single-tenant config (backward compatible)
# ---------------------------------------------------------------------------

class VectraConfig(BaseSettings):
    """Configuration settings for Vectra MCP Server (single-tenant / legacy)."""

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
        return _validate_base_url(v)

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        return _validate_api_version(v)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        v = v.upper()
        if v not in _VALID_LOG_LEVELS:
            raise ValueError(f"Invalid log level: {v}. Valid levels: {_VALID_LOG_LEVELS}")
        return v

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        v = v.lower()
        if v not in _VALID_LOG_FORMATS:
            raise ValueError(f"Invalid log format: {v}. Valid formats: {_VALID_LOG_FORMATS}")
        return v

    @property
    def api_base_url(self) -> str:
        return f"{self.base_url}/api/{self.api_version}"

    @property
    def oauth_token_url(self) -> str:
        if self.oauth_token_url_override:
            return self.oauth_token_url_override
        return f"{self.base_url}/oauth2/token"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
        "populate_by_name": True
    }


# ---------------------------------------------------------------------------
# Multi-tenant tenant descriptor
# ---------------------------------------------------------------------------

class TenantConfig(BaseModel):
    """Configuration for a single Vectra tenant."""

    name: str = Field(description="Short identifier used as tool name prefix (e.g. 'prod')")
    base_url: str
    client_id: str
    client_secret: str
    api_version: str = "v3.4"
    oauth_token_url_override: Optional[str] = None
    request_timeout: int = 30
    rate_limit_requests: int = 100
    rate_limit_period: int = 60
    cache_ttl: int = 300

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _TENANT_NAME_RE.match(v):
            raise ValueError(
                f"Invalid tenant name '{v}'. Must start with a letter, contain only "
                f"alphanumerics/underscores, and be 1-20 characters."
            )
        return v

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        return _validate_base_url(v)

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        return _validate_api_version(v)

    @property
    def api_base_url(self) -> str:
        return f"{self.base_url}/api/{self.api_version}"

    @property
    def oauth_token_url(self) -> str:
        if self.oauth_token_url_override:
            return self.oauth_token_url_override
        return f"{self.base_url}/oauth2/token"


def _tenant_config_from_vectra_config(cfg: VectraConfig) -> TenantConfig:
    """Convert a legacy VectraConfig into a TenantConfig (single-tenant, no prefix)."""
    return TenantConfig(
        name="default",
        base_url=cfg.base_url,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        api_version=cfg.api_version,
        oauth_token_url_override=cfg.oauth_token_url_override,
        request_timeout=cfg.request_timeout,
        rate_limit_requests=cfg.rate_limit_requests,
        rate_limit_period=cfg.rate_limit_period,
        cache_ttl=cfg.cache_ttl,
    )


def _vectra_config_from_tenant(tenant: TenantConfig, legacy_cfg: Optional[VectraConfig] = None) -> VectraConfig:
    """Create a VectraConfig from a TenantConfig so VectraClient works unchanged.

    If *legacy_cfg* is provided, global settings (log_level, log_format, dev_mode)
    are inherited from it; otherwise defaults are used.
    """
    return VectraConfig(
        VECTRA_BASE_URL=tenant.base_url,
        VECTRA_CLIENT_ID=tenant.client_id,
        VECTRA_CLIENT_SECRET=tenant.client_secret,
        VECTRA_API_VERSION=tenant.api_version,
        VECTRA_OAUTH_TOKEN_URL=tenant.oauth_token_url_override,
        VECTRA_REQUEST_TIMEOUT=tenant.request_timeout,
        VECTRA_RATE_LIMIT_REQUESTS=tenant.rate_limit_requests,
        VECTRA_RATE_LIMIT_PERIOD=tenant.rate_limit_period,
        VECTRA_CACHE_TTL=tenant.cache_ttl,
        LOG_LEVEL=legacy_cfg.log_level if legacy_cfg else os.environ.get("LOG_LEVEL", "INFO"),
        LOG_FORMAT=legacy_cfg.log_format if legacy_cfg else os.environ.get("LOG_FORMAT", "json"),
        DEV_MODE=legacy_cfg.dev_mode if legacy_cfg else (os.environ.get("DEV_MODE", "false").lower() == "true"),
    )


# ---------------------------------------------------------------------------
# YAML loader with per-tenant env var overrides
# ---------------------------------------------------------------------------

# Fields that can be overridden per tenant via VECTRA_TENANT_<NAME>_<FIELD> env vars
_TENANT_ENV_FIELDS = {
    "BASE_URL": "base_url",
    "CLIENT_ID": "client_id",
    "CLIENT_SECRET": "client_secret",
    "API_VERSION": "api_version",
    "OAUTH_TOKEN_URL": "oauth_token_url_override",
    "REQUEST_TIMEOUT": "request_timeout",
    "RATE_LIMIT_REQUESTS": "rate_limit_requests",
    "RATE_LIMIT_PERIOD": "rate_limit_period",
    "CACHE_TTL": "cache_ttl",
}


def _apply_env_overrides(tenant_dict: dict) -> dict:
    """Apply environment variable overrides for a tenant.

    Pattern: ``VECTRA_TENANT_<NAME_UPPER>_<FIELD>``
    Example: ``VECTRA_TENANT_PROD_BASE_URL`` overrides ``base_url`` for tenant "prod".
    """
    name = tenant_dict.get("name", "")
    prefix = f"VECTRA_TENANT_{name.upper()}_"

    for env_suffix, field_name in _TENANT_ENV_FIELDS.items():
        env_var = f"{prefix}{env_suffix}"
        value = os.environ.get(env_var)
        if value is not None:
            # Convert integer fields
            if field_name in ("request_timeout", "rate_limit_requests", "rate_limit_period", "cache_ttl"):
                value = int(value)
            tenant_dict[field_name] = value
            logger.debug("Env override %s applied for tenant '%s'", env_var, name)

    return tenant_dict


def load_tenants_from_yaml(config_path: str) -> List[TenantConfig]:
    """Load tenant configurations from a YAML file, applying env var overrides.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        List of validated TenantConfig objects.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML structure is invalid or a tenant config fails validation.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "tenants" not in data:
        raise ValueError(f"YAML config must contain a top-level 'tenants' key: {config_path}")

    raw_tenants = data["tenants"]
    if not isinstance(raw_tenants, list) or len(raw_tenants) == 0:
        raise ValueError(f"'tenants' must be a non-empty list in: {config_path}")

    tenants: List[TenantConfig] = []
    seen_names: set = set()

    for idx, raw in enumerate(raw_tenants):
        if not isinstance(raw, dict):
            raise ValueError(f"Tenant entry {idx} must be a mapping in: {config_path}")

        # Apply env var overrides
        raw = _apply_env_overrides(raw)

        tenant = TenantConfig(**raw)

        if tenant.name in seen_names:
            raise ValueError(f"Duplicate tenant name '{tenant.name}' in: {config_path}")
        seen_names.add(tenant.name)

        tenants.append(tenant)

    return tenants


# ---------------------------------------------------------------------------
# Unified loader
# ---------------------------------------------------------------------------

class ServerConfiguration:
    """Holds the resolved server configuration (single or multi-tenant).

    Attributes:
        tenants: List of tenant configs. In single-tenant mode this has exactly one entry.
        is_multi_tenant: True when multiple tenants are configured.
        log_level: Global log level.
        log_format: Global log format.
        dev_mode: Global dev mode flag.
    """

    def __init__(
        self,
        tenants: List[TenantConfig],
        is_multi_tenant: bool,
        log_level: str = "INFO",
        log_format: str = "json",
        dev_mode: bool = False,
    ):
        self.tenants = tenants
        self.is_multi_tenant = is_multi_tenant
        self.log_level = log_level
        self.log_format = log_format
        self.dev_mode = dev_mode

    def vectra_config_for_tenant(self, tenant: TenantConfig) -> VectraConfig:
        """Build a VectraConfig for a given tenant (so VectraClient works unchanged)."""
        return VectraConfig(
            VECTRA_BASE_URL=tenant.base_url,
            VECTRA_CLIENT_ID=tenant.client_id,
            VECTRA_CLIENT_SECRET=tenant.client_secret,
            VECTRA_API_VERSION=tenant.api_version,
            VECTRA_OAUTH_TOKEN_URL=tenant.oauth_token_url_override,
            VECTRA_REQUEST_TIMEOUT=tenant.request_timeout,
            VECTRA_RATE_LIMIT_REQUESTS=tenant.rate_limit_requests,
            VECTRA_RATE_LIMIT_PERIOD=tenant.rate_limit_period,
            VECTRA_CACHE_TTL=tenant.cache_ttl,
            LOG_LEVEL=self.log_level,
            LOG_FORMAT=self.log_format,
            DEV_MODE=self.dev_mode,
        )


def load_configuration(config_file: Optional[str] = None) -> ServerConfiguration:
    """Load the server configuration.

    Resolution order:
      1. If *config_file* is provided (or ``VECTRA_CONFIG_FILE`` env var is set)
         and the file exists, load multi-tenant config from YAML.
      2. Otherwise, fall back to legacy single-tenant config from environment/.env.

    Returns:
        A ``ServerConfiguration`` instance.
    """
    config_path = config_file or os.environ.get("VECTRA_CONFIG_FILE")

    # Global settings from env (used regardless of mode)
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_format = os.environ.get("LOG_FORMAT", "json").lower()
    dev_mode = os.environ.get("DEV_MODE", "false").lower() == "true"

    if config_path and os.path.isfile(config_path):
        logger.info("Loading multi-tenant configuration from %s", config_path)
        tenants = load_tenants_from_yaml(config_path)
        return ServerConfiguration(
            tenants=tenants,
            is_multi_tenant=True,
            log_level=log_level,
            log_format=log_format,
            dev_mode=dev_mode,
        )

    # Legacy single-tenant mode
    logger.info("Loading single-tenant configuration from environment")
    legacy_cfg = VectraConfig()
    tenant = _tenant_config_from_vectra_config(legacy_cfg)
    return ServerConfiguration(
        tenants=[tenant],
        is_multi_tenant=False,
        log_level=legacy_cfg.log_level,
        log_format=legacy_cfg.log_format,
        dev_mode=legacy_cfg.dev_mode,
    )


# ---------------------------------------------------------------------------
# Backward-compatible globals (for code that still calls init_config / get_global_config)
# ---------------------------------------------------------------------------

config: Optional[VectraConfig] = None


def get_config() -> VectraConfig:
    """Get the configuration instance."""
    return VectraConfig()


def load_config_from_env() -> VectraConfig:
    """Load configuration from environment variables."""
    try:
        return VectraConfig()
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration: {e}")


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
