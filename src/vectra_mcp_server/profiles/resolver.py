"""Deciding which tenant a run talks to.

Precedence, highest first::

    1  --profile on the command line
    2  VECTRA_PROFILE in the environment
    3  the active profile in profiles.yaml
    4  VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET   (legacy)
    5  a configuration error naming every option

Rules 1-3 select a profile; rule 4 is the path every existing deployment uses
and must keep working untouched.

Why the shadow warning exists
-----------------------------
A profile outranking the environment is a behaviour change for anyone who has
both — and today the environment is the only path, so *everyone* upgrading has
it. An operator with working env vars who later adds a profile would silently
start talking to a different customer's tenant.

Nothing here prevents that; the precedence is what it is. What it does is
refuse to be quiet about it: whenever a lower-ranked provider *could* have
answered, the winner and the loser are both logged by name. Given that the
audit trail cannot distinguish one analyst from another, a silent tenant switch
is the one failure mode worth spending a log line on every startup to avoid.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

from ..config import (
    ServerConfiguration,
    TenantConfig,
    VectraConfig,
    _tenant_config_from_vectra_config,
)
from ..utils.logging import get_logger
from .credentials import (
    ENV_CLIENT_ID,
    ENV_CLIENT_SECRET,
    CredentialStore,
    KeyringCredentialStore,
)
from .store import Profile, ProfileStore, UnknownProfile

logger = get_logger(__name__)

PROFILE_ENV = "VECTRA_PROFILE"
ENV_BASE_URL = "VECTRA_BASE_URL"

#: Human names for the four providers, used in log lines and errors.
SOURCE_EXPLICIT = "explicit --profile"
SOURCE_ENV_PROFILE = f"{PROFILE_ENV} environment variable"
SOURCE_ACTIVE = "active profile"
SOURCE_ENVIRONMENT = "environment variables"


class ConfigurationError(Exception):
    """No usable configuration could be resolved."""


@dataclass(frozen=True)
class Resolution:
    """What was resolved, and where it came from.

    Provenance is carried rather than logged and forgotten because two other
    things need it: the startup shadow warning, and the read-only
    ``get_active_profile`` tool that lets an agent state which tenant its
    report is about.
    """

    server_config: ServerConfiguration
    source: str
    profile_name: Optional[str] = None
    shadowed: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def base_url(self) -> str:
        return self.server_config.tenants[0].base_url

    @property
    def client_id(self) -> str:
        """Safe to surface: the non-secret half, and the only attribution."""
        return self.server_config.tenants[0].client_id

    def describe(self) -> str:
        who = f"profile {self.profile_name!r}" if self.profile_name else "environment configuration"
        return f"{who} via {self.source} -> {self.base_url}"


def _env_is_configured() -> bool:
    """True when the legacy variables could produce a working configuration."""
    return all(os.environ.get(k) for k in (ENV_BASE_URL, ENV_CLIENT_ID, ENV_CLIENT_SECRET))


def _tenant_from_profile(
    name: str, profile: Profile, credential_store: CredentialStore
) -> TenantConfig:
    ref = profile.ref_for(name)
    credential = credential_store.get(ref)
    if credential is None:
        raise ConfigurationError(
            f"profile {name!r} has no credential stored at {ref!r}. "
            f"Run 'vectra-mcp profile add {name}' to store one. "
            f"(The profile file holds no secrets by design, so this is the "
            f"expected state after copying profiles.yaml to a new machine.)"
        )

    return TenantConfig(
        # "default" keeps single-tenant registration unprefixed. The profile
        # name deliberately does NOT become the tenant name: that value is used
        # as an MCP tool-name prefix in multi-tenant mode, and letting a profile
        # name leak into it would make tool names differ between profiles —
        # the one thing the tool contract must never do.
        name="default",
        base_url=profile.base_url,
        client_id=credential.client_id,
        client_secret=credential.client_secret,
        api_version=profile.api_version,
        oauth_token_url_override=profile.oauth_token_url_override,
        request_timeout=profile.request_timeout,
        rate_limit_requests=profile.rate_limit_requests,
        rate_limit_period=profile.rate_limit_period,
        cache_ttl=profile.cache_ttl,
    )


def _server_config(tenant: TenantConfig) -> ServerConfiguration:
    return ServerConfiguration(
        tenants=[tenant],
        is_multi_tenant=False,
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        log_format=os.environ.get("LOG_FORMAT", "text").lower(),
        dev_mode=os.environ.get("DEV_MODE", "false").lower() == "true",
    )


def resolve(
    explicit_profile: Optional[str] = None,
    *,
    store: Optional[ProfileStore] = None,
    credential_store: Optional[CredentialStore] = None,
    warn_on_shadow: bool = True,
) -> Resolution:
    """Resolve configuration according to the precedence above."""
    store = store or ProfileStore()
    credential_store = credential_store or KeyringCredentialStore()

    env_profile = (os.environ.get(PROFILE_ENV) or "").strip() or None

    # ---- 1, 2, 3: a profile was selected somehow -------------------------
    name, source = None, None
    if explicit_profile:
        name, source = explicit_profile, SOURCE_EXPLICIT
    elif env_profile:
        name, source = env_profile, SOURCE_ENV_PROFILE
    else:
        active = store.active_name()
        if active:
            name, source = active, SOURCE_ACTIVE

    if name is not None:
        try:
            profile = store.get(name)
        except UnknownProfile as exc:
            # Deliberately not falling back to the environment. Asking for
            # tenant A and silently getting tenant B is worse than not
            # starting, and "it was configured but I typo'd the name" is the
            # most likely cause.
            raise ConfigurationError(
                f"{source} selected profile {name!r}, but {exc}"
            ) from exc

        shadowed = (SOURCE_ENVIRONMENT,) if _env_is_configured() else ()
        resolution = Resolution(
            server_config=_server_config(_tenant_from_profile(name, profile, credential_store)),
            source=source,
            profile_name=name,
            shadowed=shadowed,
        )
        if shadowed and warn_on_shadow:
            logger.warning(
                "Using %s (%s), which takes precedence over the %s that are "
                "also set (%s=%s). Unset them or run with --profile to make "
                "the choice explicit.",
                f"profile {name!r}", source, SOURCE_ENVIRONMENT,
                ENV_BASE_URL, os.environ.get(ENV_BASE_URL),
            )
        else:
            logger.info("Configuration: %s", resolution.describe())
        return resolution

    # ---- 4: the legacy environment path ---------------------------------
    if _env_is_configured():
        tenant = _tenant_config_from_vectra_config(VectraConfig())
        resolution = Resolution(
            server_config=_server_config(tenant),
            source=SOURCE_ENVIRONMENT,
        )
        logger.info("Configuration: %s", resolution.describe())
        return resolution

    # ---- 5: nothing usable ----------------------------------------------
    known = store.names()
    profiles_line = (
        f"Configured profiles: {', '.join(known)}. Select one with "
        f"'vectra-mcp profile use <name>'."
        if known else
        "No profiles are configured. Create one with 'vectra-mcp profile add <name>'."
    )
    raise ConfigurationError(
        "No Vectra tenant is configured. " + profiles_line + " Alternatively set "
        f"{ENV_BASE_URL}, {ENV_CLIENT_ID} and {ENV_CLIENT_SECRET} in the "
        "environment."
    )
