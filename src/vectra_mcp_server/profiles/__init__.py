"""Local named tenant profiles and secure credential storage.

A *profile* is a named Vectra tenant an operator can switch between from the
command line, so that changing customers does not mean editing an MCP client's
JSON configuration or keeping API secrets in it.

The package is deliberately narrow. It answers two questions —

    which tenant?      profiles.store
    with what secret?  profiles.credentials

— and nothing else. Tool behaviour, transports and the MCP contract live
elsewhere and do not know profiles exist; the only thing that connects them is
the ``client_provider`` seam in ``vectra_mcp_server.client_access``.
"""

from .credentials import (
    Credential,
    CredentialStore,
    CredentialStoreError,
    CredentialStoreReadOnly,
    CredentialStoreUnavailable,
    EnvCredentialStore,
    KeyringCredentialStore,
    default_credential_store,
)
from .resolver import ConfigurationError, Resolution, resolve
from .store import (
    Profile,
    ProfileFile,
    ProfileStore,
    ProfileStoreError,
    UnknownProfile,
    config_path,
)

__all__ = [
    "ConfigurationError",
    "Credential",
    "CredentialStore",
    "CredentialStoreError",
    "CredentialStoreReadOnly",
    "CredentialStoreUnavailable",
    "EnvCredentialStore",
    "KeyringCredentialStore",
    "Profile",
    "ProfileFile",
    "ProfileStore",
    "ProfileStoreError",
    "Resolution",
    "UnknownProfile",
    "config_path",
    "default_credential_store",
    "resolve",
]
