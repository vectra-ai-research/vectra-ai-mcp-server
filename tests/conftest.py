"""Shared fixtures for the profile tests.

Two things every test here needs and must never get from the developer's
machine: a credential store that is not the real OS keychain, and an
environment with no leftover VECTRA_* variables. `config.py` calls
`load_dotenv()` at import, so a stray `.env` in the checkout would otherwise
decide the outcome of a precedence test.

Nothing here is autouse. The ten pre-existing test files pass as they are, and
an autouse fixture that mutates the environment for the whole suite is exactly
the kind of action-at-a-distance that makes a later failure hard to place.
"""

from __future__ import annotations

from typing import Dict, Optional

import pytest

from vectra_mcp_server.profiles.credentials import Credential

#: Every variable that can influence tenant resolution.
CONFIG_ENV_VARS = (
    "VECTRA_PROFILE",
    "VECTRA_BASE_URL",
    "VECTRA_CLIENT_ID",
    "VECTRA_CLIENT_SECRET",
    "VECTRA_API_VERSION",
    "VECTRA_OAUTH_TOKEN_URL",
    "VECTRA_CONFIG_FILE",
    "VECTRA_MCP_CONFIG_DIR",
    "LOG_LEVEL",
    "LOG_FORMAT",
    "DEV_MODE",
)


class MemoryCredentialStore:
    """A CredentialStore that keeps everything in a dict."""

    def __init__(self, entries: Optional[Dict[str, Credential]] = None):
        self.entries: Dict[str, Credential] = dict(entries or {})

    def describe(self) -> str:
        return "in-memory (test)"

    def get(self, ref: str) -> Optional[Credential]:
        return self.entries.get(ref)

    def set(self, ref: str, credential: Credential) -> None:
        self.entries[ref] = credential

    def delete(self, ref: str) -> None:
        self.entries.pop(ref, None)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove every variable that could influence which tenant is resolved."""
    for name in CONFIG_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def credentials():
    return MemoryCredentialStore()


@pytest.fixture
def cred():
    return Credential(client_id="an-id", client_secret="a-secret")
