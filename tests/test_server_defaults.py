"""Bind address and log format are both security-relevant defaults.

`--host` defaulted to 0.0.0.0, and neither HTTP transport authenticates its
callers, so the default published an unauthenticated proxy for the tenant's
Vectra credentials to the whole local network. It now defaults to loopback.

`LOG_FORMAT` was validated by the config layer and then never passed to
setup_logging(), so `LOG_FORMAT=json` produced text with no warning. It is now
wired, and the config default was corrected from "json" to "text" to match the
behaviour every release has actually had — otherwise wiring it up would have
flipped the log format of every existing deployment on upgrade.
"""

import sys
from unittest.mock import MagicMock

import pytest

from vectra_mcp_server import server as server_mod
from vectra_mcp_server.config import ServerConfiguration, TenantConfig, VectraConfig
from vectra_mcp_server.profiles.resolver import Resolution

HOST_ENV = "VECTRA_MCP_HOST"


# ---------------------------------------------------------------- bind address

@pytest.fixture
def argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vectra-ai-mcp-server"])
    monkeypatch.delenv(HOST_ENV, raising=False)


def test_host_defaults_to_loopback(argv):
    assert server_mod.parse_args().host == "127.0.0.1"


def test_host_env_override_still_works(argv, monkeypatch):
    """Binding wide stays possible — it just has to be asked for."""
    monkeypatch.setenv(HOST_ENV, "0.0.0.0")
    assert server_mod.parse_args().host == "0.0.0.0"


def test_host_flag_beats_the_env(monkeypatch):
    monkeypatch.setenv(HOST_ENV, "0.0.0.0")
    monkeypatch.setattr(sys, "argv", ["vectra-ai-mcp-server", "--host", "10.0.0.5"])
    assert server_mod.parse_args().host == "10.0.0.5"


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost", "LOCALHOST"])
def test_loopback_addresses_are_recognised(host):
    assert server_mod._is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "192.168.1.20", "::", "example.com", ""])
def test_non_loopback_addresses_are_recognised(host):
    assert server_mod._is_loopback(host) is False


def test_an_unparseable_host_is_treated_as_exposed():
    """Fail towards the warning. A spurious warning costs a line of output; a
    missing one costs the credentials."""
    assert server_mod._is_loopback("not a host!!") is False


# ---------------------------------------------------------------- log format

@pytest.fixture
def built(monkeypatch):
    """Construct the server with the outside world stubbed, and report what
    setup_logging() was called with."""
    captured = {}

    def fake_setup_logging(**kwargs):
        captured.update(kwargs)

    tenant = TenantConfig(
        name="default",
        base_url="https://tenant.vectra.ai",
        client_id="an-id",
        client_secret="a-secret",
    )
    config = ServerConfiguration(tenants=[tenant], is_multi_tenant=False)

    monkeypatch.setattr(server_mod, "setup_logging", fake_setup_logging)
    monkeypatch.setattr(server_mod, "VectraClient", lambda *a, **k: MagicMock())

    # `resolve`, not `load_configuration`. Single-tenant configuration now
    # comes from the profile/environment precedence chain, and leaving this
    # patching load_configuration would have let the real resolver run — which
    # reads the developer's profile file and can prompt their OS keychain.
    monkeypatch.setattr(
        server_mod, "resolve",
        lambda *a, **k: Resolution(server_config=config, source="test"),
    )

    def build():
        server_mod.VectraMCPServer()
        return captured

    return build


def test_log_format_is_actually_passed_through(built, monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "json")
    assert built()["json_format"] is True


def test_text_is_the_default_so_upgrades_do_not_change_output(built, monkeypatch):
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    assert built()["json_format"] is False


@pytest.mark.parametrize("value", [" JSON ", "Json", "json"])
def test_log_format_is_case_and_whitespace_tolerant(built, monkeypatch, value):
    monkeypatch.setenv("LOG_FORMAT", value)
    assert built()["json_format"] is True


def test_an_unrecognised_log_format_falls_back_to_text(built, monkeypatch):
    """The config layer validates and rejects; this path only has to be safe."""
    monkeypatch.setenv("LOG_FORMAT", "xml")
    assert built()["json_format"] is False


def test_config_default_matches_the_wiring(monkeypatch):
    """The declared default and the shipped behaviour must not diverge again."""
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    monkeypatch.setenv("VECTRA_BASE_URL", "https://tenant.vectra.ai")
    monkeypatch.setenv("VECTRA_CLIENT_ID", "an-id")
    monkeypatch.setenv("VECTRA_CLIENT_SECRET", "a-secret")
    assert VectraConfig().log_format == "text"
