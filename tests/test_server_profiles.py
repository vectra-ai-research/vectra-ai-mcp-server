"""The server end of profiles: precedence, pinning, and the tool surface.

Every test builds a real ``VectraMCPServer`` with only two things stubbed —
``VectraClient`` (so nothing authenticates) and the keychain (so nothing
touches the developer's real credentials). The profile file is genuine, in a
temp directory, reached through ``VECTRA_MCP_CONFIG_DIR`` exactly as an
operator's would be.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest
import yaml
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server import server as server_mod
from vectra_mcp_server.profiles import resolver as resolver_mod
from vectra_mcp_server.profiles.credentials import Credential
from vectra_mcp_server.profiles.provider import FOLLOW_ENV
from vectra_mcp_server.profiles.store import CONFIG_DIR_ENV, Profile, ProfileStore
from vectra_mcp_server.registry import TOOL_CLASSES

ACME = Credential(client_id="acme-id", client_secret="acme-secret")
GLOBEX = Credential(client_id="globex-id", client_secret="globex-secret")


@pytest.fixture
def built_clients():
    """Records every configuration a client was built for."""
    return []


@pytest.fixture
def env(clean_env, tmp_path, credentials, built_clients, monkeypatch):
    """A server-shaped world: temp profile dir, fake keychain, no real client."""
    clean_env.setenv(CONFIG_DIR_ENV, str(tmp_path))
    monkeypatch.setattr(resolver_mod, "KeyringCredentialStore", lambda: credentials)

    def fake_client(config):
        built_clients.append(config)
        return MagicMock()

    monkeypatch.setattr(server_mod, "VectraClient", fake_client)
    monkeypatch.setattr(server_mod, "setup_logging", lambda **kw: None)
    return clean_env


@pytest.fixture
def store(tmp_path):
    return ProfileStore(tmp_path / "profiles.yaml")


@pytest.fixture
def two(store, credentials):
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    store.add("globex", Profile(base_url="https://globex.vectra.ai"))
    store.set_active("acme")
    credentials.set("vectra-mcp/acme", ACME)
    credentials.set("vectra-mcp/globex", GLOBEX)
    return store


def tools_of(server):
    return {t.name: t for t in server.server._tool_manager.list_tools()}


def baseline_tool_count():
    """How many tools the tool classes register, independent of the server."""
    probe = FastMCP(name="probe")
    for cls in TOOL_CLASSES:
        cls(probe, client=MagicMock()).register_tools()
    return len(probe._tool_manager.list_tools())


def set_legacy_env(env, base_url="https://legacy.vectra.ai"):
    env.setenv("VECTRA_BASE_URL", base_url)
    env.setenv("VECTRA_CLIENT_ID", "legacy-id")
    env.setenv("VECTRA_CLIENT_SECRET", "legacy-secret")


def active_url(server):
    return server.resolution.base_url


# ------------------------------------------------------------------- the flag

def test_profile_flag_exists(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vectra-ai-mcp-server", "--profile", "acme"])
    assert server_mod.parse_args().profile == "acme"


def test_profile_defaults_to_none_rather_than_reading_the_env(monkeypatch):
    """VECTRA_PROFILE is the resolver's job, one rank below the flag.

    Wiring it in as an argparse default would collapse two precedence levels
    into one and make the shadow warning report the wrong source.
    """
    monkeypatch.setenv("VECTRA_PROFILE", "acme")
    monkeypatch.setattr(sys, "argv", ["vectra-ai-mcp-server"])
    assert server_mod.parse_args().profile is None


def test_profile_and_config_together_are_refused(env, two, tmp_path):
    yaml_path = tmp_path / "tenants.yaml"
    yaml_path.write_text(yaml.safe_dump({"tenants": [
        {"name": "prod", "base_url": "https://p.vectra.ai",
         "client_id": "i", "client_secret": "s"},
    ]}))
    with pytest.raises(ValueError) as exc:
        server_mod.VectraMCPServer(config_file=str(yaml_path), profile="acme")
    assert "mutually exclusive" in str(exc.value)


# ---------------------------------------------------------------- precedence

def test_the_active_profile_is_used_by_default(env, two):
    server = server_mod.VectraMCPServer()
    assert active_url(server) == "https://acme.vectra.ai"


def test_an_explicit_profile_overrides_the_active_one(env, two):
    server = server_mod.VectraMCPServer(profile="globex")
    assert active_url(server) == "https://globex.vectra.ai"


def test_vectra_profile_is_honoured(env, two):
    env.setenv("VECTRA_PROFILE", "globex")
    assert active_url(server_mod.VectraMCPServer()) == "https://globex.vectra.ai"


def test_the_flag_beats_the_environment_variable(env, two):
    env.setenv("VECTRA_PROFILE", "globex")
    assert active_url(server_mod.VectraMCPServer(profile="acme")) == "https://acme.vectra.ai"


def test_legacy_environment_configuration_still_starts_the_server(env):
    """No profile file at all — the path every existing deployment uses."""
    set_legacy_env(env)
    server = server_mod.VectraMCPServer()
    assert active_url(server) == "https://legacy.vectra.ai"
    assert server.resolution.profile_name is None


def test_nothing_configured_raises_a_configuration_error(env):
    with pytest.raises(resolver_mod.ConfigurationError):
        server_mod.VectraMCPServer()


# -------------------------------------------------------------------- laziness

def test_no_client_is_built_while_registering_tools(env, two, built_clients):
    """Registration must not authenticate.

    It is what allows the tool list to be served with a broken credential, and
    what makes re-resolution possible at all.
    """
    server_mod.VectraMCPServer()
    assert built_clients == []


def test_the_client_appears_on_first_use_and_is_reused(env, two, built_clients):
    server = server_mod.VectraMCPServer()
    first = server.client_provider()
    second = server.client_provider()
    assert len(built_clients) == 1
    assert first is second


# --------------------------------------------------------------------- pinning

def test_pinned_is_the_default(env, two):
    server = server_mod.VectraMCPServer()
    assert server.follow_active is False
    server.client_provider()

    two.set_active("globex")
    assert server.client_provider.resolution.base_url == "https://acme.vectra.ai", \
        "a pinned server must not change tenant underneath a conversation"


def test_follow_active_switches_on_the_next_call(env, two):
    env.setenv(FOLLOW_ENV, "true")
    server = server_mod.VectraMCPServer()
    assert server.follow_active is True
    server.client_provider()

    two.set_active("globex")
    server.client_provider()
    assert server.client_provider.resolution.base_url == "https://globex.vectra.ai"


def test_an_explicitly_pinned_profile_ignores_the_active_pointer_even_when_following(
    env, two
):
    """The property that makes one-connector-per-tenant safe.

    Two server processes can share one active pointer, each pinned with
    --profile or VECTRA_PROFILE, and `profile use` cannot drag either onto the
    other's tenant.
    """
    env.setenv(FOLLOW_ENV, "true")
    server = server_mod.VectraMCPServer(profile="acme")
    server.client_provider()

    two.set_active("globex")
    server.client_provider()
    assert server.client_provider.resolution.base_url == "https://acme.vectra.ai"


def test_vectra_profile_also_survives_a_switch_while_following(env, two):
    env.setenv(FOLLOW_ENV, "true")
    env.setenv("VECTRA_PROFILE", "globex")
    server = server_mod.VectraMCPServer()
    server.client_provider()

    two.set_active("acme")
    server.client_provider()
    assert server.client_provider.resolution.base_url == "https://globex.vectra.ai"


def test_each_profile_gets_its_own_credential_when_following(env, two, built_clients):
    env.setenv(FOLLOW_ENV, "true")
    server = server_mod.VectraMCPServer()
    server.client_provider()
    two.set_active("globex")
    server.client_provider()

    # VectraClient is what is patched, so what was recorded is the VectraConfig
    # handed to it, not the ServerConfiguration one level up.
    seen = [c.client_id for c in built_clients]
    assert seen == ["acme-id", "globex-id"]


# ------------------------------------------------------------- the tool surface

def test_tools_are_registered_unprefixed(env, two):
    names = tools_of(server_mod.VectraMCPServer())
    assert "list_entities" in names
    assert not any(n.startswith("acme_") for n in names)


def test_the_only_added_tool_is_get_active_profile(env, two):
    """Pinned against a baseline rather than a hardcoded number, so this test
    cannot drift out of agreement with the tool classes."""
    names = tools_of(server_mod.VectraMCPServer())
    assert "get_active_profile" in names
    assert len(names) == baseline_tool_count() + 1


def test_there_is_no_tool_that_can_change_the_tenant(env, two):
    """The model reports the tenant; it must never select one."""
    names = tools_of(server_mod.VectraMCPServer())
    for forbidden in ("set_tenant", "set_api_key", "change_profile", "use_profile",
                      "set_active_profile", "switch_tenant"):
        assert forbidden not in names


def test_get_active_profile_is_read_only(env, two):
    tool = tools_of(server_mod.VectraMCPServer())["get_active_profile"]
    assert tool.annotations.readOnlyHint is True


async def test_get_active_profile_reports_the_resolved_tenant(env, two):
    server = server_mod.VectraMCPServer()
    result = await server.server._tool_manager.call_tool("get_active_profile", {})
    payload = json.loads(result if isinstance(result, str) else result[0].text)

    assert payload["profile"] == "acme"
    assert payload["base_url"] == "https://acme.vectra.ai"
    assert payload["client_id"] == "acme-id"
    assert payload["follows_active_profile"] is False


async def test_get_active_profile_never_reports_the_secret(env, two):
    server = server_mod.VectraMCPServer()
    result = await server.server._tool_manager.call_tool("get_active_profile", {})
    text = result if isinstance(result, str) else result[0].text
    assert ACME.client_secret not in text


async def test_get_active_profile_names_the_environment_when_there_is_no_profile(env):
    set_legacy_env(env)
    server = server_mod.VectraMCPServer()
    result = await server.server._tool_manager.call_tool("get_active_profile", {})
    payload = json.loads(result if isinstance(result, str) else result[0].text)

    assert payload["profile"] is None
    assert "environment" in payload["configured_by"]


# ------------------------------------------------------- multi-tenant is intact

@pytest.fixture
def tenants_yaml(tmp_path):
    path = tmp_path / "tenants.yaml"
    path.write_text(yaml.safe_dump({"tenants": [
        {"name": "prod", "base_url": "https://prod.vectra.ai",
         "client_id": "p-id", "client_secret": "p-secret"},
        {"name": "lab", "base_url": "https://lab.vectra.ai",
         "client_id": "l-id", "client_secret": "l-secret"},
    ]}))
    return path


def test_multi_tenant_mode_still_prefixes_and_still_lists_tenants(env, tenants_yaml):
    names = tools_of(server_mod.VectraMCPServer(config_file=str(tenants_yaml)))
    assert "list_tenants" in names
    assert "prod_list_entities" in names and "lab_list_entities" in names


def test_multi_tenant_mode_does_not_gain_get_active_profile(env, tenants_yaml):
    """There is no single active profile in that mode, so the tool would lie."""
    names = tools_of(server_mod.VectraMCPServer(config_file=str(tenants_yaml)))
    assert "get_active_profile" not in names


def test_multi_tenant_mode_builds_its_clients_eagerly_as_before(env, tenants_yaml, built_clients):
    """Unchanged behaviour: prefixed registration binds a fixed client per tenant."""
    server_mod.VectraMCPServer(config_file=str(tenants_yaml))
    assert len(built_clients) == 2


def test_the_config_file_env_var_still_selects_multi_tenant_mode(env, tenants_yaml):
    env.setenv("VECTRA_CONFIG_FILE", str(tenants_yaml))
    names = tools_of(server_mod.VectraMCPServer())
    assert "list_tenants" in names
