"""Which tenant a run talks to, and why.

The proof the brief asks for is at the bottom: same build, same tools, same
prompt — profile A reaches tenant A and profile B reaches tenant B, with no
source or tool definition differing between the two runs.
"""

from __future__ import annotations

import pytest

from vectra_mcp_server.profiles.credentials import Credential
from vectra_mcp_server.profiles.resolver import (
    SOURCE_ACTIVE,
    SOURCE_ENV_PROFILE,
    SOURCE_ENVIRONMENT,
    SOURCE_EXPLICIT,
    ConfigurationError,
    resolve,
)
from vectra_mcp_server.profiles.store import Profile, ProfileStore

ACME_CRED = Credential(client_id="acme-id", client_secret="acme-secret")
GLOBEX_CRED = Credential(client_id="globex-id", client_secret="globex-secret")


@pytest.fixture
def two_profiles(tmp_path, credentials):
    """acme active, globex configured, both with credentials stored."""
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    store.add("globex", Profile(base_url="https://globex.vectra.ai"))
    store.set_active("acme")
    credentials.set("vectra-mcp/acme", ACME_CRED)
    credentials.set("vectra-mcp/globex", GLOBEX_CRED)
    return store


def resolved(store, credentials, explicit=None):
    return resolve(explicit, store=store, credential_store=credentials)


def set_legacy_env(env, base_url="https://legacy.vectra.ai"):
    env.setenv("VECTRA_BASE_URL", base_url)
    env.setenv("VECTRA_CLIENT_ID", "legacy-id")
    env.setenv("VECTRA_CLIENT_SECRET", "legacy-secret")


# ---------------------------------------------------------------- precedence

def test_explicit_profile_wins(clean_env, two_profiles, credentials):
    clean_env.setenv("VECTRA_PROFILE", "acme")
    set_legacy_env(clean_env)
    r = resolved(two_profiles, credentials, explicit="globex")
    assert r.base_url == "https://globex.vectra.ai"
    assert r.source == SOURCE_EXPLICIT


def test_env_profile_beats_the_active_profile(clean_env, two_profiles, credentials):
    clean_env.setenv("VECTRA_PROFILE", "globex")
    r = resolved(two_profiles, credentials)
    assert r.base_url == "https://globex.vectra.ai"
    assert r.source == SOURCE_ENV_PROFILE


def test_the_active_profile_is_used_when_nothing_else_selects_one(clean_env, two_profiles, credentials):
    r = resolved(two_profiles, credentials)
    assert r.base_url == "https://acme.vectra.ai"
    assert r.source == SOURCE_ACTIVE


def test_a_profile_beats_the_legacy_environment(clean_env, two_profiles, credentials):
    set_legacy_env(clean_env)
    r = resolved(two_profiles, credentials)
    assert r.base_url == "https://acme.vectra.ai"
    assert r.shadowed == (SOURCE_ENVIRONMENT,), "the loser must be recorded"


def test_an_empty_vectra_profile_is_ignored_not_obeyed(clean_env, two_profiles, credentials):
    """An exported-but-blank variable is a common shell accident."""
    clean_env.setenv("VECTRA_PROFILE", "   ")
    assert resolved(two_profiles, credentials).source == SOURCE_ACTIVE


# ------------------------------------------------------- the legacy path holds

def test_environment_only_configuration_still_works(clean_env, tmp_path, credentials):
    """The path every existing deployment uses. No profile file at all."""
    set_legacy_env(clean_env)
    store = ProfileStore(tmp_path / "does-not-exist.yaml")
    r = resolved(store, credentials)
    assert r.base_url == "https://legacy.vectra.ai"
    assert r.source == SOURCE_ENVIRONMENT
    assert r.profile_name is None
    assert r.shadowed == ()


def test_environment_configuration_carries_the_credential_through(clean_env, tmp_path, credentials):
    set_legacy_env(clean_env)
    store = ProfileStore(tmp_path / "none.yaml")
    tenant = resolved(store, credentials).server_config.tenants[0]
    assert (tenant.client_id, tenant.client_secret) == ("legacy-id", "legacy-secret")


def test_a_profile_file_with_no_active_profile_falls_through_to_the_environment(
    clean_env, tmp_path, credentials
):
    set_legacy_env(clean_env)
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    store.remove("acme")  # leaves a file with profiles: {} and active: None
    assert resolved(store, credentials).source == SOURCE_ENVIRONMENT


@pytest.mark.parametrize("missing", ["VECTRA_BASE_URL", "VECTRA_CLIENT_ID", "VECTRA_CLIENT_SECRET"])
def test_partial_environment_configuration_does_not_count(clean_env, tmp_path, credentials, missing):
    """Two of three variables is a mistake, not a configuration."""
    set_legacy_env(clean_env)
    clean_env.delenv(missing)
    store = ProfileStore(tmp_path / "none.yaml")
    with pytest.raises(ConfigurationError):
        resolved(store, credentials)


# ------------------------------------------------------------------- failures

def test_nothing_configured_lists_every_option(clean_env, tmp_path, credentials):
    store = ProfileStore(tmp_path / "none.yaml")
    with pytest.raises(ConfigurationError) as exc:
        resolved(store, credentials)
    message = str(exc.value)
    assert "profile add" in message
    assert "VECTRA_BASE_URL" in message


def test_nothing_active_but_profiles_exist_names_them(clean_env, tmp_path, credentials):
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    store.add("globex", Profile(base_url="https://globex.vectra.ai"))
    store.set_active("acme")
    store.remove("acme")
    with pytest.raises(ConfigurationError) as exc:
        resolved(store, credentials)
    assert "globex" in str(exc.value)
    assert "profile use" in str(exc.value)


def test_a_named_profile_that_does_not_exist_is_an_error_not_a_fallback(
    clean_env, two_profiles, credentials
):
    """Asking for tenant A and silently getting tenant B is worse than not starting."""
    set_legacy_env(clean_env)
    with pytest.raises(ConfigurationError) as exc:
        resolved(two_profiles, credentials, explicit="initech")
    assert "initech" in str(exc.value)


def test_a_typo_in_vectra_profile_does_not_fall_back_either(clean_env, two_profiles, credentials):
    set_legacy_env(clean_env)
    clean_env.setenv("VECTRA_PROFILE", "acmee")
    with pytest.raises(ConfigurationError):
        resolved(two_profiles, credentials)


def test_a_profile_with_no_stored_credential_explains_the_fix(clean_env, tmp_path, credentials):
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    with pytest.raises(ConfigurationError) as exc:
        resolved(store, credentials)
    message = str(exc.value)
    assert "profile add acme" in message
    assert "vectra-mcp/acme" in message


def test_an_invalid_base_url_is_rejected_when_the_profile_is_created():
    with pytest.raises(Exception):
        Profile(base_url="")


# --------------------------------------------------------------- provenance

def test_the_resolution_describes_itself_without_the_secret(clean_env, two_profiles, credentials):
    r = resolved(two_profiles, credentials)
    described = r.describe()
    assert "acme" in described and "https://acme.vectra.ai" in described
    assert ACME_CRED.client_secret not in described


def test_client_id_is_available_for_attribution(clean_env, two_profiles, credentials):
    assert resolved(two_profiles, credentials).client_id == "acme-id"


def test_a_profile_resolves_to_single_tenant_unprefixed_registration(
    clean_env, two_profiles, credentials
):
    """A profile selects a tenant; it must not turn on multi-tenant mode.

    Multi-tenant mode prefixes every tool name with the tenant name, which
    would make the tool contract differ between profiles — the one thing it
    must never do.
    """
    config = resolved(two_profiles, credentials).server_config
    assert config.is_multi_tenant is False
    assert len(config.tenants) == 1
    assert config.tenants[0].name == "default"


def test_the_profile_name_does_not_leak_into_the_tenant_name(clean_env, two_profiles, credentials):
    for name in ("acme", "globex"):
        tenant = resolved(two_profiles, credentials, explicit=name).server_config.tenants[0]
        assert tenant.name == "default", "tenant name is a tool-name prefix; it must be stable"


# ------------------------------------------------- the claim the brief makes

def test_switching_the_active_profile_changes_the_tenant(clean_env, two_profiles, credentials):
    """Same build, same tools, same call — different tenant.

        profile A -> tenant A
        profile B -> tenant B

    with nothing changed but the active pointer.
    """
    first = resolved(two_profiles, credentials)
    two_profiles.set_active("globex")
    second = resolved(two_profiles, credentials)

    assert first.base_url == "https://acme.vectra.ai"
    assert second.base_url == "https://globex.vectra.ai"

    assert first.server_config.tenants[0].client_id == "acme-id"
    assert second.server_config.tenants[0].client_id == "globex-id"

    # And the thing that must NOT change:
    assert first.server_config.is_multi_tenant == second.server_config.is_multi_tenant
    assert first.server_config.tenants[0].name == second.server_config.tenants[0].name


def test_each_profile_uses_its_own_credential(clean_env, two_profiles, credentials):
    """A shared or leaked credential across profiles would be invisible in the
    audit trail, since Vectra records the API client and not the analyst."""
    acme = resolved(two_profiles, credentials, explicit="acme").server_config.tenants[0]
    globex = resolved(two_profiles, credentials, explicit="globex").server_config.tenants[0]
    assert acme.client_secret != globex.client_secret
