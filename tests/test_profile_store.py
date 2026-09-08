"""The profile file: round trips, the active pointer, and staying secret-free."""

from __future__ import annotations

import os
import stat

import pytest
import yaml

from vectra_mcp_server.profiles.store import (
    CONFIG_DIR_ENV,
    FILE_VERSION,
    Profile,
    ProfileFile,
    ProfileStore,
    ProfileStoreError,
    UnknownProfile,
    config_path,
    validate_profile_name,
)

ACME = Profile(base_url="https://acme.vectra.ai")
GLOBEX = Profile(base_url="https://globex.vectra.ai")


@pytest.fixture
def store(tmp_path):
    return ProfileStore(tmp_path / "profiles.yaml")


# ------------------------------------------------------------------ location

def test_config_dir_can_be_redirected(clean_env, tmp_path):
    clean_env.setenv(CONFIG_DIR_ENV, str(tmp_path / "elsewhere"))
    assert config_path() == tmp_path / "elsewhere" / "profiles.yaml"


def test_config_dir_expands_a_tilde(clean_env):
    clean_env.delenv(CONFIG_DIR_ENV, raising=False)
    assert "~" not in str(config_path())


# ------------------------------------------------------------------ round trip

def test_a_missing_file_is_an_empty_file_not_an_error(store):
    """Every new install is in this state, and the env path needs no file."""
    file = store.load()
    assert file.profiles == {}
    assert file.active is None


def test_add_then_get_round_trips(store):
    store.add("acme", ACME)
    assert store.get("acme").base_url == "https://acme.vectra.ai"


def test_the_first_profile_added_becomes_active(store):
    """Adding one profile and finding nothing selected is a puzzle, not a tool."""
    store.add("acme", ACME)
    assert store.active_name() == "acme"


def test_a_later_profile_does_not_steal_active(store):
    store.add("acme", ACME)
    store.add("globex", GLOBEX)
    assert store.active_name() == "acme"


def test_make_active_switches(store):
    store.add("acme", ACME)
    store.add("globex", GLOBEX, make_active=True)
    assert store.active_name() == "globex"


def test_set_active_switches(store):
    store.add("acme", ACME)
    store.add("globex", GLOBEX)
    store.set_active("globex")
    assert store.active_name() == "globex"


def test_names_are_sorted(store):
    store.add("globex", GLOBEX)
    store.add("acme", ACME)
    assert store.names() == ["acme", "globex"]


def test_remove_deletes_the_profile(store):
    store.add("acme", ACME)
    store.add("globex", GLOBEX)
    store.remove("acme")
    assert store.names() == ["globex"]


def test_removing_the_active_profile_clears_active_rather_than_reassigning(store):
    """No silent fall-through to a different customer's tenant."""
    store.add("acme", ACME)
    store.add("globex", GLOBEX)
    store.set_active("acme")
    store.remove("acme")
    assert store.active_name() is None


def test_the_file_survives_a_reopen(tmp_path):
    path = tmp_path / "profiles.yaml"
    ProfileStore(path).add("acme", ACME)
    assert ProfileStore(path).get("acme").base_url == "https://acme.vectra.ai"


def test_the_written_file_records_its_version(store):
    store.add("acme", ACME)
    assert yaml.safe_load(store.path.read_text())["version"] == FILE_VERSION


# ------------------------------------------------------------------ safety

def test_the_file_is_written_owner_only(store):
    store.add("acme", ACME)
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600


def test_no_temp_file_is_left_behind(store):
    """The write is atomic; a leftover .tmp means the rename path is broken."""
    store.add("acme", ACME)
    assert [p.name for p in store.path.parent.iterdir()] == ["profiles.yaml"]


@pytest.mark.parametrize("key", ["client_secret", "secret", "password", "token", "api_key"])
def test_a_hand_pasted_credential_is_refused_with_advice(store, key):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(yaml.safe_dump({
        "version": 1,
        "profiles": {"acme": {"base_url": "https://acme.vectra.ai", key: "oops"}},
    }))
    with pytest.raises(ProfileStoreError) as exc:
        store.load()
    message = str(exc.value)
    assert key in message
    assert "profile add" in message
    assert "rotate" in message, "an exposed secret needs rotating, not just removing"


def test_the_refusal_does_not_echo_the_secret(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(yaml.safe_dump({
        "version": 1,
        "profiles": {"acme": {"base_url": "https://acme.vectra.ai",
                              "client_secret": "sup3r-s3cret"}},
    }))
    with pytest.raises(ProfileStoreError) as exc:
        store.load()
    assert "sup3r-s3cret" not in str(exc.value)


def test_a_profile_cannot_hold_unknown_fields():
    with pytest.raises(Exception):
        Profile(base_url="https://acme.vectra.ai", surprise="value")


# ------------------------------------------------------------------ bad input

def test_malformed_yaml_names_the_file(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("profiles: [unclosed\n")
    with pytest.raises(ProfileStoreError) as exc:
        store.load()
    assert str(store.path) in str(exc.value)


def test_a_scalar_document_is_rejected(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("just a string\n")
    with pytest.raises(ProfileStoreError):
        store.load()


def test_an_unknown_profile_lists_the_known_ones(store):
    store.add("acme", ACME)
    store.add("globex", GLOBEX)
    with pytest.raises(UnknownProfile) as exc:
        store.get("initech")
    assert "acme" in str(exc.value) and "globex" in str(exc.value)


def test_an_unknown_profile_with_none_configured_says_how_to_create_one(store):
    with pytest.raises(UnknownProfile) as exc:
        store.get("acme")
    assert "profile add acme" in str(exc.value)


def test_removing_and_activating_an_unknown_profile_both_fail(store):
    with pytest.raises(UnknownProfile):
        store.remove("nope")
    with pytest.raises(UnknownProfile):
        store.set_active("nope")


# ------------------------------------------------------------------ names

@pytest.mark.parametrize("name", ["acme", "globex", "demo", "a", "cust-01", "a.b_c", "A1"])
def test_valid_profile_names(name):
    assert validate_profile_name(name) == name


@pytest.mark.parametrize("name", [
    "",
    "-leading",
    ".leading",
    "has space",
    "has/slash",      # would split a credential_ref
    "has:colon",
    "x" * 41,
])
def test_invalid_profile_names(name):
    with pytest.raises(ValueError):
        validate_profile_name(name)


def test_names_in_a_loaded_file_are_validated(store):
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(yaml.safe_dump({
        "version": 1,
        "profiles": {"has/slash": {"base_url": "https://x.vectra.ai"}},
    }))
    with pytest.raises(ProfileStoreError):
        store.load()


# ------------------------------------------------------------------ ref default

def test_credential_ref_defaults_to_the_profile_name():
    assert Profile(base_url="https://x.vectra.ai").ref_for("acme") == "vectra-mcp/acme"


def test_an_explicit_credential_ref_is_respected():
    profile = Profile(base_url="https://x.vectra.ai", credential_ref="other/place")
    assert profile.ref_for("acme") == "other/place"


# ------------------------------------------------------------------ normalising

def test_base_url_gets_a_scheme_and_loses_a_trailing_slash():
    assert Profile(base_url="acme.vectra.ai/").base_url == "https://acme.vectra.ai"


def test_an_unsupported_api_version_is_rejected():
    with pytest.raises(Exception):
        Profile(base_url="https://x.vectra.ai", api_version="v9")


def test_profile_file_defaults_are_empty():
    file = ProfileFile()
    assert file.version == FILE_VERSION and file.active is None and file.profiles == {}
