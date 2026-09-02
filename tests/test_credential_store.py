"""Credential storage, and the requirement that secrets stay unprintable.

Every test here runs against a fake `keyring` module injected into
`sys.modules`. Nothing touches the developer's real keychain — a test suite
that writes to the OS credential store is a test suite nobody can run twice.
"""

from __future__ import annotations

import json
import sys

import pytest

from vectra_mcp_server.profiles.credentials import (
    DEFAULT_SERVICE,
    ENV_CLIENT_ID,
    ENV_CLIENT_SECRET,
    Credential,
    CredentialStore,
    CredentialStoreError,
    CredentialStoreReadOnly,
    CredentialStoreUnavailable,
    EnvCredentialStore,
    KeyringCredentialStore,
    _split_ref,
)

SECRET = "sup3r-s3cret-v4lue"
CRED = Credential(client_id="an-id", client_secret=SECRET)


class PasswordDeleteError(Exception):
    """Named to match the real keyring error our delete() special-cases."""


class FakeKeyring:
    """Enough of the keyring API for the store to exercise, and no more."""

    PasswordDeleteError = PasswordDeleteError

    def __init__(self):
        self.entries: dict[tuple[str, str], str] = {}
        self.fail_with: Exception | None = None

    def _maybe_fail(self):
        if self.fail_with is not None:
            raise self.fail_with

    def get_password(self, service, username):
        self._maybe_fail()
        return self.entries.get((service, username))

    def set_password(self, service, username, password):
        self._maybe_fail()
        self.entries[(service, username)] = password

    def delete_password(self, service, username):
        self._maybe_fail()
        if (service, username) not in self.entries:
            raise PasswordDeleteError("no such password")
        del self.entries[(service, username)]

    def get_keyring(self):
        return self


@pytest.fixture
def fake(monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return kr


@pytest.fixture
def store(fake):
    return KeyringCredentialStore()


# ------------------------------------------------------- the credential itself

def test_repr_does_not_contain_the_secret():
    assert SECRET not in repr(CRED)
    assert "***" in repr(CRED)


def test_str_does_not_contain_the_secret():
    assert SECRET not in str(CRED)


def test_the_secret_survives_an_f_string_of_the_object():
    """The dangerous case: nobody chose to print it."""
    assert SECRET not in f"failed with {CRED}"


def test_client_id_stays_visible():
    """It is the only attribution in a log line, and it is not sensitive."""
    assert "an-id" in repr(CRED)


def test_an_incomplete_pair_is_rejected_at_construction():
    with pytest.raises(ValueError):
        Credential(client_id="an-id", client_secret="")
    with pytest.raises(ValueError):
        Credential(client_id="", client_secret=SECRET)


def test_the_protocol_is_satisfied_by_both_backends(fake):
    assert isinstance(KeyringCredentialStore(), CredentialStore)
    assert isinstance(EnvCredentialStore({}), CredentialStore)


# ------------------------------------------------------------------ round trip

def test_set_then_get_returns_the_same_credential(store):
    store.set("vectra-mcp/acme", CRED)
    assert store.get("vectra-mcp/acme") == CRED


def test_a_missing_credential_is_none_not_an_error(store):
    """"Not stored" and "cannot read the store" must stay distinguishable."""
    assert store.get("vectra-mcp/never-added") is None


def test_set_replaces_an_existing_entry(store):
    store.set("vectra-mcp/acme", CRED)
    replacement = Credential(client_id="new-id", client_secret="new-secret")
    store.set("vectra-mcp/acme", replacement)
    assert store.get("vectra-mcp/acme") == replacement


def test_delete_removes_the_entry(store):
    store.set("vectra-mcp/acme", CRED)
    store.delete("vectra-mcp/acme")
    assert store.get("vectra-mcp/acme") is None


def test_deleting_something_absent_is_not_an_error(store):
    """`profile remove` has to be able to clean up a half-created profile."""
    store.delete("vectra-mcp/never-added")


def test_profiles_are_isolated_from_each_other(store):
    other = Credential(client_id="globex-id", client_secret="globex-secret")
    store.set("vectra-mcp/acme", CRED)
    store.set("vectra-mcp/globex", other)
    assert store.get("vectra-mcp/acme") == CRED
    assert store.get("vectra-mcp/globex") == other


def test_both_halves_of_the_pair_are_in_the_keychain(store, fake):
    """The profile file must be provably free of credential material."""
    store.set("vectra-mcp/acme", CRED)
    stored = json.loads(fake.entries[("vectra-mcp", "acme")])
    assert stored == {"client_id": "an-id", "client_secret": SECRET}


# ------------------------------------------------------------------ ref parsing

@pytest.mark.parametrize("ref,expected", [
    ("vectra-mcp/acme", ("vectra-mcp", "acme")),
    ("acme", (DEFAULT_SERVICE, "acme")),
    ("custom-service/name-with-dashes", ("custom-service", "name-with-dashes")),
])
def test_ref_parsing(ref, expected):
    assert _split_ref(ref) == expected


@pytest.mark.parametrize("ref", ["", "/acme", "vectra-mcp/"])
def test_malformed_refs_are_rejected(ref):
    with pytest.raises(ValueError):
        _split_ref(ref)


# ------------------------------------------------------------- degrading well

def test_a_locked_or_broken_keychain_raises_unavailable(store, fake):
    fake.fail_with = RuntimeError("the keyring is locked")
    with pytest.raises(CredentialStoreUnavailable) as exc:
        store.get("vectra-mcp/acme")
    assert "acme" in str(exc.value), "the operator needs to know which profile failed"


def test_a_missing_keyring_package_explains_the_alternative(monkeypatch):
    """An env-var user must never be forced to care that keyring exists.

    ``None`` in ``sys.modules`` is how CPython represents "this import is
    blocked" — ``import keyring`` then raises ImportError. Cheaper and far less
    invasive than patching ``builtins.__import__``, which would affect every
    import pytest itself makes while the patch is live.
    """
    monkeypatch.setitem(sys.modules, "keyring", None)

    with pytest.raises(CredentialStoreUnavailable) as exc:
        KeyringCredentialStore().get("vectra-mcp/acme")
    assert ENV_CLIENT_ID in str(exc.value)


def test_a_corrupt_entry_does_not_quote_itself(store, fake):
    """The value we failed to parse is still a secret."""
    fake.entries[("vectra-mcp", "acme")] = SECRET  # not JSON
    with pytest.raises(CredentialStoreError) as exc:
        store.get("vectra-mcp/acme")
    assert SECRET not in str(exc.value)


def test_an_entry_missing_a_field_is_reported_without_the_value(store, fake):
    fake.entries[("vectra-mcp", "acme")] = json.dumps({"client_secret": SECRET})
    with pytest.raises(CredentialStoreError) as exc:
        store.get("vectra-mcp/acme")
    assert SECRET not in str(exc.value)


def test_describe_never_raises_even_when_the_backend_is_broken(store, fake):
    fake.fail_with = RuntimeError("boom")
    assert isinstance(store.describe(), str)


# ------------------------------------------------------------ the legacy path

def test_env_store_reads_the_legacy_variables():
    env = {ENV_CLIENT_ID: "an-id", ENV_CLIENT_SECRET: SECRET}
    assert EnvCredentialStore(env).get() == CRED


@pytest.mark.parametrize("env", [
    {},
    {ENV_CLIENT_ID: "an-id"},
    {ENV_CLIENT_SECRET: SECRET},
    {ENV_CLIENT_ID: "", ENV_CLIENT_SECRET: SECRET},
])
def test_env_store_returns_none_when_incompletely_configured(env):
    assert EnvCredentialStore(env).get() is None


def test_env_store_refuses_writes_rather_than_ignoring_them():
    with pytest.raises(CredentialStoreReadOnly):
        EnvCredentialStore({}).set("anything", CRED)
    with pytest.raises(CredentialStoreReadOnly):
        EnvCredentialStore({}).delete("anything")


def test_env_store_write_error_points_at_the_cli():
    with pytest.raises(CredentialStoreReadOnly) as exc:
        EnvCredentialStore({}).set("anything", CRED)
    assert "profile add" in str(exc.value)
