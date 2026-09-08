"""Where a profile's Vectra API secret actually lives.

The problem this solves
-----------------------
Today an operator's `claude_desktop_config.json` carries the tenant's
`VECTRA_CLIENT_SECRET` in clear text, in a file that is world-readable in the
user's home directory, gets copied between machines, and ends up pasted into
support threads and screen shares. Moving the secret into the OS keychain
removes it from every one of those paths.

What is stored where
--------------------
::

    profiles.yaml                       OS keychain
    ─────────────                       ───────────
    name: acme                          service  "vectra-mcp"
    base_url: https://acme…             username "acme"
    credential_ref: vectra-mcp/acme ──▶ password {"client_id": …,
                                                  "client_secret": …}

**Both** halves of the OAuth2 pair go into the keychain, not just the secret.
`client_id` is not itself sensitive — and is deliberately left visible in logs,
because it is the only thing that says *which* API client acted. But keeping it
out of the profile file means the file provably contains no credential
material at all, which is a much easier thing to tell a customer than "it
contains half of one".

Scope
-----
Two backends, one protocol, no plugin system, no encryption of our own, no
secret rotation. Per the brief: not a general secrets-management platform.
`keyring` handles the platform differences — macOS Keychain, Windows Credential
Manager, SecretService on Linux — and any future backend implements the
protocol below.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

#: The keychain service used when a ref does not name one.
DEFAULT_SERVICE = "vectra-mcp"

#: Legacy environment variables. Still fully supported: an operator who
#: configures the server this way must keep working untouched.
ENV_CLIENT_ID = "VECTRA_CLIENT_ID"
ENV_CLIENT_SECRET = "VECTRA_CLIENT_SECRET"


class CredentialStoreError(Exception):
    """Base class for credential store failures."""


class CredentialStoreUnavailable(CredentialStoreError):
    """The backing store could not be reached.

    Distinct from "the credential is not there" — which is a ``None`` return,
    not an exception. A locked keychain, a missing backend and an absent
    profile are three different problems needing three different answers, and
    collapsing them is how an operator ends up re-entering a credential that
    was already stored correctly.
    """


class CredentialStoreReadOnly(CredentialStoreError):
    """The store cannot be written to (the environment provider, for example)."""


@dataclass(frozen=True, repr=False)
class Credential:
    """An OAuth2 client-credentials pair.

    ``repr`` and ``str`` are overridden, and that is the entire point of this
    class existing rather than passing a tuple around. A dataclass's generated
    repr prints every field, and the places a value gets printed without anyone
    deciding to print it are exactly the dangerous ones: an unhandled exception
    rendering its arguments, a debugger, ``logger.debug("%s", cred)``, a
    pydantic validation error quoting the input it rejected.
    """

    client_id: str
    client_secret: str

    def __repr__(self) -> str:
        return f"Credential(client_id={self.client_id!r}, client_secret='***')"

    __str__ = __repr__

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret:
            raise ValueError("both client_id and client_secret are required")


@runtime_checkable
class CredentialStore(Protocol):
    """Somewhere a credential can be kept, keyed by an opaque reference."""

    def get(self, ref: str) -> Optional[Credential]:
        """Return the credential at *ref*, or ``None`` if it is not stored.

        Raises:
            CredentialStoreUnavailable: the store itself could not be read.
        """

    def set(self, ref: str, credential: Credential) -> None:
        """Store *credential* at *ref*, replacing anything already there."""

    def delete(self, ref: str) -> None:
        """Remove the credential at *ref*. Absent is not an error."""

    def describe(self) -> str:
        """One short line naming this store, for diagnostics and errors."""


def _split_ref(ref: str) -> tuple[str, str]:
    """``"vectra-mcp/acme"`` -> ``("vectra-mcp", "acme")``; ``"acme"`` -> default service.

    The two-part form is what appears in the profile file, so that an operator
    reading it can find the matching entry in Keychain Access by name.
    """
    if not ref:
        raise ValueError("credential_ref must not be empty")
    if "/" in ref:
        service, _, username = ref.partition("/")
        if not service or not username:
            raise ValueError(f"malformed credential_ref: {ref!r}")
        return service, username
    return DEFAULT_SERVICE, ref


class KeyringCredentialStore:
    """The OS keychain, via the ``keyring`` package.

    ``keyring`` is imported lazily inside each method rather than at module
    import. Importing it eagerly would make the whole server — including
    ``--help`` and the env-var path that has always worked — fail to start on a
    machine with no usable keychain backend. A profile user needs the keychain;
    an env-var user must never be made to care that it exists.
    """

    def describe(self) -> str:
        try:
            keyring = self._keyring()
        except CredentialStoreUnavailable as exc:
            return f"OS keychain (unavailable: {exc})"
        try:
            backend = type(keyring.get_keyring()).__name__
        except Exception:  # pragma: no cover - diagnostics must not raise
            backend = "unknown backend"
        return f"OS keychain ({backend})"

    @staticmethod
    def _keyring():
        try:
            import keyring  # noqa: PLC0415 - deliberately lazy, see class docstring
        except ImportError as exc:
            raise CredentialStoreUnavailable(
                "the 'keyring' package is not installed, so profile "
                "credentials cannot be read. Install it, or configure the "
                f"server with {ENV_CLIENT_ID} / {ENV_CLIENT_SECRET} instead."
            ) from exc
        return keyring

    def get(self, ref: str) -> Optional[Credential]:
        keyring = self._keyring()
        service, username = _split_ref(ref)
        try:
            raw = keyring.get_password(service, username)
        except Exception as exc:
            # Locked keychain, no backend, D-Bus not running, user declined the
            # prompt. The message names the ref so the operator knows which
            # profile failed, and never contains the value.
            raise CredentialStoreUnavailable(
                f"could not read credential {ref!r} from the OS keychain: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        if raw is None:
            return None
        return self._decode(raw, ref)

    def set(self, ref: str, credential: Credential) -> None:
        keyring = self._keyring()
        service, username = _split_ref(ref)
        payload = json.dumps(
            {"client_id": credential.client_id, "client_secret": credential.client_secret}
        )
        try:
            keyring.set_password(service, username, payload)
        except Exception as exc:
            raise CredentialStoreUnavailable(
                f"could not store credential {ref!r} in the OS keychain: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def delete(self, ref: str) -> None:
        keyring = self._keyring()
        service, username = _split_ref(ref)
        try:
            keyring.delete_password(service, username)
        except Exception as exc:
            # Deleting something already absent is success, not failure —
            # otherwise `profile remove` cannot clean up a half-made profile.
            if type(exc).__name__ == "PasswordDeleteError":
                return
            raise CredentialStoreUnavailable(
                f"could not delete credential {ref!r} from the OS keychain: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    @staticmethod
    def _decode(raw: str, ref: str) -> Credential:
        try:
            data = json.loads(raw)
            return Credential(
                client_id=data["client_id"], client_secret=data["client_secret"]
            )
        except Exception as exc:
            # Note what is NOT in this message: `raw`. A corrupt entry is still
            # a secret, and quoting the value we failed to parse is the classic
            # way a credential reaches a log file.
            raise CredentialStoreError(
                f"credential {ref!r} in the OS keychain is not in the expected "
                f"format ({type(exc).__name__}). Re-add the profile to replace it."
            ) from exc


class EnvCredentialStore:
    """The legacy environment variables, exposed through the same protocol.

    This is how backward compatibility is kept without a second code path: the
    resolver asks a store for a credential, and for an env-configured
    deployment the store happens to be this one. *ref* is ignored, because
    environment variables are not addressable — which is also why writes are
    refused rather than silently doing nothing.
    """

    def __init__(self, environ: Optional[dict] = None):
        self._environ = environ if environ is not None else os.environ

    def describe(self) -> str:
        return f"environment ({ENV_CLIENT_ID} / {ENV_CLIENT_SECRET})"

    def get(self, ref: str = "") -> Optional[Credential]:
        client_id = self._environ.get(ENV_CLIENT_ID)
        client_secret = self._environ.get(ENV_CLIENT_SECRET)
        if not client_id or not client_secret:
            return None
        return Credential(client_id=client_id, client_secret=client_secret)

    def set(self, ref: str, credential: Credential) -> None:
        raise CredentialStoreReadOnly(
            "environment variables cannot be written by this process. Use "
            "'vectra-mcp profile add' to store a credential in the OS keychain."
        )

    def delete(self, ref: str) -> None:
        raise CredentialStoreReadOnly(
            "environment variables cannot be removed by this process."
        )


def default_credential_store() -> CredentialStore:
    """The store profiles use. Separate function so tests can substitute one."""
    return KeyringCredentialStore()
