"""Turning a resolved profile into the client the tools call.

This is the object handed to ``client_provider``. It answers one question —
"which ``VectraClient`` should this tool call use?" — and it answers it in one
of two modes.

Pinned (the default)
--------------------
Resolve once at startup and return the same client forever. A conversation can
never change tenant halfway through. ``vectra-mcp profile use`` affects the
next process start.

Following the active profile (opt-in)
-------------------------------------
With ``VECTRA_PROFILE_FOLLOW_ACTIVE=true``, the active-profile pointer is
re-read when the profile file changes on disk, and the next tool call lands on
the new tenant with no restart.

Why pinned is the default
-------------------------
Under live switching, a conversation that read Acme's detections and then
writes an entity note can land the note in Globex — and Vectra's audit log
records only the API client, not the analyst or the session, so nothing
downstream would catch it. That is a real hazard, not a theoretical one, so it
is opt-in. Whoever turns it on has decided the convenience is worth it.

Precedence still applies when following
---------------------------------------
Re-resolution runs the *same* chain, so an instance started with ``--profile
acme`` or ``VECTRA_PROFILE=acme`` keeps Acme no matter where the active pointer
moves. That is what makes one-connector-per-tenant safe to combine with a
shared active pointer.

Client caching
--------------
Clients are cached per tenant identity and never closed. Each holds an OAuth
token, a rate-limiter and an httpx connection pool, so rebuilding one per call
would re-authenticate constantly; closing one on switch would need an event
loop from a synchronous property. The cost is one idle connection pool per
profile the process has actually used — bounded by how many tenants an operator
touches in a session, and the reason a *changed* credential still needs a
restart to take effect.
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from ..utils.logging import get_logger
from .credentials import CredentialStore
from .resolver import ConfigurationError, Resolution, resolve
from .store import ProfileStore

logger = get_logger(__name__)

FOLLOW_ENV = "VECTRA_PROFILE_FOLLOW_ACTIVE"


def follow_active_enabled() -> bool:
    return os.environ.get(FOLLOW_ENV, "").strip().lower() in {"1", "true", "yes"}


class ProfileClientProvider:
    """A callable that returns the ``VectraClient`` for the current profile."""

    def __init__(
        self,
        resolution: Resolution,
        *,
        client_factory,
        follow_active: bool = False,
        explicit_profile: Optional[str] = None,
        store: Optional[ProfileStore] = None,
        credential_store: Optional[CredentialStore] = None,
    ):
        """
        Args:
            resolution: what was resolved at startup.
            client_factory: ``(ServerConfiguration) -> VectraClient``. Injected
                rather than imported so this module never imports the API
                client, which keeps it testable without network stubs.
            follow_active: re-read the active profile when the file changes.
            explicit_profile: the ``--profile`` value, replayed on every
                re-resolution so precedence is preserved.
        """
        self._resolution = resolution
        self._client_factory = client_factory
        self._follow = follow_active
        self._explicit = explicit_profile
        self._store = store or ProfileStore()
        self._credential_store = credential_store
        self._clients: Dict[tuple, object] = {}
        self._file_stamp = self._stamp()

    # ------------------------------------------------------------------ state

    @property
    def resolution(self) -> Resolution:
        """The resolution currently in force. Used by ``get_active_profile``."""
        return self._resolution

    @property
    def following(self) -> bool:
        return self._follow

    def _stamp(self):
        """A cheap change signal for the profile file.

        ``st_mtime_ns`` plus size rather than a hash: the file is rewritten
        atomically by ``os.replace``, so any change gives a new inode and a new
        mtime. Hashing the contents on every tool call would be the wrong cost
        for the benefit.
        """
        try:
            st = os.stat(self._store.path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    # -------------------------------------------------------------- resolving

    def _maybe_reresolve(self) -> None:
        stamp = self._stamp()
        if stamp == self._file_stamp:
            return
        self._file_stamp = stamp

        try:
            fresh = resolve(
                self._explicit,
                store=self._store,
                credential_store=self._credential_store,
                warn_on_shadow=False,
            )
        except ConfigurationError as exc:
            # Keep serving the tenant we have. Dropping to an error because
            # someone was mid-edit of profiles.yaml would break an
            # investigation for a reason that has nothing to do with it.
            logger.warning(
                "Profile file changed but could not be resolved (%s). "
                "Continuing with %s.", exc, self._resolution.describe(),
            )
            return

        if fresh.base_url == self._resolution.base_url and \
                fresh.profile_name == self._resolution.profile_name:
            return

        # Worth a warning rather than info: the tenant a tool call reaches has
        # just changed underneath a conversation that may already be in
        # progress, and this line is the only record of when it happened.
        logger.warning(
            "Active profile changed: %s -> %s. Subsequent tool calls will use "
            "the new tenant.", self._resolution.describe(), fresh.describe(),
        )
        self._resolution = fresh

    # ------------------------------------------------------------------- call

    def __call__(self):
        if self._follow:
            self._maybe_reresolve()

        tenant = self._resolution.server_config.tenants[0]
        # Deliberately excludes the secret: a rotated credential needs a
        # restart, which is documented, and keeping secrets out of dict keys
        # keeps them out of anything that dumps this object.
        key = (self._resolution.profile_name, tenant.base_url, tenant.client_id)

        client = self._clients.get(key)
        if client is None:
            client = self._client_factory(self._resolution.server_config)
            self._clients[key] = client
        return client
