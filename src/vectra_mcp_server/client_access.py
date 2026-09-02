"""The one seam between MCP tools and the Vectra client they call.

Why this exists
---------------
Every tool reaches its API client the same way::

    detection = await self.client.get_detection(detection_id)

That dereference happens at *invocation* time, not at registration time — which
means a single indirection at ``.client`` is enough to change which tenant a
call lands on, without editing any of the 39 tools. This module is that
indirection, and nothing more.

Before this, ``client`` was a plain attribute assigned once in
``BaseMCPTools.__init__``, so the tenant was fixed for the life of the process:
changing the active profile could not affect a running Claude Desktop
connection. With the holder in place, a caller may pass either

* ``client`` — a concrete ``VectraClient``, resolved once (the historical
  behaviour, and still what the server does today), or
* ``client_provider`` — a zero-argument callable invoked on *every* access,
  which is what lets profile switching take effect on the next tool call.

Deliberately not here
---------------------
No profile logic, no credential handling, no caching. The provider is an opaque
callable; whoever supplies it owns those decisions. Keeping this module free of
them is what allows a future hosted deployment to hand in a provider that
resolves the authenticated user's tenant per request, without any tool changing.

The provider signature is ``() -> VectraClient``. When per-request context is
eventually needed, the provider closes over it rather than the tools passing it
down — that keeps the tool signatures, and therefore the MCP tool contract,
untouched.
"""

from typing import Callable, Optional


class ClientHolder:
    """Mixin giving a class a ``client`` that may be fixed or resolved per access.

    Used by both ``BaseMCPTools`` and ``VectraMCPPrompts``. They share it rather
    than each keeping their own copy, because a version where tools resolve the
    client live and prompts hold a stale one is precisely the kind of split
    behaviour nobody would think to test for.
    """

    _client = None
    _client_provider: Optional[Callable[[], object]] = None

    def _init_client(self, client=None, client_provider=None) -> None:
        """Set up client access. Exactly one of the two arguments is required."""
        if client is None and client_provider is None:
            raise ValueError(
                "either client or client_provider is required — a tool class "
                "with no way to reach the Vectra API would register fine and "
                "fail on first call"
            )
        if client is not None and client_provider is not None:
            raise ValueError(
                "pass client or client_provider, not both — two sources of "
                "truth for which tenant a call reaches is the bug this seam "
                "exists to prevent"
            )
        self._client = client
        self._client_provider = client_provider

    @property
    def client(self):
        """The Vectra client for this call.

        With a provider, this is resolved on every access — so it must stay
        cheap. Providers are expected to cache the client per tenant; this
        property does not cache, because caching here would defeat the point.
        """
        if self._client_provider is not None:
            return self._client_provider()
        return self._client

    @client.setter
    def client(self, value) -> None:
        """Assigning a client wins over any provider.

        Kept so that ``obj.client = something`` behaves as it did when this was
        a plain attribute — existing code and tests do exactly that, and a
        property without a setter would turn that into an AttributeError at
        import time in someone else's fork.
        """
        self._client = value
        self._client_provider = None
