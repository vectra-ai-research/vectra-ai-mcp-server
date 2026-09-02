"""The MCP tool contract must not depend on how the client is supplied.

Centrally maintained Skills and workflows call these tools by name and schema.
Tenant selection is runtime configuration, so introducing a per-access client
provider — the mechanism that lets `profile use` take effect without a restart
— must be invisible across the wire: same tool names, same descriptions, same
input schemas, same annotations.

This test is the tripwire for that. It compares a full snapshot of the
registered contract built two ways:

    cls(server, client)                    the historical form
    cls(server, client_provider=lambda)    the new seam

and requires them to be equal. It is deliberately a snapshot comparison rather
than a list of assertions about individual tools: an assertion list only checks
what someone remembered to write down, and the whole risk here is an
unintended change to something nobody thought about.
"""

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.client_access import ClientHolder
from vectra_mcp_server.prompt.prompt import VectraMCPPrompts
from vectra_mcp_server.registry import TOOL_CLASSES

#: Everything a caller can observe about a tool. `title` is included because
#: it is part of the wire shape even though nothing sets it today — if a future
#: change starts populating it, this test should notice.
CONTRACT_KEYS = ("name", "title", "description", "parameters", "annotations")

#: The keys that must be present for every tool. If a library upgrade renames
#: one of these, the snapshots would still compare equal — both empty — and the
#: test would pass while checking nothing. `test_the_snapshot_captured_a_real
#: _contract` is what stops that.
REQUIRED_KEYS = ("description", "parameters", "annotations")


def contract(**kwargs):
    """Register every tool class and return a comparable snapshot."""
    server = FastMCP(name="test")
    for cls in TOOL_CLASSES:
        cls(server, **kwargs).register_tools()

    snapshot = {}
    for tool in server._tool_manager.list_tools():
        entry = {}
        for key in CONTRACT_KEYS:
            if not hasattr(tool, key):
                continue
            value = getattr(tool, key)
            entry[key] = value.model_dump() if hasattr(value, "model_dump") else value
        snapshot[tool.name] = entry
    return snapshot


@pytest.fixture(scope="module")
def injected():
    return contract(client=MagicMock())


@pytest.fixture(scope="module")
def provided():
    return contract(client_provider=lambda: MagicMock())


# ------------------------------------------------------------------ the claim

def test_the_two_forms_register_the_same_tool_names(injected, provided):
    assert injected, "no tools registered — the fixture itself is broken"
    assert set(injected) == set(provided)


def test_the_two_forms_register_an_identical_contract(injected, provided):
    """One assertion covering names, descriptions, schemas and annotations."""
    assert injected == provided


def test_the_snapshot_captured_a_real_contract(injected):
    """Guard against a vacuous pass.

    If the attributes we read were renamed upstream, both snapshots above would
    be empty dicts and compare equal. Pin one known tool to something real.
    """
    for name, entry in injected.items():
        for key in REQUIRED_KEYS:
            assert key in entry, f"{name} is missing {key} — snapshot is vacuous"

    tool = injected["list_entities"]
    assert tool["description"], "description not captured"
    assert isinstance(tool["parameters"], dict) and tool["parameters"], "input schema not captured"
    assert tool["annotations"]["readOnlyHint"] is True, "annotations not captured"


# ------------------------------------------------------------------ the seam

def test_the_provider_is_not_called_during_registration():
    """Registration must not resolve a client.

    This is what makes deferred and switchable configuration possible at all:
    if registration resolved the client, the server would need valid
    credentials for a tenant before it could describe its own tools.
    """
    calls = []
    contract(client_provider=lambda: calls.append(1) or MagicMock())
    assert calls == [], f"provider called {len(calls)} times at registration"


def test_the_provider_is_called_on_every_access():
    """No caching in the holder — the provider owns that decision."""
    calls = []

    def provider():
        calls.append(1)
        return MagicMock()

    holder = ClientHolder()
    holder._init_client(client_provider=provider)
    holder.client
    holder.client
    assert len(calls) == 2


def test_an_injected_client_is_returned_unchanged():
    sentinel = MagicMock()
    holder = ClientHolder()
    holder._init_client(client=sentinel)
    assert holder.client is sentinel


def test_assignment_still_works_as_it_did_when_this_was_an_attribute():
    sentinel = MagicMock()
    holder = ClientHolder()
    holder._init_client(client=MagicMock())
    holder.client = sentinel
    assert holder.client is sentinel


def test_assignment_wins_over_a_provider():
    sentinel = MagicMock()
    holder = ClientHolder()
    holder._init_client(client_provider=lambda: MagicMock())
    holder.client = sentinel
    assert holder.client is sentinel, "a provider must not shadow an explicit assignment"


@pytest.mark.parametrize("kwargs", [
    {},
    {"client": MagicMock(), "client_provider": lambda: MagicMock()},
])
def test_ambiguous_or_absent_client_configuration_is_rejected(kwargs):
    """Fail at construction, not on the first tool call.

    Two sources of truth for which tenant a call reaches is the exact bug this
    seam exists to prevent, so it is refused rather than resolved by precedence.
    """
    with pytest.raises(ValueError):
        ClientHolder()._init_client(**kwargs)


# ------------------------------------------------------------------ prompts

def test_prompts_use_the_same_seam_as_tools():
    """Otherwise half a conversation could reach a different tenant."""
    sentinel = MagicMock()
    prompts = VectraMCPPrompts(FastMCP(name="test"), client_provider=lambda: sentinel)
    assert prompts.client is sentinel


def test_prompt_registration_is_unaffected_by_how_the_client_arrives():
    def names(**kwargs):
        server = FastMCP(name="test")
        VectraMCPPrompts(server, **kwargs).register_prompts()
        return sorted(p.name for p in server._prompt_manager.list_prompts())

    assert names(client=MagicMock()) == names(client_provider=lambda: MagicMock())
