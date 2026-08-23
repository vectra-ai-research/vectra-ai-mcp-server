"""Every registered MCP tool must declare its side effects.

Annotations are the only signal a client has for telling a safe read apart
from a call that mutates tenant state, absent any external playbook. These
tests fail closed: a new tool added without annotations, or a mutating tool
mislabelled as read-only, breaks the build rather than shipping quietly.
"""

from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.resources.investigation_resources import InvestigationResourceTools
from vectra_mcp_server.tool.detection_tools import DetectionMCPTools
from vectra_mcp_server.tool.entity_tools import EntityMCPTools
from vectra_mcp_server.tool.investigation_tools import InvestigationMCPTools
from vectra_mcp_server.tool.management_tools import ManagementMCPTools
from vectra_mcp_server.tool.response_tools import ResponseMCPTools

TOOL_CLASSES = (
    DetectionMCPTools,
    EntityMCPTools,
    InvestigationMCPTools,
    ManagementMCPTools,
    ResponseMCPTools,
    InvestigationResourceTools,
)

# Tools that change tenant state. Anything not listed here must be read-only.
# Adding a tool to this set is a deliberate act; forgetting to is caught by
# test_no_unexpected_mutating_tools.
EXPECTED_MUTATING = {
    "add_member_to_group",
    "close_detections",
    "create_assignment",
    "create_entity_note",
    "delete_assignment",
    "mark_detection_fixed",
    "reopen_detections",
    "run_investigation",
}

# Of those, the ones that remove, close, or suppress existing state.
EXPECTED_DESTRUCTIVE = {
    "close_detections",
    "delete_assignment",
    "mark_detection_fixed",
}


def build_tools(prefix=None, tenant_label=None):
    """Register every tool class against a real FastMCP and return its tools."""
    server = FastMCP(name="test")
    client = MagicMock()
    for cls in TOOL_CLASSES:
        cls(server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


@pytest.fixture(scope="module")
def tools():
    return build_tools()


def test_every_tool_declares_annotations(tools):
    assert tools, "no tools registered — the fixture itself is broken"
    missing = sorted(name for name, t in tools.items() if t.annotations is None)
    assert not missing, f"tools registered without annotations: {missing}"


def test_read_only_flag_matches_the_expected_mutating_set(tools):
    actual_mutating = {
        name for name, t in tools.items() if t.annotations.readOnlyHint is False
    }
    assert actual_mutating == EXPECTED_MUTATING


def test_no_unexpected_mutating_tools(tools):
    """A tool whose name suggests mutation must be declared, not silently read-only."""
    suspicious_prefixes = ("create_", "delete_", "close_", "update_", "add_", "mark_", "set_")
    for name, tool in tools.items():
        if name.startswith(suspicious_prefixes):
            assert tool.annotations.readOnlyHint is False, (
                f"{name} looks like a mutation but is annotated read-only"
            )


def test_destructive_flag_is_set_only_where_expected(tools):
    actual_destructive = {
        name for name, t in tools.items() if t.annotations.destructiveHint is True
    }
    assert actual_destructive == EXPECTED_DESTRUCTIVE


def test_read_only_tools_are_idempotent_and_closed_world(tools):
    for name, tool in tools.items():
        if tool.annotations.readOnlyHint:
            assert tool.annotations.idempotentHint is True, f"{name}"
            assert tool.annotations.openWorldHint is False, f"{name}"


def test_run_investigation_is_not_read_only(tools):
    """It POSTs a new async query job and returns a fresh request_id each call."""
    ann = tools["run_investigation"].annotations
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is False
    assert ann.idempotentHint is False


def test_annotations_survive_multi_tenant_registration():
    """Prefixed registration takes a different code path in _register_tool."""
    prefixed = build_tools(prefix="prod", tenant_label="prod (https://prod.vectra.ai)")

    missing = sorted(n for n, t in prefixed.items() if t.annotations is None)
    assert not missing, f"multi-tenant tools without annotations: {missing}"

    mutating = {
        n.removeprefix("prod_")
        for n, t in prefixed.items()
        if t.annotations.readOnlyHint is False
    }
    assert mutating == EXPECTED_MUTATING


def test_single_and_multi_tenant_agree_on_every_tool():
    single = build_tools()
    prefixed = build_tools(prefix="prod", tenant_label="prod")

    assert {f"prod_{n}" for n in single} == set(prefixed)
    for name, tool in single.items():
        assert (
            prefixed[f"prod_{name}"].annotations.model_dump()
            == tool.annotations.model_dump()
        ), f"annotations differ between tenancy modes for {name}"
