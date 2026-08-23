"""Multi-tenant registration must not degrade tool descriptions.

The prefixed path passes an explicit ``description`` to FastMCP, which bypasses
the ``fn.__doc__`` fallback the single-tenant path relies on
(``func_doc = description or fn.__doc__ or ""``). That made it possible -- and
for a long time actual -- for prefixed registration to ship a one-line
description while single-tenant shipped the full docstring.

These tests pin the invariant: a tool's description may gain a tenant label,
but it must never lose content.
"""

import inspect
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

LABEL = "prod (https://prod.vectra.ai)"


def build(prefix=None, tenant_label=None):
    server = FastMCP(name="test")
    client = MagicMock()
    for cls in TOOL_CLASSES:
        cls(server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


def nonblank(text):
    return [line for line in (text or "").splitlines() if line.strip()]


@pytest.fixture(scope="module")
def single():
    return build()


@pytest.fixture(scope="module")
def prefixed():
    return build(prefix="prod", tenant_label=LABEL)


def test_fixtures_registered_the_same_tools(single, prefixed):
    assert single, "no tools registered — the fixture itself is broken"
    assert {f"prod_{name}" for name in single} == set(prefixed)


def test_every_prefixed_description_carries_the_label(prefixed):
    for name, tool in prefixed.items():
        assert tool.description.startswith(f"[{LABEL}] "), name


def test_label_falls_back_to_prefix_when_no_tenant_label():
    tools = build(prefix="prod")
    assert tools["prod_list_entities"].description.startswith("[prod] ")


def test_no_tool_loses_lines_in_multi_tenant_mode(single, prefixed):
    """The regression this module exists for."""
    shrunk = []
    for name, tool in single.items():
        before = len(nonblank(tool.description))
        after = len(nonblank(prefixed[f"prod_{name}"].description))
        if after < before:
            shrunk.append(f"{name}: {before} -> {after} lines")
    assert not shrunk, "descriptions truncated under a tenant prefix:\n" + "\n".join(shrunk)


def test_prefixed_description_contains_the_entire_docstring(single, prefixed):
    for name, tool in single.items():
        body = prefixed[f"prod_{name}"].description.split("] ", 1)[1]
        assert body == inspect.cleandoc(tool.description), name


def test_returns_section_survives_the_prefix(single, prefixed):
    """25 of 28 docstrings document their return shape; truncation dropped it."""
    checked = 0
    for name, tool in single.items():
        if "Returns:" in (tool.description or ""):
            checked += 1
            assert "Returns:" in prefixed[f"prod_{name}"].description, name
    assert checked > 20, f"expected most tools to document returns, saw {checked}"


def test_mark_detection_fixed_keeps_its_second_line(prefixed):
    """Concrete case: a destructive tool whose first line omits what it does.

    Truncated, the description read only "Marks or unmark detection as fixed."
    and lost the sentence explaining that marking closes the detection as
    remediated.
    """
    description = prefixed["prod_mark_detection_fixed"].description
    assert "closed as remediated" in description


def test_single_tenant_descriptions_are_untouched(single):
    """This fix must not alter the default, backward-compatible path."""
    for name, tool in single.items():
        assert not tool.description.startswith("["), name
        assert tool.description == tool.fn.__doc__
