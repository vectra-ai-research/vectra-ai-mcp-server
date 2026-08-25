"""Findings tools: read-only, context-bounded, and honest when unavailable.

Every findings endpoint is tagged `unreleased` in the API contract, so the
failure path matters as much as the happy path — a tenant without the feature
must produce "not available here" rather than an exception or, worse, an empty
result that reads as "no exposure".
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.tool.findings_tools import FindingsMCPTools, _MAX_PAGE


def build(client):
    server = FastMCP(name="test")
    FindingsMCPTools(server, client, prefix=None, tenant_label=None).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


def _has_enum(schema) -> bool:
    """True if an `enum` key appears anywhere in the schema structure.

    Walks the structure rather than searching the serialised JSON — a
    description mentioning the word "enum" is prose, not a constraint.
    """
    if isinstance(schema, dict):
        return "enum" in schema or any(
            _has_enum(v) for k, v in schema.items() if k != "description"
        )
    if isinstance(schema, list):
        return any(_has_enum(v) for v in schema)
    return False


def _enum_values(schema) -> list:
    """Collect every enum value in a schema, ignoring descriptions.

    Asserting on the values is the only robust form. The `ordering` description
    deliberately *names* the unsortable fields to explain why they're absent, so
    a substring search for "first_seen" finds the prose and fails; searching for
    '"first_seen"' happens to work only because JSON quotes enum members. Too
    subtle to rely on.
    """
    found = []
    if isinstance(schema, dict):
        found += schema.get("enum", []) or []
        for k, v in schema.items():
            if k != "description":
                found += _enum_values(v)
    elif isinstance(schema, list):
        for v in schema:
            found += _enum_values(v)
    return found


@pytest.fixture
def client():
    return MagicMock()


def test_registers_the_tier_one_tools(client):
    tools = build(client)
    assert set(tools) == {
        "get_host_findings", "list_findings", "list_finding_entities",
        "list_finding_types",
    }


def test_all_findings_tools_are_read_only(client):
    """Findings are an exposure inventory. Nothing here writes."""
    for name, tool in build(client).items():
        assert tool.annotations.readOnlyHint is True, name
        assert tool.annotations.destructiveHint is not True, name


def test_page_size_is_capped_well_below_the_api_ceiling(client):
    """The API allows page_size up to 5000.

    A `detailed` page at that size would swamp an agent's context, and there is
    no agentic workflow that wants it, so the tool signature caps lower.
    """
    assert _MAX_PAGE <= 500
    schema = build(client)["list_findings"].parameters
    assert schema["properties"]["page_size"]["maximum"] == _MAX_PAGE


def test_category_is_not_a_closed_enum(client):
    """The contract says category values are product-defined, not a fixed enum.

    Typing it as a Literal would reject valid categories this tenant happens to
    use, which is worse than letting the API reject an invalid one.
    """
    category = build(client)["list_findings"].parameters["properties"]["category"]
    # Check schema *keys*, not the serialised blob. Two earlier attempts failed
    # on the same mistake from opposite directions: `"enum" not in blob or
    # "snake_case" in blob` was trivially true because the description contains
    # "snake_case", and plain `"enum" not in blob` was trivially false because
    # the description contains the word "enum". Substring-matching a schema
    # dump reads the prose as structure.
    assert not _has_enum(category), category

    # ...and the sanity check the other way: severity, which IS a closed set,
    # must still be constrained. Otherwise this test would pass on a schema
    # where nothing is enumerated at all.
    severity = build(client)["list_findings"].parameters["properties"]["severity"]
    assert _has_enum(severity), severity


def test_ordering_offers_only_severity(client):
    """first_seen / last_seen / status / asset_count are not sortable server-side.

    Offering them would invite a client-side sort that only orders the fetched
    page — a plausible and wrong "top N", the same failure class as the
    ORDER BY-on-a-string-constant bug.
    """
    ordering = build(client)["list_findings"].parameters["properties"]["ordering"]
    allowed = set(_enum_values(ordering))
    assert allowed, ordering
    assert allowed <= {"severity", "-severity"}, allowed


async def test_host_findings_passes_filters_through(client):
    client.get_host_findings = AsyncMock(return_value={"results": [{"id": "F1__x"}]})
    tools_obj = FindingsMCPTools(FastMCP(name="t"), client, prefix=None, tenant_label=None)

    out = await tools_obj.get_host_findings(
        host_id=105314, severity="critical", status="active",
        resolution="open", page_size=10,
    )

    kwargs = client.get_host_findings.await_args.kwargs
    assert kwargs["host_id"] == 105314
    assert kwargs["severity"] == "critical"
    assert kwargs["resolution"] == "open"
    assert "size" not in kwargs          # this endpoint 400s on it
    assert json.loads(out)["results"][0]["id"] == "F1__x"


async def test_unavailable_endpoint_reports_rather_than_raises(client):
    """An `unreleased` endpoint that 404s must not look like "no exposure"."""
    client.get_host_findings = AsyncMock(side_effect=Exception("404 Not Found"))
    tools_obj = FindingsMCPTools(FastMCP(name="t"), client, prefix=None, tenant_label=None)

    payload = json.loads(await tools_obj.get_host_findings(host_id=1))

    assert payload["findings_available"] is False
    assert "unreleased" in payload["note"]
    assert "404" in payload["error"]


async def test_empty_result_does_not_claim_there_is_no_exposure(client):
    """Zero rows is about the filters, not about the host."""
    client.get_host_findings = AsyncMock(return_value={"results": []})
    tools_obj = FindingsMCPTools(FastMCP(name="t"), client, prefix=None, tenant_label=None)

    payload = json.loads(await tools_obj.get_host_findings(host_id=1))

    assert payload["count"] == 0
    assert "filters" in payload["note"]
    # and it must not have claimed the feature is missing
    assert "findings_available" not in payload


def test_host_findings_takes_no_size_parameter(client):
    """/hosts/{id}/findings/ returns 400 if sent `size`.

    Probed live 2026-08-24 — the contract lists no `size` on this path and the
    API enforces it, unlike /findings/ where the parameter is valid. Offering it
    in the signature would guarantee a 400 on the tool's most useful call.
    """
    assert "size" not in build(client)["get_host_findings"].parameters["properties"]
    assert "size" in build(client)["list_findings"].parameters["properties"]


def test_resolution_is_not_a_closed_enum(client):
    """The documented values and this tenant's values disagree.

    Contract says Open / In Progress / Risk Accepted. The tenant returned
    resolution_counts keyed 'open' and 'remediated' — and 'remediated' is not in
    the documented set at all. A Literal would reject a value the API accepts.
    """
    for tool in ("get_host_findings", "list_findings"):
        resolution = build(client)[tool].parameters["properties"]["resolution"]
        assert not _has_enum(resolution), (tool, resolution)


async def test_finding_types_is_the_only_source_of_severity(client):
    """Findings embed FindingTypeSmall — uid and name only.

    So severity, category, remediation and compliance_frameworks are reachable
    only through the type catalogue. This test exists to stop anyone "simplifying"
    the tool away on the assumption findings already carry that data.
    """
    client.get_finding_types = AsyncMock(return_value={"results": [{
        "uid": "ae2b27cc", "name": "NetBIOS Usage", "severity": "medium",
        "category": "risky_protocol_activity", "remediation": "Disable NetBIOS.",
        "compliance_frameworks": ["CIS"],
    }]})
    tools_obj = FindingsMCPTools(FastMCP(name="t"), client, prefix=None, tenant_label=None)

    row = json.loads(await tools_obj.list_finding_types())["results"][0]

    assert row["severity"] == "medium"
    assert row["category"] == "risky_protocol_activity"
    assert row["remediation"]
    assert row["compliance_frameworks"] == ["CIS"]


async def test_finding_entities_requires_a_finding_id(client):
    client.get_finding_entities = AsyncMock(return_value={"results": [
        {"id": "EF1__a", "entity": {"name": "host-01", "urgency": 75}}
    ]})
    tools_obj = FindingsMCPTools(FastMCP(name="t"), client, prefix=None, tenant_label=None)

    out = await tools_obj.list_finding_entities(finding_id="F1__33skg")

    assert client.get_finding_entities.await_args.kwargs["finding_id"] == "F1__33skg"
    assert json.loads(out)["results"][0]["entity"]["urgency"] == 75
