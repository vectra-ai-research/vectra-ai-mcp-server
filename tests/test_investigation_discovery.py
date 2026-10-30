"""Live table and schema discovery tools.

The payloads here are trimmed copies of live responses (30 Oct 2026), not the
shapes the API contract describes. They differ in ways that matter: lists arrive
under `results`, table records have `name` rather than `id`, and a schema is a
flat map with dotted field names and an undocumented `usage` hint. A tool that
trusted the contract would have returned nothing and said nothing.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.resources.investigation_resources import (
    InvestigationResourceTools,
    _sql_name,
)

TABLES = {
    "categories": [{"id": "network", "label": "Network"}, {"id": "o365", "label": "Microsoft 365"}],
    "tables": [
        {"aliases": ["dcerpctxn"], "category_id": "network", "internal": False,
         "connectors": [{"id": "a1", "source_type": "network"}],
         "label": "DCE/RPC", "name": "dce_rpc"},
        {"aliases": [], "category_id": "o365", "internal": False,
         "connectors": [{"id": "b1", "source_type": "o365"}, {"id": "b2", "source_type": "o365"}],
         "label": "SignIns", "name": "signins"},
        {"aliases": [], "category_id": "azurecp", "internal": False,
         "connectors": [{"id": "c1", "source_type": "azure-cp"}],
         "label": "Flow Logs", "name": "flowlogs_legacy"},
    ],
}

CATALOG = {"results": [{"table_name": "ssl"}, {"table_name": "beacon"}, {"table_name": "smtp"}]}

SCHEMA = {"results": {"table_name": "dns", "schema": {
    "id.orig_h": {"description": "Originating endpoint IP address", "type": "string",
                  "usage": ["ip_address"]},
    "query": {"description": "Domain queried", "type": "string"},
    "answers[]": {"description": "Answers", "type": "string"},
}}}


def build(client):
    server = FastMCP(name="test")
    InvestigationResourceTools(server, client, prefix=None, tenant_label=None).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


def test_discovery_tools_are_registered_and_read_only():
    tools = build(MagicMock())
    for name in ("list_investigation_tables", "list_investigation_schemas", "get_table_schema"):
        assert name in tools
        assert tools[name].annotations.readOnlyHint is True
        assert tools[name].annotations.destructiveHint is not True
    # The static fallback must still be there.
    assert "get_investigation_schema" in tools


@pytest.mark.asyncio
async def test_tables_use_name_not_id_and_report_sql_names():
    client = MagicMock()
    client.list_investigation_tables = AsyncMock(return_value=TABLES)
    out = json.loads(await build(client)["list_investigation_tables"].fn())
    by_name = {t["name"]: t for t in out["tables"]}

    assert out["count"] == 3
    assert by_name["dce_rpc"]["sql_name"] == "network.dce_rpc"
    assert by_name["dce_rpc"]["aliases"] == ["dcerpctxn"]
    # o365 is ambiguous (entra.* and m365.*), so it is mapped explicitly.
    assert by_name["signins"]["sql_name"] == "entra.signins"
    assert by_name["signins"]["source_types"] == ["o365"]
    # No confirmed SQL name: null, not a guess.
    assert by_name["flowlogs_legacy"]["sql_name"] is None


@pytest.mark.asyncio
async def test_tables_also_accept_the_contract_shape():
    client = MagicMock()
    client.list_investigation_tables = AsyncMock(return_value={
        "tables": [{"id": "beacon", "label": "Beacon", "aliases": [],
                    "connectors": [{"id": "x", "source_type": "network"}]}]
    })
    out = json.loads(await build(client)["list_investigation_tables"].fn())
    assert [t["name"] for t in out["tables"]] == ["beacon"]


@pytest.mark.asyncio
async def test_schema_catalog_is_read_from_results():
    client = MagicMock()
    client.list_investigation_schemas = AsyncMock(return_value=CATALOG)
    out = json.loads(await build(client)["list_investigation_schemas"].fn())
    assert out == {"count": 3, "table_names": ["beacon", "smtp", "ssl"]}


@pytest.mark.asyncio
async def test_table_schema_returns_dotted_fields_with_usage():
    client = MagicMock()
    client.get_investigation_table_schema = AsyncMock(return_value=SCHEMA)
    out = json.loads(await build(client)["get_table_schema"].fn(table_name="dns"))
    assert out["table_name"] == "dns"
    assert out["field_count"] == 3 and out["returned"] == 3
    first = next(f for f in out["fields"] if f["name"] == "id.orig_h")
    assert first["type"] == "string" and first["usage"] == ["ip_address"]
    # Array marker stays in the name: it is how the API says "array".
    assert any(f["name"] == "answers[]" for f in out["fields"])


@pytest.mark.asyncio
async def test_table_schema_name_filter_keeps_the_total():
    client = MagicMock()
    client.get_investigation_table_schema = AsyncMock(return_value=SCHEMA)
    out = json.loads(
        await build(client)["get_table_schema"].fn(table_name="dns", name_contains="ORIG")
    )
    assert out["field_count"] == 3          # what the table has
    assert out["returned"] == 1             # what matched
    assert out["fields"][0]["name"] == "id.orig_h"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,args", [
    ("list_investigation_tables", {}),
    ("list_investigation_schemas", {}),
    ("get_table_schema", {"table_name": "dns"}),
])
async def test_unavailable_discovery_is_reported_not_raised(tool, args):
    """A tenant without Vectra Pro (403) or without the endpoint (404)."""
    client = MagicMock()
    for method in ("list_investigation_tables", "list_investigation_schemas",
                   "get_investigation_table_schema"):
        setattr(client, method, AsyncMock(side_effect=RuntimeError("403 Forbidden")))
    out = json.loads(await build(client)[tool].fn(**args))
    assert out["available"] is False
    assert "get_investigation_schema" in out["note"]      # points at the fallback


def test_table_name_cannot_carry_a_path():
    """table_name goes into a URL path; the schema must refuse traversal."""
    schema = build(MagicMock())["get_table_schema"].parameters
    pattern = schema["properties"]["table_name"]["pattern"]
    import re
    assert re.match(pattern, "ssl") and re.match(pattern, "directory_audits")
    for bad in ("../health", "ssl/../x", "..", "a.b", "a b", "", "x" * 65):
        assert not re.match(pattern, bad), bad


def test_sql_name_rules():
    assert _sql_name("beacon", "network") == "network.beacon"
    assert _sql_name("cloudtrail", "aws") == "aws.cloudtrail"
    assert _sql_name("operations", "azurecp") == "azurecp.operations"
    assert _sql_name("dnslogs", None) is None
    assert _sql_name("flowlogs", "azurecp") is None


# --- client: pinned to v3.5, path-safe ---------------------------------------

@pytest.mark.asyncio
async def test_client_discovery_calls_pin_v35():
    from vectra_mcp_server.vectra_client import VectraClient

    client = VectraClient.__new__(VectraClient)
    client._make_request = AsyncMock(return_value={})

    await client.list_investigation_tables(category="network")
    await client.get_investigation_table("beacon")
    await client.list_investigation_schemas()
    await client.get_investigation_table_schema("dns")

    calls = client._make_request.call_args_list
    assert [c.args[1] for c in calls] == [
        "investigations/tables/",
        "investigations/tables/beacon/",
        "investigations/schemas/",
        "investigations/schemas/dns/",
    ]
    assert all(c.kwargs["api_version"] == "v3.5" for c in calls)
    assert calls[0].kwargs["params"] == {"category": "network"}


@pytest.mark.asyncio
async def test_client_quotes_the_table_name_in_the_path():
    from vectra_mcp_server.vectra_client import VectraClient

    client = VectraClient.__new__(VectraClient)
    client._make_request = AsyncMock(return_value={})
    await client.get_investigation_table_schema("../health")
    assert client._make_request.call_args.args[1] == "investigations/schemas/..%2Fhealth/"
