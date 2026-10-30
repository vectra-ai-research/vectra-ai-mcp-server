"""v3.5 hosts listing, and tolerance of the Investigate API's array-row format."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.tool.entity_tools import EntityMCPTools, _MAX_HOST_PAGE
from vectra_mcp_server.tool.investigation_tools import normalize_investigation_rows
from vectra_mcp_server.vectra_client import VectraClient


def build(client):
    server = FastMCP(name="test")
    EntityMCPTools(server, client, prefix=None, tenant_label=None).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


# --- list_hosts -----------------------------------------------------------

def test_list_hosts_is_registered_and_read_only():
    tool = build(MagicMock())["list_hosts"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is not True


def test_size_is_a_closed_set_defaulting_to_regular():
    props = build(MagicMock())["list_hosts"].parameters["properties"]
    assert props["size"]["enum"] == ["small", "regular", "detailed"]
    assert props["size"]["default"] == "regular"


def test_page_size_is_capped():
    props = build(MagicMock())["list_hosts"].parameters["properties"]
    assert props["page_size"]["maximum"] == _MAX_HOST_PAGE


@pytest.mark.asyncio
async def test_list_hosts_passes_size_and_maps_ip_to_last_source():
    client = MagicMock()
    client.get_hosts_v35 = AsyncMock(return_value={"count": 0, "results": []})
    tool = build(client)["list_hosts"]
    await tool.fn(size="detailed", host_ip="10.0.0.5", page_size=10)
    kwargs = client.get_hosts_v35.call_args.kwargs
    assert kwargs["size"] == "detailed"
    assert kwargs["last_source"] == "10.0.0.5"
    assert kwargs["page_size"] == 10


@pytest.mark.asyncio
async def test_list_hosts_reports_errors_as_json_not_exceptions():
    client = MagicMock()
    client.get_hosts_v35 = AsyncMock(side_effect=RuntimeError("boom"))
    out = json.loads(await build(client)["list_hosts"].fn())
    assert "boom" in out["error"]


@pytest.mark.asyncio
async def test_client_pins_v35_and_sends_size():
    client = VectraClient.__new__(VectraClient)
    client._make_request = AsyncMock(return_value={})
    await client.get_hosts_v35(size="small", name="srv")
    args, kwargs = client._make_request.call_args
    assert args == ("GET", "hosts/")
    assert kwargs["api_version"] == "v3.5"
    assert kwargs["params"]["size"] == "small"
    assert kwargs["params"]["name"] == "srv"


@pytest.mark.asyncio
async def test_client_rejects_unknown_size():
    client = VectraClient.__new__(VectraClient)
    client._make_request = AsyncMock()
    with pytest.raises(ValueError):
        await client.get_hosts_v35(size="huge")
    client._make_request.assert_not_called()


# --- investigation row normalisation --------------------------------------

PAIR_COLUMNS = [["timestamp", [{"type": "timestamp"}, ""]], ["orig_h", [{"type": "string"}, ""]]]


def test_object_rows_pass_through_untouched():
    result = {"data": [{"a": 1}], "meta": {"columns": PAIR_COLUMNS}}
    assert normalize_investigation_rows(result) == result


def test_array_rows_become_objects_using_pair_columns():
    result = {"data": [["t1", "10.0.0.1"], ["t2", "10.0.0.2"]], "meta": {"columns": PAIR_COLUMNS}}
    out = normalize_investigation_rows(result)
    assert out["data"] == [
        {"timestamp": "t1", "orig_h": "10.0.0.1"},
        {"timestamp": "t2", "orig_h": "10.0.0.2"},
    ]
    assert out["meta"] == result["meta"]
    assert result["data"][0] == ["t1", "10.0.0.1"]  # input not mutated


def test_plain_string_columns_and_nested_results_block():
    result = {"results": {"columns": ["a", "b"], "data": [[1, 2]]}}
    assert normalize_investigation_rows(result)["results"]["data"] == [{"a": 1, "b": 2}]


def test_duplicate_column_names_do_not_overwrite():
    result = {"data": [[1, 2]], "meta": {"columns": ["ip", "ip"]}}
    assert normalize_investigation_rows(result)["data"] == [{"ip": 1, "ip_2": 2}]


def test_unmappable_arrays_are_returned_as_received():
    no_columns = {"data": [[1, 2]]}
    assert normalize_investigation_rows(no_columns) == no_columns
    wrong_width = {"data": [[1, 2, 3]], "meta": {"columns": ["a", "b"]}}
    assert normalize_investigation_rows(wrong_width) == wrong_width


def test_empty_and_non_dict_inputs_are_safe():
    assert normalize_investigation_rows({"data": [], "meta": {}}) == {"data": [], "meta": {}}
    assert normalize_investigation_rows(None) is None


def test_real_post_change_payload_normalizes_to_the_old_keys():
    """A trimmed live response (entra.signins, 30 Oct 2026).

    Rows are arrays under top-level `data`; `meta.columns` keeps its
    `[name, [{type}, ""]]` pair form. Column names are the flattened leaf names
    (`vectra.identity_principal` comes back as `identity_principal`), which is
    what the object-row format used as keys, so existing readers keep working.
    """
    import json
    from pathlib import Path

    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "investigation_array_rows.json").read_text()
    )
    assert all(isinstance(r, list) for r in payload["data"])

    out = normalize_investigation_rows(payload)

    first = out["data"][0]
    assert first["identity_principal"] == "pm@demolab.vectra.ai"
    assert first["error_code"] == 50126
    assert first["is_compliant"] is False
    assert out["data"][1]["additional_details"] is None
    assert out["meta"] == payload["meta"]
