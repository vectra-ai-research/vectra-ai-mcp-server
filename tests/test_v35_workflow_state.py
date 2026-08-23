"""v3.5 detection history and workflow state.

Two v3.5-only capabilities, both pinned per-call rather than by moving the
server's default version: v3.5 documents 12 paths against v3.4's 76 and has no
accounts / groups / rules / assignments / health, so a server-wide default of
v3.5 would break most tools.

The awkward part this module guards: `external_reference_id` and
`investigation_status` are **write-only from the detection resource** — PATCH
sets them, GET /detections does not return them. The only read path is the
events endpoint, whose `investigation_status` filter defaults to `open`. So a
naive history query silently returns nothing for any detection that has been
acknowledged, escalated, paused, closed or expired — and since GET /detections
cannot tell you the status, the caller has no way to know which value to ask
for. Hence the all-statuses sweep.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.tool.investigation_tools import InvestigationMCPTools
from vectra_mcp_server.vectra_client import VectraClient

STATUSES = ("open", "acknowledged", "escalated", "paused", "closed", "expired")


@pytest.fixture
def client():
    c = MagicMock()
    c.INVESTIGATION_STATUSES = STATUSES
    c.get_detection_events = AsyncMock(return_value={"events": [], "count": 0})
    c.set_detection_workflow_state = AsyncMock(return_value={"_meta": {"level": "Success"}})
    return c


@pytest.fixture
def tools(client):
    return InvestigationMCPTools(vectra_mcp=None, client=client)


def registered():
    server = FastMCP(name="test")
    InvestigationMCPTools(server, MagicMock()).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


# ---------------------------------------------------------------------------
# Version pinning
# ---------------------------------------------------------------------------

def test_v35_is_supported_but_not_the_default():
    from vectra_mcp_server.config import _SUPPORTED_API_VERSIONS
    assert "v3.5" in _SUPPORTED_API_VERSIONS


def test_make_request_accepts_a_per_call_version_override():
    import inspect
    params = inspect.signature(VectraClient._make_request).parameters
    assert "api_version" in params
    assert params["api_version"].default is None


# ---------------------------------------------------------------------------
# The investigation_status=open trap
# ---------------------------------------------------------------------------

async def test_history_sweeps_all_statuses_when_none_given():
    """The regression this guards: default-open hides closed detections."""
    raw = MagicMock()
    raw._make_request = AsyncMock(return_value={"events": []})
    raw.INVESTIGATION_STATUSES = STATUSES
    await VectraClient.get_detection_events(raw, detection_id=19554)

    asked = [
        call.kwargs["params"]["investigation_status"]
        for call in raw._make_request.await_args_list
    ]
    assert sorted(asked) == sorted(STATUSES)


async def test_history_queries_once_when_a_status_is_given():
    raw = MagicMock()
    raw._make_request = AsyncMock(return_value={"events": []})
    raw.INVESTIGATION_STATUSES = STATUSES
    await VectraClient.get_detection_events(
        raw, detection_id=19554, investigation_status="closed"
    )
    assert raw._make_request.await_count == 1
    assert raw._make_request.await_args.kwargs["params"]["investigation_status"] == "closed"


async def test_history_pins_v35_and_defaults_to_size_small():
    raw = MagicMock()
    raw._make_request = AsyncMock(return_value={"events": []})
    raw.INVESTIGATION_STATUSES = ("open",)
    await VectraClient.get_detection_events(raw, detection_id=19554)
    kwargs = raw._make_request.await_args.kwargs
    assert kwargs["api_version"] == "v3.5"
    assert kwargs["params"]["size"] == "small"


async def test_history_dedupes_events_across_status_queries():
    """The same event can come back under more than one status query."""
    raw = MagicMock()
    raw.INVESTIGATION_STATUSES = ("open", "closed")
    raw._make_request = AsyncMock(return_value={
        "events": [
            {"id": 1, "event_timestamp": "2026-08-14T11:21:48Z"},
            {"id": 2, "event_timestamp": "2026-08-15T05:12:30Z"},
        ]
    })
    result = await VectraClient.get_detection_events(raw, detection_id=19554)
    assert result["count"] == 2
    assert [e["id"] for e in result["events"]] == [1, 2]  # oldest first


# ---------------------------------------------------------------------------
# Workflow state writes
# ---------------------------------------------------------------------------

async def test_workflow_state_sends_both_fields(tools, client):
    await tools.set_detection_workflow_state(
        detection_ids=[19554], external_reference_id="TICKET-12345",
        investigation_status="escalated",
    )
    client.set_detection_workflow_state.assert_awaited_once_with(
        detection_ids=[19554], external_reference_id="TICKET-12345",
        investigation_status="escalated",
    )


async def test_workflow_state_rejects_an_empty_update(tools, client):
    result = await tools.set_detection_workflow_state(detection_ids=[19554])
    assert "Nothing to set" in result
    client.set_detection_workflow_state.assert_not_awaited()


async def test_workflow_state_rejects_an_empty_id_list(tools, client):
    result = await tools.set_detection_workflow_state(
        detection_ids=[], external_reference_id="TICKET-1"
    )
    assert "No detection IDs provided." in result
    client.set_detection_workflow_state.assert_not_awaited()


async def test_workflow_patch_pins_v35():
    raw = MagicMock()
    raw._make_request = AsyncMock(return_value={})
    await VectraClient.set_detection_workflow_state(
        raw, detection_ids=[1], investigation_status="closed"
    )
    kwargs = raw._make_request.await_args.kwargs
    assert kwargs["api_version"] == "v3.5"
    assert kwargs["json_data"]["detectionIdList"] == [1]


# ---------------------------------------------------------------------------
# Annotations and discoverability
# ---------------------------------------------------------------------------

def test_history_is_read_only():
    assert registered()["get_detection_history"].annotations.readOnlyHint is True


def test_workflow_state_is_a_non_destructive_mutation():
    ann = registered()["set_detection_workflow_state"].annotations
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is False


def test_workflow_state_description_distinguishes_it_from_assignment():
    """Assignment acknowledges and starts metrics timers; this annotates.
    Conflating them misuses the assignment field."""
    d = registered()["set_detection_workflow_state"].description
    assert "create_assignment" in d
    assert "write-only" in d


def test_history_description_names_what_is_unique_to_it():
    d = registered()["get_detection_history"].description
    assert "mitre" in d.lower()
    assert "grouped_details" in d
