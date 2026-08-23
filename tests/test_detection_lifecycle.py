"""The close/open detection lifecycle, and the deprecation of mark_as_fixed.

Three API operations, three distinct pieces of state:

    PATCH /detections/close/   {detectionIdList, reason}   -> close_detections
    PATCH /detections/open/    {detectionIdList}           -> reopen_detections
    PATCH /detections          {detectionIdList,
                                mark_as_fixed}             -> mark_detection_fixed

The third is legacy and writes a *different* field from the first two, so
mark_fixed=False does not reopen a detection closed via close/. These tests pin
the request shapes and keep the deprecation notice discoverable.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.tool.investigation_tools import InvestigationMCPTools


@pytest.fixture
def client():
    c = MagicMock()
    c.close_detections = AsyncMock(return_value={"_meta": {"level": "Success"}})
    c.reopen_detections = AsyncMock(return_value={"_meta": {"level": "Success"}})
    c.mark_detection_fixed = AsyncMock(return_value={"_meta": {"level": "Success"}})
    return c


@pytest.fixture
def tools(client):
    return InvestigationMCPTools(vectra_mcp=None, client=client)


def registered():
    server = FastMCP(name="test")
    InvestigationMCPTools(server, MagicMock()).register_tools()
    return {t.name: t for t in server._tool_manager.list_tools()}


# --------------------------------------------------------------------------
# close_detections
# --------------------------------------------------------------------------

async def test_close_detections_passes_ids_and_reason(tools, client):
    await tools.close_detections(detection_ids=[83738, 220], reason="benign")
    client.close_detections.assert_awaited_once_with(
        detection_ids=[83738, 220], reason="benign"
    )


async def test_close_detections_accepts_a_single_id(tools, client):
    """The bulk form is the only form; n=1 must work naturally."""
    await tools.close_detections(detection_ids=[42], reason="remediated")
    client.close_detections.assert_awaited_once_with(
        detection_ids=[42], reason="remediated"
    )


async def test_close_detections_rejects_an_empty_list(tools, client):
    result = await tools.close_detections(detection_ids=[], reason="benign")
    assert "No detection IDs provided." in result
    client.close_detections.assert_not_awaited()


# --------------------------------------------------------------------------
# reopen_detections
# --------------------------------------------------------------------------

async def test_reopen_detections_passes_ids(tools, client):
    await tools.reopen_detections(detection_ids=[83738])
    client.reopen_detections.assert_awaited_once_with(detection_ids=[83738])


async def test_reopen_detections_rejects_an_empty_list(tools, client):
    result = await tools.reopen_detections(detection_ids=[])
    assert "No detection IDs provided." in result
    client.reopen_detections.assert_not_awaited()


# --------------------------------------------------------------------------
# Deprecation
# --------------------------------------------------------------------------

def test_mark_detection_fixed_is_marked_deprecated():
    """MCP has no deprecation flag, so the description is the only channel."""
    description = registered()["mark_detection_fixed"].description
    assert "DEPRECATED" in description
    assert "close_detections" in description


def test_mark_detection_fixed_warns_that_it_is_separate_state():
    """The trap: mark_fixed=False does not reopen a close/'d detection."""
    description = registered()["mark_detection_fixed"].description
    assert "SEPARATE STATE" in description


async def test_mark_detection_fixed_still_calls_the_legacy_endpoint(tools, client):
    """Deprecated, not removed -- existing callers must keep working."""
    await tools.mark_detection_fixed(detection_ids=[1, 2], mark_fixed=True)
    client.mark_detection_fixed.assert_awaited_once_with([1, 2], True)


# --------------------------------------------------------------------------
# Tool surface
# --------------------------------------------------------------------------

def test_close_detection_singular_is_gone():
    """Replaced by the list form; two tools differing only in arity invite
    wrong-tool selection."""
    assert "close_detection" not in registered()


def test_reopen_detections_is_not_destructive():
    """It restores state rather than removing it, but it is still a mutation
    (and it triggers a rescore)."""
    annotations = registered()["reopen_detections"].annotations
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is False


def test_reopen_detections_documents_the_rescore():
    assert "rescore" in registered()["reopen_detections"].description
