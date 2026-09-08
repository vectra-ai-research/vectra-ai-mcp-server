"""The report renderer as an MCP tool.

This exists because the same renderer shipped as a file inside a skill and
could not work: a plugin carrying a fourth file under `skills/*/scripts/`
silently fails to install, and a plain MCP client cannot execute Python
anyway. As a tool it needs neither.

The load-bearing behaviour tested here is that a bad case file comes back as a
*value*, not an exception. The caller is a model filling a schema from
investigation notes; it will get fields wrong, and the useful reply names the
field so it can try again.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP

from vectra_mcp_server.tool.report_tools import ReportMCPTools

MINIMAL = {
    "schema": 1,
    "entity": {"name": "build-agent-07", "kind": "host"},
    "tenant": {"label": "example-tenant.ew1"},
    "verdict": {"code": "BTP"},
    "answer": "The RPC reconnaissance is the CI agent enumerating its own fleet.",
    "next_action": "No containment. Recommend a triage rule scoped to the group.",
}


@pytest.fixture
def tool(tmp_path, monkeypatch):
    """The tool, writing into a temp directory instead of the real one."""
    monkeypatch.setattr("vectra_mcp_server.tool.report_tools.REPORT_DIR", tmp_path)
    return ReportMCPTools(FastMCP(name="test"), client=MagicMock())


async def call(tool, case, **kw):
    payload = case if isinstance(case, str) else json.dumps(case)
    return json.loads(await tool.render_investigation_report(payload, **kw))


# ------------------------------------------------------------------ the happy path

async def test_renders_a_minimal_case(tool, tmp_path):
    out = await call(tool, MINIMAL)
    assert out["rendered"] is True
    written = Path(out["path"])
    assert written.exists()
    assert written.parent == tmp_path


async def test_returns_the_path_not_the_html(tool):
    out = await call(tool, MINIMAL)
    assert "<!doctype" not in json.dumps(out).lower(), (
        "a report is ~30KB of markup; re-emitting it through the conversation "
        "would cost more than the investigation"
    )
    assert set(out) >= {"path", "size_bytes", "sha256", "entity", "verdict"}


async def test_sha256_matches_the_bytes_on_disk(tool):
    out = await call(tool, MINIMAL)
    data = Path(out["path"]).read_bytes()
    assert out["sha256"] == hashlib.sha256(data).hexdigest()
    assert out["size_bytes"] == len(data)


async def test_filename_defaults_to_the_entity(tool):
    out = await call(tool, MINIMAL)
    assert Path(out["path"]).name == "Investigation-Report-build-agent-07.html"


async def test_explicit_filename_is_honoured(tool):
    out = await call(tool, MINIMAL, filename="my-report.html")
    assert Path(out["path"]).name == "my-report.html"


async def test_a_missing_extension_is_added(tool):
    out = await call(tool, MINIMAL, filename="report")
    assert Path(out["path"]).name == "report.html"


async def test_a_directory_in_the_filename_is_ignored(tool, tmp_path):
    """The caller does not choose where files land on the server's disk."""
    out = await call(tool, MINIMAL, filename="/etc/passwd.html")
    assert Path(out["path"]).parent == tmp_path
    assert Path(out["path"]).name == "passwd.html"


async def test_traversal_in_the_filename_is_ignored(tool, tmp_path):
    out = await call(tool, MINIMAL, filename="../../escape.html")
    assert Path(out["path"]).parent == tmp_path


async def test_rerendering_overwrites_rather_than_accumulating(tool, tmp_path):
    await call(tool, MINIMAL)
    await call(tool, MINIMAL)
    assert len(list(tmp_path.iterdir())) == 1


# ------------------------------------------------- a bad case is a value, not a raise

async def test_invalid_json_is_reported_not_raised(tool):
    out = await call(tool, "this is not json")
    assert out["rendered"] is False
    assert "not valid JSON" in out["error"]


async def test_a_json_array_is_rejected_with_its_type(tool):
    out = await call(tool, "[1, 2, 3]")
    assert out["rendered"] is False
    assert "list" in out["error"]


@pytest.mark.parametrize("missing", ["entity", "tenant", "verdict", "answer", "next_action"])
async def test_a_missing_required_field_names_that_field(tool, missing):
    case = {k: v for k, v in MINIMAL.items() if k != missing}
    out = await call(tool, case)
    assert out["rendered"] is False
    assert missing in out["error"]
    assert "case-schema.md" in out["hint"]


async def test_a_bad_verdict_lists_the_valid_ones(tool):
    out = await call(tool, dict(MINIMAL, verdict={"code": "MAYBE"}))
    assert out["rendered"] is False
    assert "TP-High" in out["error"]


async def test_the_tenant_is_required_and_says_so(tool):
    """Entity and detection IDs are tenant-scoped with overlapping ranges, so a
    report citing bare IDs with no tenant recorded resolves to the wrong entity
    elsewhere rather than erroring."""
    out = await call(tool, {k: v for k, v in MINIMAL.items() if k != "tenant"})
    assert out["rendered"] is False
    assert "tenant" in out["error"]


async def test_nothing_is_written_when_validation_fails(tool, tmp_path):
    await call(tool, {k: v for k, v in MINIMAL.items() if k != "answer"})
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------------ warnings

async def test_warnings_are_returned_alongside_a_successful_render(tool):
    out = await call(tool, MINIMAL)
    assert out["rendered"] is True
    assert isinstance(out["warnings"], list)
    assert any("timeline" in w for w in out["warnings"]), (
        "the minimal case has no timeline, which should warn rather than fail"
    )


async def test_an_account_without_identities_warns(tool):
    case = dict(MINIMAL, entity={"name": "a@b.com", "kind": "account"})
    out = await call(tool, case)
    assert any("identities" in w for w in out["warnings"])


# ------------------------------------------------------------------ registration

def test_the_tool_is_registered_read_only():
    """It writes a file but changes nothing in the tenant, and rendering the
    same case twice gives the same document — the same reasoning that makes
    get_detection_pcap read-only."""
    server = FastMCP(name="test")
    ReportMCPTools(server, client=MagicMock()).register_tools()
    tools = {t.name: t for t in server._tool_manager.list_tools()}
    assert "render_investigation_report" in tools
    assert tools["render_investigation_report"].annotations.readOnlyHint is True


def test_it_is_in_the_registry():
    from vectra_mcp_server.registry import TOOL_CLASSES
    assert ReportMCPTools in TOOL_CLASSES


def test_it_makes_no_api_calls(tmp_path, monkeypatch):
    """The client is never touched, so a broken credential cannot stop a render."""
    monkeypatch.setattr("vectra_mcp_server.tool.report_tools.REPORT_DIR", tmp_path)
    client = MagicMock()
    tool = ReportMCPTools(FastMCP(name="test"), client=client)
    import asyncio
    asyncio.run(tool.render_investigation_report(json.dumps(MINIMAL)))
    assert not client.method_calls
