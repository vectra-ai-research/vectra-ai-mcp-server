#!/usr/bin/env python3
"""Print the registered MCP tool inventory with side-effect annotations.

Registers every tool class against a real FastMCP instance using a stub
client, so this needs **no Vectra credentials and makes no network calls** —
it reports what the server *would* expose.

Usage:
    python scripts/list_tools.py              # print the table
    python scripts/list_tools.py --check      # non-zero exit if any tool
                                              # lacks annotations
    python scripts/list_tools.py --prefix prod  # multi-tenant registration
    python scripts/list_tools.py --json       # machine-readable

Why this exists: annotations are the only signal a client has for telling a
safe read from a call that mutates tenant state. This is the fastest way to
eyeball that classification after touching a tool, and the check mode is
wired into CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from vectra_mcp_server.resources.investigation_resources import (  # noqa: E402
    InvestigationResourceTools,
)
from vectra_mcp_server.tool.detection_tools import DetectionMCPTools  # noqa: E402
from vectra_mcp_server.tool.entity_tools import EntityMCPTools  # noqa: E402
from vectra_mcp_server.tool.investigation_tools import InvestigationMCPTools  # noqa: E402
from vectra_mcp_server.tool.management_tools import ManagementMCPTools  # noqa: E402
from vectra_mcp_server.tool.response_tools import ResponseMCPTools  # noqa: E402

TOOL_CLASSES = (
    DetectionMCPTools,
    EntityMCPTools,
    InvestigationMCPTools,
    ManagementMCPTools,
    ResponseMCPTools,
    InvestigationResourceTools,
)


def classify(ann) -> str:
    """Collapse the annotation hints into a one-word label."""
    if ann is None:
        return "UNANNOTATED"
    if ann.readOnlyHint:
        return "read-only"
    if ann.destructiveHint:
        return "DESTRUCTIVE"
    return "additive" if ann.idempotentHint else "additive (each call)"


def build(prefix: str | None = None):
    server = FastMCP(name="inventory")
    client = MagicMock()
    for cls in TOOL_CLASSES:
        cls(server, client, prefix=prefix, tenant_label=prefix).register_tools()
    return sorted(server._tool_manager.list_tools(), key=lambda t: t.name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                       help="exit non-zero if any tool lacks annotations")
    parser.add_argument("--prefix", default=None,
                       help="register with a tenant prefix (multi-tenant mode)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    tools = build(args.prefix)
    unannotated = [t.name for t in tools if t.annotations is None]

    if args.json:
        print(json.dumps([
            {
                "name": t.name,
                "class": classify(t.annotations),
                "annotations": t.annotations.model_dump(exclude_none=True)
                if t.annotations else None,
            }
            for t in tools
        ], indent=2))
    else:
        width = max((len(t.name) for t in tools), default=10)
        print(f"{'TOOL'.ljust(width)}  CLASS")
        print(f"{'-' * width}  {'-' * 20}")
        for t in tools:
            print(f"{t.name.ljust(width)}  {classify(t.annotations)}")

        counts: dict[str, int] = {}
        for t in tools:
            counts[classify(t.annotations)] = counts.get(classify(t.annotations), 0) + 1
        print()
        print(f"{len(tools)} tools: " + ", ".join(
            f"{n} {label}" for label, n in sorted(counts.items())
        ))
        print()
        print("NOTE: list_tenants is registered directly in server.py (multi-tenant")
        print("      mode only) and is not included above.")

    if unannotated:
        print(f"\nERROR: {len(unannotated)} tool(s) without annotations: "
              f"{', '.join(unannotated)}", file=sys.stderr)
        return 1
    if args.check:
        print("\nOK: every tool declares its side effects.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
