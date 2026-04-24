"""MCP tools that expose investigation SQL syntax and schema documentation.

These tools let the LLM fetch reference material (SQL dialect, table schemas)
before constructing a query for the run_investigation tool.
"""

import os
from typing import Annotated, Literal

from pydantic import Field

from tool.base import BaseMCPTools


_RESOURCES_DIR = os.path.dirname(os.path.abspath(__file__))


def _read_resource(filename: str) -> str:
    """Read a resource markdown file from the resources directory."""
    with open(os.path.join(_RESOURCES_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


_SCHEMA_FILES = {
    "network": "schema_network.md",
    "m365": "schema_m365.md",
    "cloudtrail": "schema_cloudtrail.md",
    "azurecp": "schema_azurecp.md",
}


class InvestigationResourceTools(BaseMCPTools):
    """MCP tools that return investigation reference documentation."""

    def register_tools(self):
        """Register all investigation resource tools with the MCP server."""
        self._register_tool(self.get_investigation_sql_reference)
        self._register_tool(self.get_investigation_schema)

    async def get_investigation_sql_reference(self) -> str:
        """
        Get the complete Vectra investigation SQL dialect reference. MUST be called before constructing a query for run_investigation. Returns the supported SQL syntax, operators, functions, fully-qualified table names, time-window patterns, CIDR filtering, forbidden constructs, and curated query examples for all data sources (network, M365, AWS CloudTrail, Azure).
        """
        return _read_resource("sql_reference.md")

    async def get_investigation_schema(
        self,
        data_source: Annotated[
            Literal["network", "m365", "cloudtrail", "azurecp"],
            Field(description=(
                "The data source to get the schema for. "
                "'network' = Zeek-style network telemetry (beacon, dns, http, kerberos, ntlm, ssl, etc.), "
                "'m365' = Microsoft 365 audit logs (Azure AD, Exchange, SharePoint, sign-ins, etc.), "
                "'cloudtrail' = AWS CloudTrail events, "
                "'azurecp' = Azure control plane (operations, flow logs, insights logs, etc.)."
            ))
        ],
    ) -> str:
        """
        Get the attribute schema for a specific data source. Returns every queryable column name, type, and description for the chosen data source tables. Call this before constructing a run_investigation query to know the exact attribute names available.
        """
        filename = _SCHEMA_FILES[data_source]
        return _read_resource(filename)
