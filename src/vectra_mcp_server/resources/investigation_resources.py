"""MCP tools that expose investigation SQL syntax and schema documentation.

These tools let the LLM fetch reference material (SQL dialect, table schemas)
before constructing a query for the run_investigation tool.
"""

import json
import os
from typing import Annotated, Any, Literal

from pydantic import Field

from ..tool.base import READ_ONLY, BaseMCPTools


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


#: API table name -> the name to use after FROM. The API speaks logical names
#: (`signins`, category `o365`); queries need the product's prefixed name
#: (`entra.signins`). The `o365` category covers both `entra.*` and `m365.*` in
#: SQL, so that one cannot be derived from the API and is listed explicitly.
#: Tables not listed (and not network/aws) return None rather than a guess:
#: `flowlogs`, `flowlogs_legacy` and `dnslogs` have no confirmed SQL name.
_SQL_NAMES = {
    "signins": "entra.signins",
    "directory_audits": "entra.directoryaudits",
    "exchange": "m365.exchange",
    "sharepoint": "m365.sharepoint",
    "general": "m365.general",
    "active_directory": "m365.active_directory",
    "operations": "azurecp.operations",
}
_SQL_PREFIX = {"network": "network", "aws": "aws"}

_TABLE_NAME_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"

_UNAVAILABLE = (
    "Investigate table and schema discovery is not available on this tenant. "
    "A 403 usually means no Vectra Pro subscription; a 404 means the endpoint is "
    "not enabled yet. Fall back to get_investigation_schema, which serves a "
    "static copy that can be out of date."
)


def _listing(body: Any, *keys: str) -> list:
    """The list inside a response, under whichever key it uses.

    The contract says `tables` / `data`; the live API has used `results`.
    """
    if not isinstance(body, dict):
        return []
    for key in (*keys, "results", "data", "tables"):
        if isinstance(body.get(key), list):
            return body[key]
    return []


def _table_name(record: dict) -> str | None:
    for key in ("name", "id", "table_name"):
        if isinstance(record.get(key), str) and record[key]:
            return record[key]
    return None


def _sql_name(name: str, category: str | None) -> str | None:
    if name in _SQL_NAMES:
        return _SQL_NAMES[name]
    prefix = _SQL_PREFIX.get(category or "")
    return f"{prefix}.{name}" if prefix else None


def _schema_body(payload: Any) -> dict:
    if not isinstance(payload, dict):
        return {}
    for key in ("results", "data"):
        if isinstance(payload.get(key), dict):
            return payload[key]
    return payload


class InvestigationResourceTools(BaseMCPTools):
    """MCP tools that return investigation reference documentation."""

    def register_tools(self):
        """Register all investigation resource tools with the MCP server."""
        self._register_tool(self.get_investigation_sql_reference, READ_ONLY)
        self._register_tool(self.get_investigation_schema, READ_ONLY)
        self._register_tool(self.list_investigation_tables, READ_ONLY)
        self._register_tool(self.list_investigation_schemas, READ_ONLY)
        self._register_tool(self.get_table_schema, READ_ONLY)

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
        Get the attribute schema for a specific data source from a static copy bundled with the server. Prefer get_table_schema, which reads the live schema: this copy lags the API (it lacks hundreds of newer fields, for example 78 on signins) and does not know the newest tables. Use this one only when the live tools report that discovery is unavailable on the tenant.
        """
        filename = _SCHEMA_FILES[data_source]
        return _read_resource(filename)

    async def list_investigation_tables(
        self,
        category: Annotated[
            str | None,
            Field(description="Restrict to one category, e.g. 'network', 'aws', 'azurecp', 'o365'. The accepted values are still being defined by the API, so an unknown one may return nothing rather than an error.")
        ] = None,
        source_type: Annotated[
            str | None,
            Field(description="Restrict to one source type, e.g. 'network', 'aws', 'azure-cp', 'o365'.")
        ] = None,
    ) -> str:
        """
        List the Investigate tables available on THIS tenant, with the name to use in a query.

        Per tenant: a table appears only if the tenant has a source for it. list_investigation_schemas is global and can name tables with no data here. Use this one to decide what can be queried, then get_table_schema for the fields.

        Each table has `name` (the API's logical name), `sql_name` (what to write after FROM, or null when it has no confirmed SQL name, in which case confirm with a LIMIT 1 query), `category`, `aliases` (older internal names such as dcerpctxn for dce_rpc) and `source_types`.

        Returns:
            str: JSON with count, tables and categories, or a note if discovery is unavailable.
        """
        try:
            body = await self.client.list_investigation_tables(
                category=category, source_type=source_type
            )
        except Exception as e:                                    # noqa: BLE001
            return json.dumps({"available": False, "error": str(e), "note": _UNAVAILABLE}, indent=2)

        tables = []
        for rec in _listing(body, "tables"):
            if not isinstance(rec, dict):
                continue
            name = _table_name(rec)
            if not name:
                continue
            cat = rec.get("category_id") or rec.get("category")
            tables.append({
                "name": name,
                "sql_name": _sql_name(name, cat),
                "label": rec.get("label"),
                "category": cat,
                "aliases": rec.get("aliases") or [],
                "source_types": sorted({
                    c.get("source_type") for c in rec.get("connectors") or []
                    if isinstance(c, dict) and c.get("source_type")
                }),
                **({"internal": True} if rec.get("internal") else {}),
            })
        tables.sort(key=lambda t: (t["category"] or "", t["name"]))
        return json.dumps({
            "count": len(tables),
            "tables": tables,
            "categories": body.get("categories", []) if isinstance(body, dict) else [],
        }, indent=2)

    async def list_investigation_schemas(self) -> str:
        """
        List every table that has a schema. Global, not per tenant.

        A schema is not proof the table is queryable on your tenant, and at least one (smtp) is known not to be queryable at all. Compare against list_investigation_tables before writing a query.

        Returns:
            str: JSON with the table names, or a note if discovery is unavailable.
        """
        try:
            body = await self.client.list_investigation_schemas()
        except Exception as e:                                    # noqa: BLE001
            return json.dumps({"available": False, "error": str(e), "note": _UNAVAILABLE}, indent=2)
        names = sorted(
            r["table_name"] for r in _listing(body)
            if isinstance(r, dict) and isinstance(r.get("table_name"), str)
        )
        return json.dumps({"count": len(names), "table_names": names}, indent=2)

    async def get_table_schema(
        self,
        table_name: Annotated[
            str,
            Field(pattern=_TABLE_NAME_PATTERN, description="The API's logical table name, as returned by list_investigation_tables or list_investigation_schemas, e.g. 'ssl', 'signins', 'cloudtrail'. Not the SQL name: use 'signins', not 'entra.signins'.")
        ],
        name_contains: Annotated[
            str | None,
            Field(description="Return only fields whose name contains this text (case-insensitive). Large tables have over a hundred fields; filter when you know what you are looking for.")
        ] = None,
    ) -> str:
        """
        Get the live schema for one Investigate table: every queryable field with its type and description.

        Call this before writing a run_investigation query, after list_investigation_tables tells you the table exists and its sql_name (what to write after FROM; this tool does not return it). Field names are the dotted paths to use in WHERE (id.orig_h). A [] suffix marks an array. A usage of ip_address or quantity is a hint about the value, not a different type.

        Returns:
            str: JSON with table_name, field_count, and the fields, or a note if discovery is unavailable or the table has no schema.
        """
        try:
            body = await self.client.get_investigation_table_schema(table_name)
        except Exception as e:                                    # noqa: BLE001
            return json.dumps({"table_name": table_name, "available": False,
                               "error": str(e), "note": _UNAVAILABLE}, indent=2)
        data = _schema_body(body)
        raw = data.get("schema") if isinstance(data.get("schema"), dict) else {}
        fields = [
            {"name": k, "type": v.get("type"), "description": v.get("description"),
             **({"usage": v["usage"]} if v.get("usage") else {})}
            for k, v in raw.items() if isinstance(v, dict)
        ]
        total = len(fields)
        if name_contains:
            needle = name_contains.lower()
            fields = [f for f in fields if needle in f["name"].lower()]
        return json.dumps({
            "table_name": data.get("table_name") or table_name,
            "field_count": total,
            "returned": len(fields),
            "fields": fields,
        }, indent=2)
