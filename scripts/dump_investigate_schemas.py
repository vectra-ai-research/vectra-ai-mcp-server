#!/usr/bin/env python3
"""Dump every Investigate table and schema from the v3.5 discovery endpoints.

Calls, read-only:

    GET /api/v3.5/investigations/tables/            what exists, per source
    GET /api/v3.5/investigations/tables/{table}/    detail for each table
    GET /api/v3.5/investigations/schemas/           which tables have a schema
    GET /api/v3.5/investigations/schemas/{table}/   every field, for each one

and writes, into --out (default ./investigate-schema-dump):

    tables.json            raw list response
    table-<id>.json        raw detail response per table
    schemas.json           raw catalog response
    schema-<name>.json     raw schema response per table
    SCHEMA_REFERENCE.md    one section per table: field, type, nullable, description
    COVERAGE.md            table-vs-schema cross-check (what has no schema, and the reverse)

The raw JSON is the source of truth. The Markdown is a rendering of it, meant as
the input to the public "Investigate API metadata schema reference". Nothing is
hand-edited between the API and the page.

Needs VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET, and a tenant
with a Vectra Pro subscription (403 otherwise).

Usage
-----
    python scripts/dump_investigate_schemas.py
    python scripts/dump_investigate_schemas.py --out /tmp/schemas
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vectra_mcp_server.profiles.resolver import ConfigurationError, resolve  # noqa: E402
from vectra_mcp_server.vectra_client import USER_AGENT, VectraClient  # noqa: E402

BASE = "investigations"


async def get(client: VectraClient, path: str, params=None, retries: int = 4):
    """GET one v3.5 path. Returns (status, json-or-None). Backs off on 429."""
    delay = 2.0
    for _ in range(retries):
        token = await client.token_manager.get_access_token()
        resp = await client.client.get(
            f"{client.config.base_url}/api/v3.5/{path.lstrip('/')}",
            params=params,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                     "User-Agent": USER_AGENT},
        )
        if resp.status_code == 429:
            await asyncio.sleep(delay)
            delay *= 2
            continue
        await asyncio.sleep(0.3)
        try:
            body = resp.json()
        except Exception:                                          # noqa: BLE001
            body = None
        return resp.status_code, body
    return 429, None


def safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def flatten(fields: dict, prefix: str = ""):
    """Yield (dotted_path, definition) for a schema map, parents before children."""
    for name, spec in (fields or {}).items():
        path = f"{prefix}{name}"
        yield path, spec
        if isinstance(spec, dict) and spec.get("fields"):
            yield from flatten(spec["fields"], f"{path}.")


def cell(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def listing(body: dict, key: str | None = None) -> list:
    """The list inside a response, under whichever key it uses."""
    for k in (key, "results", "data", "tables"):
        if k and isinstance((body or {}).get(k), list):
            return body[k]
    return []


def table_id(record: dict) -> str | None:
    for k in ("id", "table_name", "name"):
        if isinstance(record.get(k), str) and record[k]:
            return record[k]
    return None


def schema_body(payload: dict) -> dict:
    """The object holding table_name and the field map, wherever it sits."""
    for k in ("data", "results"):
        v = (payload or {}).get(k)
        if isinstance(v, dict):
            return v
    return payload or {}


def schema_fields(payload: dict) -> dict:
    body = schema_body(payload)
    for k in ("schema", "fields", "properties"):
        if isinstance(body.get(k), dict):
            return body[k]
    return {}


def render_schema(name: str, payload: dict) -> str:
    data = schema_body(payload)
    fields = schema_fields(payload)
    rows = list(flatten(fields))
    out = [f"## {data.get('table_name') or name}", "",
           f"{len(rows)} field(s), including nested.", "",
           "| Column | Type | Nullable | Description |",
           "| --- | --- | --- | --- |"]
    for path, spec in rows:
        out.append(
            f"| `{path}` | `{cell(spec.get('type'))}` | "
            f"{cell(spec.get('nullable')) or ''} | {cell(spec.get('description'))} |"
        )
    # Anything on a field other than the four documented keys is worth seeing:
    # the spec says the response format is still under development.
    extra = sorted({k for _, s in rows for k in s
                    if k not in ("type", "description", "nullable", "fields")})
    if extra:
        out += ["", f"> Undocumented keys seen on fields: {', '.join(extra)}"]
    return "\n".join(out) + "\n"


async def run(args) -> int:
    # Same resolver the server uses, so this talks to the tenant the MCP server
    # does: --profile, then VECTRA_PROFILE, then the active profile, and only
    # then the legacy VECTRA_BASE_URL variables (which a repo .env can set).
    try:
        resolution = resolve(args.profile, warn_on_shadow=False)
    except ConfigurationError as exc:
        print(f"configuration error: {exc}")
        return 1
    config = resolution.server_config
    tenant = config.tenants[0]
    client = VectraClient(config.vectra_config_for_tenant(tenant))
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    print(f"profile: {resolution.profile_name or '(environment variables)'} "
          f"via {resolution.source}")
    if resolution.shadowed:
        print("note: VECTRA_BASE_URL and friends are also set (a .env file?) "
              "but are ignored in favor of the profile")
    print(f"dumping Investigate tables and schemas from {tenant.base_url}\n")

    status, tables = await get(client, f"{BASE}/tables/")
    if status != 200:
        print(f"tables/ returned {status}. 403 usually means the tenant has no "
              f"Vectra Pro subscription; 404 means the endpoint is not enabled.")
        return 1
    (out / "tables.json").write_text(json.dumps(tables, indent=2))
    # The spec says `tables`; be liberal, since the live shape has already
    # differed from the spec once (schemas/ uses `results`, not `data`).
    table_list = listing(tables, "tables")
    print(f"tables/: {len(table_list)} table(s), "
          f"{len(tables.get('categories') or [])} categor(ies); "
          f"top-level keys {sorted(tables)}")
    if table_list:
        print(f"  first table record keys: {sorted(table_list[0])}")

    status, catalog = await get(client, f"{BASE}/schemas/")
    if status != 200:
        print(f"schemas/ returned {status}")
        return 1
    (out / "schemas.json").write_text(json.dumps(catalog, indent=2))
    schema_names = [i["table_name"] for i in listing(catalog)
                    if isinstance(i, dict) and i.get("table_name")]
    print(f"schemas/: {len(schema_names)} table(s) with a schema")
    if not schema_names:
        # An empty catalog is either "not enabled on this tenant" or a response
        # shape this script does not know. Show the shape, then try each table
        # id directly: the detail endpoint may work even when the list is empty.
        print(f"  catalog keys: {sorted(catalog)}; "
              f"raw (first 300 chars): {json.dumps(catalog)[:300]}")
        print("  trying schemas/{table}/ for each table id instead")
        for t in table_list:
            tid = table_id(t)
            if not tid:
                continue
            s, body = await get(client, f"{BASE}/schemas/{tid}/")
            if s == 200:
                schema_names.append(tid)
            print(f"    {tid}: {s}")

    for t in table_list:
        tid = table_id(t)
        if not tid:
            continue
        s, body = await get(client, f"{BASE}/tables/{tid}/")
        if s == 200:
            (out / f"table-{safe(tid)}.json").write_text(json.dumps(body, indent=2))
        else:
            print(f"  table {tid}: {s}")

    sections, failed = [], []
    for name in schema_names:
        s, body = await get(client, f"{BASE}/schemas/{name}/")
        if s != 200:
            failed.append((name, s))
            print(f"  schema {name}: {s}")
            continue
        (out / f"schema-{safe(name)}.json").write_text(json.dumps(body, indent=2))
        sections.append(render_schema(name, body))
        n = sum(1 for _ in flatten(schema_fields(body)))
        shape = "" if n else f"  (no fields parsed; top-level keys {sorted(body)})"
        print(f"  schema {name}: {n} field(s){shape}")

    (out / "SCHEMA_REFERENCE.md").write_text(
        "# Investigate table schemas (generated)\n\n"
        f"Source: GET /api/v3.5/investigations/schemas/{{table}}/ on {tenant.base_url}\n\n"
        + "\n".join(sections)
    )

    table_ids = {table_id(t) for t in table_list if table_id(t)}
    cov = ["# Coverage", "",
           f"- tables listed: {len(table_ids)}",
           f"- schemas listed: {len(schema_names)}", "",
           "## Tables with no schema", ""]
    cov += [f"- `{t}`" for t in sorted(table_ids - set(schema_names))] or ["- none"]
    cov += ["", "## Schemas with no table entry", ""]
    cov += [f"- `{n}`" for n in sorted(set(schema_names) - table_ids)] or ["- none"]
    cov += ["", "## Table -> sources", "", "| Table | Label | Source types | Aliases |", "| --- | --- | --- | --- |"]
    for t in sorted(table_list, key=lambda x: table_id(x) or ""):
        types = sorted({c.get("source_type") for c in t.get("connectors") or [] if c.get("source_type")})
        cov.append(f"| `{table_id(t)}` | {cell(t.get('label'))} | {', '.join(types)} | "
                   f"{', '.join(map(str, t.get('aliases') or []))} |")
    if failed:
        cov += ["", "## Schema fetches that failed", ""] + [f"- `{n}`: {s}" for n, s in failed]
    (out / "COVERAGE.md").write_text("\n".join(cov) + "\n")

    print(f"\nwrote {out}/ ({len(sections)} schemas rendered)")
    await client.close()
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="investigate-schema-dump")
    parser.add_argument("--profile", help="profile name; default is the active profile")
    sys.exit(asyncio.run(run(parser.parse_args())))
