#!/usr/bin/env python3
"""Which endpoints this server calls exist on v3.5 on THIS tenant?

The contract spec in this repo's history documented only 12 v3.5 paths (against
76 on v3.4), which is why the server defaults to v3.4 and pins individual calls
to v3.5. Now that v3.5 is GA that may be out of date. This answers it live,
per endpoint, instead of trusting a spec.

For every endpoint the client calls it makes the same request against v3.4 and
v3.5 and compares:

  * status code (200 vs 404/403/...)
  * the keys on the first returned object, so a v3.5 endpoint that exists but
    changed shape is flagged as DIFFERENT rather than silently passing

Write endpoints (POST/PATCH/PUT/DELETE) are NEVER called. They are checked with
OPTIONS, which reports the methods the path accepts. Everything else is a GET
with page_size=1. Read-only.

Usage
-----
    python scripts/probe_v35_coverage.py
    python scripts/probe_v35_coverage.py --json out.json

Needs VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vectra_mcp_server.profiles.resolver import ConfigurationError, resolve  # noqa: E402
from vectra_mcp_server.vectra_client import USER_AGENT, VectraClient  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
)

# (path as the client sends it, {id} placeholders resolved from a list call,
#  where "list" names the endpoint to take an id from)
GET_ENDPOINTS = [
    ("accounts", None), ("accounts/{id}", "accounts"),
    ("hosts", None), ("hosts/{id}", "hosts"),
    ("entities", None), ("entities/{id}", "entities"),
    ("detections", None), ("detections/{id}", "detections"),
    ("events/detections/", None),
    ("assignments", None), ("assignments/{id}", "assignments"),
    ("health", None), ("health/edr", None), ("health/edr/details", None),
    ("health/external_connectors", None),
    ("health/external_connectors/details", None),
    ("health/network_brain/ping", None),
    ("groups", None), ("groups/{id}", "groups"), ("groups/{id}/members", "groups"),
    ("rules", None), ("rules/{id}", "rules"),
    ("users", None), ("users/{id}", "users"), ("users/roles", None),
    ("lockdown", None),
    ("threatFeeds", None), ("threatFeeds/{id}", "threatFeeds"),
    ("unique_hosts_observed", None), ("unique_hosts_observed_monthly", None),
    ("vectra-match/stats", None), ("vectra-match/rules", None),
    ("vectra-match/status", None), ("vectra-match/enablement", None),
    ("vectra-match/available-devices", None),
    ("findings/", None), ("finding_types/", None),
]

# Called by the client with a write method. Checked with OPTIONS only.
WRITE_ENDPOINTS = [
    ("detections", "PATCH"), ("detections/close/", "PATCH"),
    ("detections/open/", "PATCH"),
    ("assignments", "POST"), ("assignments/{id}", "PATCH/DELETE"),
    ("groups", "POST"), ("groups/{id}", "PATCH/DELETE"),
    ("rules", "POST"), ("rules/{id}", "PATCH/DELETE"),
    ("lockdown", "POST"), ("threatFeeds", "POST"), ("threatFeeds/{id}", "DELETE"),
    ("entities/{id}/notes", "POST"), ("hosts/{id}/tags", "PATCH"),
    ("accounts/{id}/tags", "PATCH"),
    ("investigations", "POST"),
]


async def raw(client: VectraClient, method: str, version: str, path: str, params=None):
    token = await client.token_manager.get_access_token()
    url = f"{client.config.base_url}/api/{version}/{path.lstrip('/')}"
    resp = await client.client.request(
        method, url, params=params,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                 "User-Agent": USER_AGENT},
    )
    await asyncio.sleep(0.25)
    return resp


#: Paged list endpoints that accept page_size. Sending it anywhere else gets a
#: 400 (detail paths, health, lockdown), which reads as "endpoint broken" when
#: it is the probe that is wrong. An earlier run mislabelled ~17 rows this way.
PAGED = {
    "accounts", "hosts", "entities", "detections", "assignments", "groups",
    "groups/{id}/members", "rules", "users", "threatFeeds",
    "unique_hosts_observed", "unique_hosts_observed_monthly",
    "vectra-match/rules", "findings/", "finding_types/",
}
#: Resources where v3.5 takes `size`. Without it v3.5 returns its default
#: (lean) shape, so a plain comparison reports fields as "removed" that
#: `size=detailed` brings back.
SIZED = {"accounts", "hosts", "entities", "detections"}


def params_for(path: str, version: str, size: str | None, ids: dict) -> dict:
    params: dict = {}
    if path in PAGED:
        params["page_size"] = 1
    if path == "events/detections/":
        # Required filter; take a real detection id from the list call.
        if "detections" in ids:
            params["detection_id"] = ids["detections"]
        params["limit"] = 1
    if version == "v3.5" and size and path in SIZED:
        params["size"] = size
    return params


def first_object(body):
    if isinstance(body, dict):
        for key in ("results", "events", "data"):
            if isinstance(body.get(key), list) and body[key]:
                return body[key][0] if isinstance(body[key][0], dict) else None
        return body
    if isinstance(body, list) and body and isinstance(body[0], dict):
        return body[0]
    return None


def safe_json(resp):
    try:
        return resp.json()
    except Exception:                                              # noqa: BLE001
        return None


async def run(args) -> int:
    try:
        resolution = resolve(args.profile, warn_on_shadow=False)
    except ConfigurationError as exc:
        print(f"configuration error: {exc}")
        return 1
    config = resolution.server_config
    tenant = config.tenants[0]
    client = VectraClient(config.vectra_config_for_tenant(tenant))
    print(f"profile: {resolution.profile_name or '(environment variables)'} "
          f"via {resolution.source}")
    print(f"probing v3.4 vs v3.5 against {tenant.base_url}\n")

    ids: dict[str, str] = {}
    rows = []

    for path, id_from in GET_ENDPOINTS:
        if "{id}" in path:
            ident = ids.get(id_from or "")
            if ident is None:
                rows.append((path, "GET", "-", "-", "SKIPPED", "no id available from list call"))
                continue
            resolved = path.replace("{id}", ident)
        else:
            resolved = path

        out = {}
        for version in ("v3.4", "v3.5"):
            params = params_for(path, version, args.size, ids)
            resp = await raw(client, "GET", version, resolved, params)
            body = safe_json(resp) if resp.status_code == 200 else None
            out[version] = (resp.status_code, body)
            if version == "v3.4" and "{id}" not in path and resp.status_code == 200:
                obj = first_object(body)
                if isinstance(obj, dict) and "id" in obj:
                    ids.setdefault(path, str(obj["id"]))

        s4, b4 = out["v3.4"]
        s5, b5 = out["v3.5"]
        if s4 != 200 and s5 != 200:
            verdict, note = "N/A", f"fails on both ({s4}/{s5}); check the path or permissions"
        elif s5 != 200:
            verdict, note = "MISSING", f"v3.5 returned {s5}"
        elif s4 != 200:
            verdict, note = "V35-ONLY", f"v3.4 returned {s4}"
        else:
            k4 = set((first_object(b4) or {}).keys())
            k5 = set((first_object(b5) or {}).keys())
            if k4 == k5:
                verdict, note = "OK", ""
            else:
                verdict = "DIFFERENT"
                note = f"+{sorted(k5 - k4)[:6]} -{sorted(k4 - k5)[:6]}"
        rows.append((path, "GET", s4, s5, verdict, note))

    for path, methods in WRITE_ENDPOINTS:
        resolved = path.replace("{id}", ids.get(path.split("/")[0], "1"))
        allow = {}
        status = {}
        for version in ("v3.4", "v3.5"):
            resp = await raw(client, "OPTIONS", version, resolved)
            status[version] = resp.status_code
            allow[version] = resp.headers.get("allow", "")
        wanted = set(methods.split("/"))
        have5 = {m.strip() for m in allow["v3.5"].split(",")}
        if status["v3.5"] >= 400 and status["v3.5"] != 405:
            verdict, note = "MISSING", f"OPTIONS on v3.5 returned {status['v3.5']}"
        elif have5 and not wanted <= have5:
            verdict, note = "MISSING", f"v3.5 Allow={allow['v3.5']!r}"
        elif not have5:
            verdict, note = "UNKNOWN", "no Allow header; confirm with a real write in a test tenant"
        else:
            verdict, note = "OK", ""
        rows.append((path, methods, status["v3.4"], status["v3.5"], verdict, note))

    colour = {"OK": GREEN, "MISSING": RED, "DIFFERENT": YELLOW, "V35-ONLY": YELLOW,
              "UNKNOWN": YELLOW, "N/A": DIM, "SKIPPED": DIM}
    print(f"{'endpoint':<38}{'method':<14}{'v3.4':<6}{'v3.5':<6}verdict")
    for path, method, s4, s5, verdict, note in rows:
        print(f"{path:<38}{method:<14}{str(s4):<6}{str(s5):<6}"
              f"{colour[verdict]}{verdict}{RESET}  {DIM}{note}{RESET}")

    missing = [r for r in rows if r[4] == "MISSING"]
    different = [r for r in rows if r[4] == "DIFFERENT"]
    print(f"\n{len(rows)} endpoints: "
          f"{sum(r[4] == 'OK' for r in rows)} OK, {len(different)} different, "
          f"{len(missing)} missing on v3.5")
    if not missing and not different:
        print("Safe to set VECTRA_API_VERSION=v3.5 as the default.")
    else:
        print("Do NOT flip the global default yet; pin only the OK endpoints.")

    if args.json:
        Path(args.json).write_text(json.dumps(
            [dict(zip(("endpoint", "method", "v3.4", "v3.5", "verdict", "note"), r))
             for r in rows], indent=2))
        print(f"wrote {args.json}")
    await client.close()
    return 1 if missing else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", help="also write results to this file")
    parser.add_argument("--profile", help="profile name; default is the active profile")
    parser.add_argument("--size", choices=("small", "regular", "detailed"),
                        help="send size=… to v3.5 on accounts/hosts/entities/"
                             "detections, to compare against v3.4's full shape")
    sys.exit(asyncio.run(run(parser.parse_args())))
