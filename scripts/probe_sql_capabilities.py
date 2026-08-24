#!/usr/bin/env python3
"""Check that what we document about the SQL dialect is actually true.

`sql_reference.md` and `schema_*.md` are hand-maintained, and the API has no
schema-discovery endpoint to generate them from — `/investigations/` submits a
query and `/investigations/{id}` fetches results, and that is all. So nothing
verifies our documentation against reality, and it has already drifted:
`CONTAINS` was documented as a string function (45 recipe call sites copied it),
and `schema_network.md` documents an `smtp` table that `sql_reference.md` says
returns `TABLE_NOT_FOUND`.

This is the missing half of the validation story:

    validate_recipes.py (starter repo)  recipes conform to the reference
    probe_sql_capabilities.py (here)    the reference conforms to the API

Run it after changing the SQL engine. Three outcomes matter:

    holds             the documented behaviour is still correct
    BROKEN            we document something the API no longer does — fix the docs
    NEWLY PERMITTED   we forbid something the API now allows — new capability

That last category is the point. Adding JOIN support to the engine should show
up here as "§3.5 is now stale", not as a rejected query six weeks later.

Only the submit call is needed: FUNCTION_NOT_FOUND and TABLE_NOT_FOUND come
back on the POST, so each claim costs one request rather than submit-then-poll.

Usage
-----
    make probe                                  # all claims
    python scripts/probe_sql_capabilities.py --only contains-two-strings
    python scripts/probe_sql_capabilities.py --tables      # + per-table existence
    python scripts/probe_sql_capabilities.py --update-verified

Needs VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET, and a tenant
you are content to send trivial LIMIT 1 queries to. Every probe is read-only.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import re
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vectra_mcp_server.config import load_configuration          # noqa: E402
from vectra_mcp_server.vectra_client import (                    # noqa: E402
    VectraAPIError,
    VectraClient,
    VectraRateLimitError,
)

HERE = Path(__file__).resolve().parent
CLAIMS_FILE = HERE / "sql_capability_claims.yaml"
RESOURCES = HERE.parent / "src" / "vectra_mcp_server" / "resources"

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def error_name(exc: VectraAPIError) -> str | None:
    """Pull `error_name` out of the API's error payload.

    Shape observed live:
        {"error": {"extra": [{"error_name": "FUNCTION_NOT_FOUND", ...}], ...}}
    """
    data = getattr(exc, "response_data", None) or {}
    err = data.get("error", data)
    for item in err.get("extra", []) or []:
        if isinstance(item, dict) and item.get("error_name"):
            return item["error_name"]
    return err.get("errorCode")


def documented_tables() -> list[str]:
    """Every `<db>.<table>._all` the SQL reference lists."""
    ref = RESOURCES / "sql_reference.md"
    if not ref.is_file():
        return []
    return sorted(set(re.findall(r"`([a-z_]+\.[a-z_]+\._all)`", ref.read_text())))


#: A claim's outcome. INDETERMINATE means the probe could not decide — a rate
#: limit or a poll timeout — and must never be reported as a failed claim.
OK, FAILED, INDETERMINATE = "ok", "failed", "indeterminate"


async def probe(client: VectraClient, query: str, *,
                poll_timeout: float = 60.0,
                poll_interval: float = 4.0) -> tuple[str, str | None, str]:
    """Submit one query and poll it to completion.

    Submitting is NOT enough. POST /investigations/ only queues the query;
    GET /investigations/{id}/ returns 202 while it runs and 200 when done, so
    analysis errors — FUNCTION_NOT_FOUND, TABLE_NOT_FOUND — surface on the
    *poll*. An earlier version of this script checked only the submit, which
    made every syntactically-parseable query look accepted.

    Returns (outcome, error_name, detail).
    """
    # ---- submit ----
    for attempt in range(4):
        try:
            submission = await client.create_investigation(query)
            break
        except VectraRateLimitError:
            await asyncio.sleep(15 * (attempt + 1))
        except VectraAPIError as e:
            return FAILED, error_name(e), f"rejected at submit: {str(e)[:120]}"
        except Exception as e:                                  # noqa: BLE001
            return FAILED, None, f"{type(e).__name__}: {e}"[:120]
    else:
        return INDETERMINATE, None, "rate limited on submit after 4 attempts"

    request_id = submission.get("requestId") or submission.get("request_id")
    if not request_id:
        return INDETERMINATE, None, f"no request id in submission: {submission}"

    # ---- poll ----
    deadline = asyncio.get_event_loop().time() + poll_timeout
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(poll_interval)
        try:
            res = await client.get_investigation_results(request_id)
        except VectraRateLimitError:
            await asyncio.sleep(15)
            continue
        except VectraAPIError as e:
            return FAILED, error_name(e), f"failed during execution: {str(e)[:120]}"
        except Exception as e:                                  # noqa: BLE001
            return FAILED, None, f"{type(e).__name__}: {e}"[:120]

        # Completion lives in meta.query_status, NOT at the top level. Observed
        # shapes:
        #   running   {"status": "RUNNING", "message": ..., "rows_available": 0}
        #   finished  {"data": [...], "meta": {"query_status": "SUCCESS", ...}}
        # A finished response carries no top-level `status` at all, so the
        # earlier check — top-level status against {"completed","succeeded",...}
        # — could only ever see "". That was survivable for a claim returning
        # rows, because the `data` test caught it first, and silently fatal for
        # one returning none: the loop fell through to "still processing" and
        # polled until the deadline no matter how large the deadline was. Two
        # array claims read as timeouts for exactly this reason, which looked
        # like slow queries and was not.
        meta = res.get("meta") or {}
        qstatus = str(meta.get("query_status", "")).upper()
        if qstatus in {"SUCCESS", "SUCCEEDED", "COMPLETED", "FINISHED", "DONE"}:
            rows = res.get("data") or res.get("results") or []
            n = len(rows) if isinstance(rows, list) else 0
            # Zero rows is a valid query; only execution is under test.
            return OK, None, f"completed, {n} row(s)"
        if qstatus in {"FAILED", "ERROR", "CANCELLED", "CANCELED"}:
            return (FAILED, meta.get("error_name") or res.get("error_name"),
                    f"query_status={qstatus}")

        # Fallbacks for a top-level status, in case the shape changes back.
        data = res.get("data")
        if res.get("results") or (isinstance(data, list) and data):
            return OK, None, "completed with rows"
        status = str(res.get("status", "")).lower()
        if status in {"failed", "error"}:
            return FAILED, res.get("error_name"), f"status={status}"
        if status in {"completed", "succeeded", "done", "finished"}:
            return OK, None, "completed, no rows in window"
        # otherwise still processing — keep polling

    return INDETERMINATE, None, f"still processing after {poll_timeout:.0f}s"


async def run(args) -> int:
    spec = yaml.safe_load(CLAIMS_FILE.read_text())
    claims: list[dict[str, Any]] = spec.get("claims", [])

    if args.tables:
        for t in documented_tables():
            claims.append({
                "id": f"table-{t.replace('.', '-')}",
                "claim": f"{t} is queryable",
                "section": "2",
                "query": (f"SELECT timestamp FROM {t} "
                          f"WHERE timestamp > date_add('hour', -1, now()) LIMIT 1"),
                "expect": "success",
                "generated": True,
            })

    if args.only:
        wanted = set(args.only)
        claims = [c for c in claims if c["id"] in wanted]
        if not claims:
            print(f"no claim matched {sorted(wanted)}", file=sys.stderr)
            return 2

    config = load_configuration(None)
    tenant = config.tenants[0]
    client = VectraClient(config.vectra_config_for_tenant(tenant))

    print(f"probing {len(claims)} claim(s) against {tenant.base_url}\n")

    holds, broken, newly, unknown = [], [], [], []
    for n, c in enumerate(claims):
        if n:
            await asyncio.sleep(args.delay)
        query = c["query"] if c.get("raw") else " ".join(c["query"].split())
        # A claim may raise its own ceiling: array predicates unnest every row
        # and run several times longer than the scalar ones, even with `dt`.
        outcome, ename, detail = await probe(
            client, query,
            poll_timeout=float(c.get("poll_timeout") or args.poll_timeout))

        expect_success = c["expect"] == "success"
        want_name = c.get("error_name")

        if outcome == INDETERMINATE:
            verdict, bucket = f"{DIM}indeterminate{RESET}", unknown
        elif (outcome == OK) == expect_success and (not want_name or ename == want_name):
            verdict, bucket = f"{GREEN}holds{RESET}", holds
        elif expect_success and outcome == FAILED:
            verdict, bucket = f"{RED}BROKEN{RESET}", broken
        elif not expect_success and outcome == OK:
            verdict, bucket = f"{YELLOW}NEWLY PERMITTED{RESET}", newly
        else:
            # rejected as predicted, but not for the documented reason
            verdict, bucket = f"{YELLOW}BROKEN (different error){RESET}", broken

        bucket.append(c["id"])
        gen = f" {DIM}(generated){RESET}" if c.get("generated") else ""
        print(f"  {verdict:<30} §{c.get('section','?'):<4} {c['id']}{gen}")
        print(f"  {DIM}{c['claim']}{RESET}")
        if bucket is not holds:
            if want_name and outcome != INDETERMINATE:
                got = "success" if outcome == OK else (ename or "error")
                print(f"      expected {c['expect']} / {want_name}, got {got}")
            print(f"      {DIM}{detail}{RESET}")
            if c.get("why") and bucket is not unknown:
                print(f"      {DIM}why it matters: {' '.join(c['why'].split())[:150]}{RESET}")
        print()

    print(f"{len(holds)} hold, {len(broken)} broken, "
          f"{len(newly)} newly permitted, {len(unknown)} indeterminate")
    if unknown:
        print(f"\n{DIM}Indeterminate (not a result — rate limited or timed out):{RESET} "
              + ", ".join(unknown))
        print(f"  {DIM}Re-run those with --only, or raise --delay.{RESET}")
    if broken:
        print(f"\n{RED}The reference is wrong about:{RESET} " + ", ".join(broken))
        print("  Fix sql_reference.md / schema_*.md, then re-run.")
    if newly:
        print(f"\n{YELLOW}The API now allows what we forbid:{RESET} " + ", ".join(newly))
        print("  New capability — document it, and relax the recipe validator to match.")

    if args.update_verified:
        # Same reasoning as the checks below, one step earlier: a filtered run
        # cannot support a stamp that means "every claim was checked and held",
        # however green the subset looks. --only is for iterating on one claim;
        # stamping is for a full run.
        if args.only:
            print(f"\n{DIM}not stamping last_verified: --only ran {len(claims)} "
                  f"of the claims, and the stamp asserts a complete run.{RESET}")
        # An indeterminate claim was not verified, so the stamp would assert a
        # completeness that did not happen. Requiring zero of all three is the
        # whole point of having the stamp.
        elif broken or newly or unknown:
            print(f"\n{DIM}not stamping last_verified: "
                  f"{len(broken)} broken, {len(newly)} newly permitted, "
                  f"{len(unknown)} indeterminate — the stamp means every claim "
                  f"was checked and held.{RESET}")
        else:
            text = CLAIMS_FILE.read_text()
            stamp = dt.date.today().isoformat()
            text = re.sub(r"last_verified: .*", f"last_verified: {stamp}", text, count=1)
            CLAIMS_FILE.write_text(text)
            print(f"\nstamped last_verified: {stamp} ({len(holds)} claims)")

    return 1 if (broken or newly) else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--only", nargs="+", metavar="ID", help="run only these claim ids")
    p.add_argument("--tables", action="store_true",
                   help="also probe every table the reference documents")
    p.add_argument("--update-verified", action="store_true",
                   help="stamp last_verified in the claims file when everything holds")
    p.add_argument("--delay", type=float, default=10.0, metavar="SEC",
                   help="pause between claims. The investigations endpoint has a "
                        "much tighter budget than the client's default 100/60s "
                        "limiter, and each claim costs a submit plus polls "
                        "(default: 10)")
    p.add_argument("--poll-timeout", type=float, default=120.0, metavar="SEC",
                   help="give up polling one query after this long. LDAP and "
                        "other wide tables have exceeded 60s (default: 120)")
    args = p.parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
