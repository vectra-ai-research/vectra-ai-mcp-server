#!/usr/bin/env python3
"""Is the v3.5 findings API actually enabled on this tenant?

Every findings path in the API contract carries the `unreleased` tag, so the
endpoints may 404 or 403 regardless of whether the code is correct. This answers
that in seconds, without restarting a connector or rebuilding a plugin.

It also reports two things the contract flags but only a live call can confirm:

  * whether `pivot` is populated — the rendered Investigation Query behind a
    finding, which is the interesting field and is nullable
  * which `category` values this tenant actually uses, since the contract says
    they are product-defined rather than a fixed enum

Usage
-----
    python scripts/probe_findings.py
    python scripts/probe_findings.py --host-id 105314

Needs VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET. Read-only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vectra_mcp_server.config import load_configuration            # noqa: E402
from vectra_mcp_server.vectra_client import VectraClient            # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
)


async def probe(label: str, coro):
    try:
        result = await coro
        return True, result, None
    except Exception as e:                                         # noqa: BLE001
        return False, None, f"{type(e).__name__}: {e}"


async def run(args) -> int:
    config = load_configuration(None)
    tenant = config.tenants[0]
    client = VectraClient(config.vectra_config_for_tenant(tenant))

    print(f"probing v3.5 findings against {tenant.base_url}\n")

    # ---- 1. does the endpoint exist at all? ----
    ok, findings, err = await probe(
        "findings", client.get_findings(size="detailed", page_size=5)
    )
    if not ok:
        print(f"  {RED}findings/ unavailable{RESET}  {err}")
        print(f"\n{DIM}Every findings path is tagged `unreleased`. A 404/403 here "
              f"means the feature is not enabled on this tenant — the tools will "
              f"report that cleanly, but there is nothing to demo.{RESET}")
        return 1

    results = findings.get("results") or []
    total = findings.get("count", len(results))
    print(f"  {GREEN}findings/ available{RESET}  — {total} finding(s) reported, "
          f"{len(results)} returned")

    if not results:
        print(f"\n{YELLOW}Endpoint works but returned no findings.{RESET} "
              f"Nothing to build a demo card on yet.")
        return 0

    # ---- 2. what does a finding look like here? ----
    sample = results[0]
    ftype = sample.get("finding_type") or {}
    print(f"\n  {DIM}sample finding{RESET}")
    print(f"    id            {sample.get('id')}")
    print(f"    type          {ftype.get('name')}")
    print(f"    severity      {ftype.get('severity')}")
    print(f"    category      {ftype.get('category')}")
    print(f"    context       {sample.get('context_short')}")
    print(f"    asset_count   {sample.get('asset_count')}")
    print(f"    status        {sample.get('status')}")
    print(f"    resolutions   {sample.get('resolution_counts')}")

    # ---- 3. the field that matters: is pivot populated? ----
    with_pivot = [r for r in results if r.get("pivot")]
    if with_pivot:
        pivot = with_pivot[0]["pivot"]
        print(f"\n  {GREEN}pivot IS populated{RESET} — findings carry a rendered "
              f"Investigation Query")
        print(f"    {DIM}query{RESET}    {str(pivot.get('query'))[:150]}")
        print(f"    {DIM}queryUrl{RESET} {pivot.get('queryUrl')}")
        print(f"\n  {DIM}This is the interrogability story as an API field: the "
              f"product ships the\n  SQL that substantiates its own claim. Worth "
              f"showing directly.{RESET}")
    else:
        print(f"\n  {YELLOW}pivot is null on all {len(results)} sampled "
              f"findings{RESET} — the pivot feature is off, or no usable query "
              f"renders for these types. Skills must not depend on it.")

    # ---- 4. which categories exist here? (contract says not a fixed enum) ----
    cats = sorted({(r.get("finding_type") or {}).get("category")
                   for r in results if (r.get("finding_type") or {}).get("category")})
    if cats:
        print(f"\n  {DIM}categories seen in this sample:{RESET} {', '.join(cats)}")
    else:
        print(f"\n  {YELLOW}severity and category are null on the sampled "
              f"findings{RESET} — expected: a findings response embeds only the "
              f"type's uid and name.\n  {DIM}Join finding_type.uid against "
              f"/finding_types/ to get severity, category, remediation and "
              f"compliance frameworks.{RESET}")

    ok, types, err = await probe("finding types", client.get_finding_types(page_size=5))
    if ok and (types.get("results") or []):
        t0 = types["results"][0]
        print(f"\n  {GREEN}finding_types/ available{RESET} — "
              f"{types.get('count', '?')} type(s)")
        print(f"    {t0.get('name')}  severity={t0.get('severity')}  "
              f"category={t0.get('category')}")
        if t0.get("compliance_frameworks"):
            print(f"    frameworks: {', '.join(t0['compliance_frameworks'])}")
    elif not ok:
        print(f"\n  {RED}finding_types/ failed{RESET}  {err}")

    # ---- 5. blast radius on the first finding ----
    ok, entities, err = await probe(
        "entities", client.get_finding_entities(finding_id=sample["id"], page_size=5)
    )
    if ok:
        rows = entities.get("results") or []
        print(f"\n  {GREEN}findings/{{id}}/entities/ available{RESET} — "
              f"{entities.get('count', len(rows))} entity finding(s)")
        for r in rows[:3]:
            ent = r.get("entity") or {}
            print(f"    {ent.get('name')}  importance={ent.get('importance')}  "
                  f"urgency={ent.get('urgency')}  ref={r.get('external_reference_id')}")
    else:
        print(f"\n  {RED}findings/{{id}}/entities/ failed{RESET}  {err}")

    # ---- 6. host findings, the investigation-relevant one ----
    if args.host_id:
        ok, hf, err = await probe(
            "host findings",
            client.get_host_findings(host_id=args.host_id, page_size=5),
        )
        if ok:
            rows = hf.get("results") or []
            print(f"\n  {GREEN}hosts/{args.host_id}/findings/ available{RESET} — "
                  f"{hf.get('count', len(rows))} finding(s)")
            for r in rows[:5]:
                t = r.get("finding_type") or {}
                print(f"    [{t.get('severity')}] {t.get('name')} — "
                      f"{r.get('context_short')}")
            if not rows:
                print(f"    {DIM}(none on this host — try another, or drop the "
                      f"status filter){RESET}")
        else:
            print(f"\n  {RED}hosts/{args.host_id}/findings/ failed{RESET}  {err}")
    else:
        print(f"\n  {DIM}pass --host-id <id> to also probe host findings — that is "
              f"the endpoint that pairs with an entity investigation.{RESET}")

    if args.dump:
        print(f"\n{DIM}--- raw first finding ---{RESET}")
        print(json.dumps(sample, indent=2, default=str))

    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host-id", type=int,
                   help="also probe /hosts/{id}/findings/ for this host")
    p.add_argument("--dump", action="store_true",
                   help="print the raw JSON of the first finding")
    try:
        return asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
