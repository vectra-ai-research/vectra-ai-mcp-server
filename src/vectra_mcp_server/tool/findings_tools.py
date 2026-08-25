"""Posture findings tools.

Deliberately a separate module from detection_tools. Findings are a different
axis, not more detections:

    detections  ->  is something happening?      threat behaviour, active
    findings    ->  what makes this possible?    standing exposure

They also have their own lifecycle — Open / In Progress / **Risk Accepted** —
rather than triage-to-verdict. Keeping them apart is what stops an agent
applying a detection verdict rubric to an open port, where "TP-High" means
nothing.

All of these are v3.5 and the API contract tags every findings path
`unreleased`. They may be unavailable on a given tenant; that is reported as a
result, not raised as a failure, so a skill can degrade instead of breaking.
"""

from typing import Annotated, Literal
from pydantic import Field
import json

from .base import READ_ONLY, BaseMCPTools

#: Well below the API's 5000 ceiling. A `detailed` page at 5000 rows would
#: swamp an agent's context; there is no useful agentic workflow at that size.
_MAX_PAGE = 200

_UNAVAILABLE = (
    "Findings may not be enabled on this tenant — every findings endpoint is "
    "tagged `unreleased` in the API contract. Treat this as 'not available "
    "here', not as evidence that the host or finding has no exposure."
)


def _wrap(payload: dict, note: str | None = None) -> str:
    if note:
        payload = {**payload, "note": note}
    return json.dumps(payload, indent=2, default=str)


class FindingsMCPTools(BaseMCPTools):
    """MCP tools for posture findings (exposure), as distinct from detections."""

    def register_tools(self):
        """Register all findings tools with the MCP server."""
        self._register_tool(self.get_host_findings, READ_ONLY)
        self._register_tool(self.list_findings, READ_ONLY)
        self._register_tool(self.list_finding_entities, READ_ONLY)
        self._register_tool(self.list_finding_types, READ_ONLY)

    async def get_host_findings(
        self,
        host_id: Annotated[
            int, Field(ge=1, description="Vectra host entity id to list findings for.")
        ],
        severity: Annotated[
            Literal["low", "medium", "high", "critical"] | None,
            Field(description="Restrict to one severity. Leave unset for all.")
        ] = None,
        status: Annotated[
            Literal["all", "active", "inactive"],
            Field(description="Finding status. 'active' is current exposure; "
                              "'inactive' means it is no longer observed.")
        ] = "active",
        category: Annotated[
            str | None,
            Field(description="Canonical lowercase snake_case category, e.g. "
                              "'risky_protocol_activity'. Values are "
                              "product-defined and NOT a fixed enum, so an "
                              "unknown value is rejected by the API rather "
                              "than by this tool. Call list_findings without "
                              "filters first to learn which categories exist "
                              "in this tenant.")
        ] = None,
        resolution: Annotated[
            str | None,
            Field(description="Workflow state of the exposure. The contract "
                              "documents 'Open', 'In Progress' and 'Risk "
                              "Accepted', but this tenant's resolution_counts "
                              "came back keyed 'open' and 'remediated' "
                              "(probed 2026-08-24) — 'remediated' is not in the "
                              "documented set. Left as a free string rather "
                              "than a closed enum so a valid value is not "
                              "rejected client-side; check resolution_counts on "
                              "a findings response to see what this tenant "
                              "actually uses.")
        ] = None,
        last_seen_gte: Annotated[
            str | None,
            Field(description="ISO-8601 lower bound on last_seen. Use this "
                              "rather than trying to sort by recency — the API "
                              "cannot order by last_seen.")
        ] = None,
        page_size: Annotated[
            int, Field(ge=1, le=_MAX_PAGE, description="Findings per page.")
        ] = 50,
        page: Annotated[int, Field(ge=1, description="1-based page number.")] = 1,
    ) -> str:
        """
        List posture findings for one host — the exposure that made an attack path possible.

        Pairs with an entity investigation: a detection timeline says what
        happened, findings say why the host was reachable. Use it when asked
        about infection vector, attack surface, or how something got in.

        This endpoint takes no `size` parameter — unlike list_findings — and
        sending one returns 400.

        **This is where the useful `pivot` lives.** Findings here carry a
        *host-scoped* rendered Investigation Query — the SQL that substantiates
        this finding on this host. list_findings is a tenant-wide view of the
        finding type, so its pivot is often null: there is no single host to
        scope a query to. Verified 2026-08-24: "Passwords in Cleartext over
        HTTP" had pivot null via list_findings and a rendered, directly
        executable host-specific query here.

        So the loop is: get_host_findings -> read pivot.query -> run_investigation.
        No substitution needed; the query came back as valid single-line SQL.

        Severity is returned inline here (unlike list_findings, where it was
        null). Use list_finding_types for remediation, compliance_frameworks and
        rationale — those are only in the type catalogue.

        Treat a finding as a *lead*, not a conclusion. The pivot exists so the
        claim can be checked, and checking sometimes refutes it: the cleartext
        finding above turned out to be an Nmap NSE probe with empty credential
        parameters, i.e. a pattern match on URL shape rather than a real leak.

        Returns:
            str: JSON with the findings page, or a note if findings are unavailable.
        """
        try:
            result = await self.client.get_host_findings(
                host_id=host_id, severity=severity, category=category,
                status=status, resolution=resolution,
                last_seen_gte=last_seen_gte,
                page=page, page_size=page_size,
            )
            if not result.get("results"):
                return _wrap(
                    {"host_id": host_id, "count": 0, "results": []},
                    "No findings matched. If this host is expected to have "
                    "exposure, check the status and severity filters before "
                    "concluding there is none.",
                )
            return _wrap(result)
        except Exception as e:                                    # noqa: BLE001
            return _wrap(
                {"host_id": host_id, "error": str(e), "findings_available": False},
                _UNAVAILABLE,
            )

    async def list_findings(
        self,
        severity: Annotated[
            Literal["low", "medium", "high", "critical"] | None,
            Field(description="Restrict to one severity.")
        ] = None,
        status: Annotated[
            Literal["all", "active", "inactive"],
            Field(description="Finding status.")
        ] = "active",
        category: Annotated[
            str | None,
            Field(description="Canonical lowercase snake_case category. "
                              "Product-defined, not a fixed enum.")
        ] = None,
        resolution: Annotated[
            str | None,
            Field(description="Workflow state of the exposure. Documented as "
                              "'Open' / 'In Progress' / 'Risk Accepted', but "
                              "this tenant reported 'open' and 'remediated' "
                              "(probed 2026-08-24). Free string rather than a "
                              "closed enum so a valid value is not rejected "
                              "client-side.")
        ] = None,
        finding_type_uid: Annotated[
            str | None,
            Field(description="Restrict to one finding type by uid.")
        ] = None,
        last_seen_gte: Annotated[
            str | None,
            Field(description="ISO-8601 lower bound on last_seen. Prefer this "
                              "over sorting by recency, which the API does not "
                              "support.")
        ] = None,
        ordering: Annotated[
            Literal["severity", "-severity"] | None,
            Field(description="The ONLY sortable field is severity ('-' for "
                              "descending). The API explicitly does not support "
                              "ordering by first_seen, last_seen, status or "
                              "asset_count — and sorting those client-side "
                              "only orders the page you fetched, which "
                              "produces a plausible but wrong 'top N'.")
        ] = None,
        size: Annotated[
            Literal["small", "regular", "detailed"],
            Field(description="Response verbosity.")
        ] = "regular",
        page_size: Annotated[
            int, Field(ge=1, le=_MAX_PAGE, description="Findings per page.")
        ] = 50,
        page: Annotated[int, Field(ge=1, description="1-based page number.")] = 1,
    ) -> str:
        """
        List posture findings across the environment — the standing exposure inventory.

        This is a portfolio view, not a work queue. Findings have no
        urgency-ranked backlog and the detection verdict framework does not
        apply to them: an open port is not a true or false positive. Do not fold
        these into detection triage.

        Useful for exposure posture questions, severity distribution, and
        governance reporting — `resolution` distinguishes what is Open from what
        has been explicitly Risk Accepted.

        `pivot` here is frequently null even with size='detailed'. This is a
        tenant-wide view of a finding *type* across many assets, so there is
        often no single host to scope a query to. For a runnable, host-specific
        Investigation Query use get_host_findings instead — that is where the
        rendered pivot appears.

        Returns:
            str: JSON with the findings page, or a note if findings are unavailable.
        """
        try:
            result = await self.client.get_findings(
                severity=severity, category=category, status=status,
                resolution=resolution, finding_type_uid=finding_type_uid,
                last_seen_gte=last_seen_gte, size=size, ordering=ordering,
                page=page, page_size=page_size,
            )
            if not result.get("results"):
                return _wrap(
                    {"count": 0, "results": []},
                    "No findings matched these filters.",
                )
            return _wrap(result)
        except Exception as e:                                    # noqa: BLE001
            return _wrap({"error": str(e), "findings_available": False}, _UNAVAILABLE)

    async def list_finding_types(
        self,
        size: Annotated[
            Literal["small", "regular", "detailed"],
            Field(description="'regular' carries severity, category, "
                              "remediation, rationale and compliance "
                              "frameworks — usually what you want.")
        ] = "regular",
        page_size: Annotated[
            int, Field(ge=1, le=_MAX_PAGE, description="Types per page.")
        ] = 100,
        page: Annotated[int, Field(ge=1, description="1-based page number.")] = 1,
    ) -> str:
        """
        The finding type catalogue — severity, category, remediation and compliance mapping.

        Call this alongside a findings list, not instead of it. `list_findings`
        embeds only the type's `uid` and `name` — severity and category came
        back null there when probed, though `get_host_findings` does return
        severity. Remediation, compliance frameworks and rationale are only
        available here regardless. Join on `finding_type.uid` to get:

          severity              low / medium / high / critical
          category              product-defined snake_case identifier
          remediation           what to actually do about it
          compliance_frameworks which frameworks the exposure maps to
          rationale             why it is considered a risk

        Without this, an agent can report that an exposure exists but not how
        serious it is or how to fix it.

        Returns:
            str: JSON with the finding type catalogue, or a note if unavailable.
        """
        try:
            result = await self.client.get_finding_types(
                size=size, page=page, page_size=page_size,
            )
            if not result.get("results"):
                return _wrap({"count": 0, "results": []},
                             "No finding types returned.")
            return _wrap(result)
        except Exception as e:                                    # noqa: BLE001
            return _wrap({"error": str(e), "findings_available": False}, _UNAVAILABLE)

    async def list_finding_entities(
        self,
        finding_id: Annotated[
            str,
            Field(min_length=1, description="Finding id, e.g. "
                                            "'F1__33skgTZwPiSYavqaB78xu'. From "
                                            "the `id` field of a findings list.")
        ],
        page_size: Annotated[
            int, Field(ge=1, le=_MAX_PAGE, description="Entities per page.")
        ] = 50,
        page: Annotated[int, Field(ge=1, description="1-based page number.")] = 1,
    ) -> str:
        """
        List every entity carrying one finding — the blast radius of a single exposure.

        Answers "how many other assets have this same weakness?". This is
        breadth on the *exposure* axis, distinct from sweeping metadata for an
        indicator of compromise.

        Each row carries the entity's `importance` and `urgency`, so a
        widespread finding can be prioritised by which assets it lands on rather
        than by count alone.

        Returns:
            str: JSON with the entity findings page, or a note if unavailable.
        """
        try:
            result = await self.client.get_finding_entities(
                finding_id=finding_id, page=page, page_size=page_size,
            )
            if not result.get("results"):
                return _wrap(
                    {"finding_id": finding_id, "count": 0, "results": []},
                    "No entities returned for this finding id. Verify the id "
                    "came from a findings list on this tenant.",
                )
            return _wrap(result)
        except Exception as e:                                    # noqa: BLE001
            return _wrap(
                {"finding_id": finding_id, "error": str(e),
                 "findings_available": False},
                _UNAVAILABLE,
            )
