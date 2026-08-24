"""MCP tools for security investigations."""

import asyncio
import re
from typing import Literal, List, Annotated
from pydantic import Field
import json

from ..utils.logging import get_logger
from ..utils.validators import validate_date_range
from .base import (
    ADDITIVE,
    ADDITIVE_EACH_CALL,
    DESTRUCTIVE,
    READ_ONLY,
    BaseMCPTools,
)

logger = get_logger(__name__)

# Hard timeout for investigation API calls (seconds).
# Prevents a slow/hanging Vectra API from blocking the entire MCP server.
_INVESTIGATION_TIMEOUT = 20

#: A token safe to emit as an unquoted SQL identifier.
_BARE_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def unquote_identifier_aliases(query: str) -> str:
    """Turn single-quoted aliases into bare identifiers.

    The dialect rejects ``AS 'x'`` outright with SYNTAX_ERROR. Far worse, it
    *accepts* ``ORDER BY 'x'`` — as an ordering on a string constant, which
    sorts by nothing. Combined with LIMIT that returns an arbitrary slice, so
    a "top 10" query built this way succeeds and is silently not a top 10.
    Verified live: ``ORDER BY 'n' DESC LIMIT 10`` returned counts in the order
    17, 2, 13, 52, 14, 26, 169, 1, 1, 18.

    Double quotes are the correct Trino spelling, but they cannot survive the
    sanitiser: models routinely use them for string literals, where they are
    invalid, so every ``"`` is folded to ``'``. That fold is what manufactures
    both broken forms. This undoes it for the two positions where an
    identifier — never a literal — is what was meant.

    Only whole terms are unquoted, so a genuine literal inside an ORDER BY
    expression (``ORDER BY CASE WHEN x = 'a' THEN 1 END``) is left alone.
    """
    query = re.sub(rf"\bAS\s+'({_BARE_IDENT})'", r"AS \1", query, flags=re.I)

    def _unquote_terms(m: re.Match) -> str:
        terms = [
            re.sub(rf"^(\s*)'({_BARE_IDENT})'(\s+(?:ASC|DESC))?(\s*)$",
                   r"\1\2\3\4", term, flags=re.I)
            for term in m.group(2).split(",")
        ]
        return m.group(1) + ",".join(terms)

    return re.sub(
        r"\b((?:ORDER|GROUP)\s+BY\s+)(.*?)"
        r"(?=\s+(?:LIMIT|HAVING|ORDER|OFFSET|UNION)\b|$)",
        _unquote_terms, query, flags=re.I,
    )


def strip_sql_comments(query: str) -> str:
    """Remove SQL comments, leaving single-quoted literals untouched.

    This MUST run before whitespace normalisation. Collapsing newlines first
    turns a `-- comment` line into a comment that swallows everything after it
    on the joined line — the remaining predicates, the ORDER BY, and the LIMIT.
    The query then runs unfiltered and unbounded instead of failing, which is
    strictly worse than a 400.

    Literal-aware on purpose: `--` inside a string is data, not a comment. A
    hunt for SQL-injection patterns in HTTP URIs legitimately searches for it,
    and a regex strip would corrupt that query.
    """
    out: list[str] = []
    i, n = 0, len(query)
    in_literal = False

    while i < n:
        ch = query[i]

        if in_literal:
            out.append(ch)
            if ch == "'":
                # '' is an escaped quote *inside* a literal, not its end.
                if i + 1 < n and query[i + 1] == "'":
                    out.append(query[i + 1])
                    i += 2
                    continue
                in_literal = False
            i += 1
            continue

        if ch == "'":
            in_literal = True
            out.append(ch)
            i += 1
            continue

        if query.startswith("--", i):
            nl = query.find("\n", i)
            i = n if nl == -1 else nl
            out.append(" ")
            continue

        if query.startswith("/*", i):
            close = query.find("*/", i + 2)
            i = n if close == -1 else close + 2
            out.append(" ")
            continue

        out.append(ch)
        i += 1

    return "".join(out)


class InvestigationMCPTools(BaseMCPTools):
    """MCP tools for investigations."""

    def register_tools(self):
        """Register all investigation tools with the MCP server."""
        # Each call creates a new assignment object.
        self._register_tool(self.create_assignment, ADDITIVE_EACH_CALL)
        self._register_tool(self.list_assignments, READ_ONLY)
        self._register_tool(self.list_assignments_for_user, READ_ONLY)
        # Removes an existing assignment.
        self._register_tool(self.delete_assignment, DESTRUCTIVE)
        self._register_tool(self.get_assignment_detail_by_id, READ_ONLY)
        self._register_tool(self.get_assignment_for_entity, READ_ONLY)
        # Each call appends a new note.
        self._register_tool(self.create_entity_note, ADDITIVE_EACH_CALL)
        # DEPRECATED in favour of close_detections; writes the legacy
        # mark_as_fixed field, which is separate state from close/open.
        self._register_tool(self.mark_detection_fixed, DESTRUCTIVE)
        # Removes detections from the queue and from entity scoring.
        self._register_tool(self.close_detections, DESTRUCTIVE)
        # Restores closed detections to the queue; triggers a rescore.
        self._register_tool(self.reopen_detections, ADDITIVE)
        # Submits a new async query job; returns a fresh request_id each call.
        self._register_tool(self.run_investigation, ADDITIVE_EACH_CALL)
        self._register_tool(self.get_investigation_results, READ_ONLY)
        # v3.5 events endpoint — lifecycle and MITRE, neither on the detection.
        self._register_tool(self.get_detection_history, READ_ONLY)
        # Overwrites customer workflow metadata, not security state.
        self._register_tool(self.set_detection_workflow_state, ADDITIVE)

    async def list_assignments(
            self,
            resolved: Annotated[
                bool, 
                Field(description="Filter assignments by resolved state. True for resolved, False for unresolved. Default is False.")
            ] = False,
            created_after: Annotated[
                str | None,
                Field(description="Use this to list assignments created at or after this time stamp (YYYY-MM-DDTHH:MM:SS)")
            ] = None
        ) -> str:
        """
        List all investigation assignments with optional filtering by timestamp and resolved state.
        
        Returns:
            str: JSON string with list of assignments.
        """
        try:
            search_params = {"resolved" : resolved}

            # Validate and convert date strings to datetime objects
            start_date, end_date = validate_date_range(created_after, None)
            if start_date:
                search_params["created_after"] = start_date.isoformat()

            assignments = await self.client.get_assignments(**search_params)

            if assignments is None:
                return "No assignments found."
            return json.dumps(assignments, indent=2)
        except Exception as e:
            raise Exception(f"Failed to list assignments: {str(e)}")
        
    async def list_assignments_for_user(
            self,
            user_id: Annotated[
                int, 
                Field(description="Vectra platform user ID to retrieve assignments for.")
            ],
            resolved: Annotated[
                bool, 
                Field(description="Filter assignments by resolved state. True for resolved, False for unresolved. Default is False to retrieve only unresolved/open assignments.")
            ] = False,
        ) -> str:
        """
        List all investigation assignments assigned to a user/analyst.
        
        Returns:
            str: JSON string with list of assignments.
        """
        try:
            assignments = await self.client.get_assignments(
                assignees = user_id,
                resolved = resolved
                )
            if assignments is None:
                return "No assignments found."
            return json.dumps(assignments, indent=2)
        except Exception as e:
            raise Exception(f"Failed to list assignments: {str(e)}")
        
    async def get_assignment_detail_by_id(
        self,
        assignment_id: Annotated[
            int,
            Field(ge=1, description="ID of the assignment to retrieve")
        ]    
    ) -> str:
        """
        Retrieve details of a specific investigation assignment.

        Returns:
            str: JSON string with details of the assignment.
        Raises:
            Exception: If fetching assignment details fails.
        """
        try:
            assignment_details = await self.client.get_assignment(assignment_id)

            return json.dumps(assignment_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to list assignment : {assignment_id}: {str(e)}")
        
    async def get_assignment_for_entity(
        self,
        entity_ids: Annotated[
            List[int], 
            Field(description="List of entity IDs to retrieve assignment for")
        ],
        entity_type: Annotated[
            Literal["host", "account"], 
            Field(description="Type of entity to retrieve assignment for (host or account)")
        ]
    ) -> str:
        """
        Retrieve investigation assignment for a specific account.

        Returns:
            str: JSON string with assignment details for the account.
        Raises:
            Exception: If fetching assignment fails.
        """
        try:
            if entity_type not in ["host", "account"]:
                raise ValueError("entity_type must be either 'host' or 'account'.")
            
            if entity_type == "host":
                search_params = {
                    "hosts": ",".join(map(str, entity_ids)) # stitch entity ids separated by commas
                }
            else:
                search_params = {
                    "accounts": ",".join(map(str, entity_ids)) # stitch entity ids separated by commas
                }
            
            # Fetch assignments for the entity
            assignments = await self.client.get_assignments(**search_params)

            if not assignments['results']:
                return f"No assignments found for {entity_type}: {entity_ids}."
            
            return json.dumps(assignments['results'], indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch assignment for {entity_type}: {entity_ids}: {str(e)}")
    
    async def create_assignment(
        self,
        assign_to_user_id: Annotated[
            int, 
            Field(ge=1, description="ID of the user to assign the entity to")
        ],
        assign_entity_id: Annotated[
            int, 
            Field(description="ID of the entity (account or host) to assign.")
        ],
        assign_entity_type: Annotated[
            Literal["account", "host"], 
            Field(description="Type of the entity (account or host) to assign. This is the type of the entity specified in assign_entity_id")
        ]
    ) -> str:
        """
        Create investigation assignment for an account or host
        
        Returns:
            str: Formatted string with assignment details.
        Raises:
            Exception: If assignment creation fails.
        """

        # Prepare assignment data
        assignment_data = {
            "assign_to_user_id": assign_to_user_id,
        }

        # Create payload based on entity type
        if assign_entity_type == "account":
            assignment_data["assign_account_id"] = assign_entity_id
        else:
            assignment_data["assign_host_id"] = assign_entity_id

        try:
            # Create the assignment
            assignment = await self.client.create_assignment(assignment_data)
            assignment_id = assignment.get("assignment").get("id")
            
            # Return assignment details
            return json.dumps(assignment)
            
        except Exception as e:
            raise Exception(f"Failed to create assignment: {str(e)}")
        
    async def create_entity_note(
            self,
            entity_id: Annotated[
                int, Field(ge=1, description="ID of the entity to add note to")
            ],
            entity_type: Annotated[
                Literal["host", "account"], 
                Field(description="Type of entity to add note to (host or account)")
            ],
            note: Annotated[
                str, 
                Field(description="Note text to add to the entity.")
            ]
    ) -> str:
        """
        Add an investigation note to an entity (host or account).
        
        Returns:
            str: Confirmation message with note details.
        """
        try:
            if entity_type not in ["host", "account"]:
                raise ValueError("entity_type must be either 'host' or 'account'.")
            
            params = {}

            params["entity_id"] = entity_id
            
            params["type"] = entity_type
            
            # Add note to the entity
            params["note"] = note

            create_note = await self.client.add_entity_note(**params)

            # Return note assignment details
            return json.dumps(create_note, indent=2)
        except Exception as e:
            raise Exception(f"Failed to add note to entity {entity_id}: {str(e)}")
        
    async def mark_detection_fixed(
        self,
        detection_ids: Annotated[
            List[int], 
            Field(description="List of detection IDs to mark as fixed or not fixed")
        ],
        mark_fixed: Annotated[
            bool, 
            Field(description="True to mark as fixed, False to unmark as fixed")
        ]
    ) -> str:
        """
        DEPRECATED -- use close_detections instead. Marks or unmarks detections as fixed.

        This writes the legacy 'mark_as_fixed' field via PATCH /detections, which is
        SEPARATE STATE from the close/open lifecycle. A detection closed with
        close_detections cannot be reopened by calling this with mark_fixed=False,
        and a detection marked fixed here does not carry a close reason.

        Prefer close_detections (which records why: remediated or benign) and
        reopen_detections (which reverses it). This tool remains only for
        compatibility with existing callers and will be removed in 0.5.0.

        Returns:
            str: Confirmation message of operation.
        Raises:
            Exception: If marking detections fails.
        """
        if not detection_ids:
            return "No detection IDs provided."

        try:
            response = await self.client.mark_detection_fixed(detection_ids, mark_fixed)
            return f"Marked {len(detection_ids)} detections as {'fixed' if mark_fixed else 'not fixed'}."
        except Exception as e:
            raise Exception(f"Failed to mark detections: {str(e)}")

    async def close_detections(
        self,
        detection_ids: Annotated[
            List[int],
            Field(description="IDs of the detections to close. Pass a single-element list to close one.")
        ],
        reason: Annotated[
            Literal["remediated", "benign"],
            Field(description=(
                "Reason for closing. "
                "'remediated' — a corrective action was taken to address the threat. "
                "'benign' — the activity was reviewed and determined not to be a threat."
            ))
        ],
    ) -> str:
        """
        Close one or more detections, removing them from the active queue and
        stopping them from contributing to entity scoring.

        All detections in the call are closed with the same reason, so group IDs by
        reason and make one call per reason. Reversible with reopen_detections.

        Returns:
            str: JSON confirmation from the API, or an error message.
        """
        if not detection_ids:
            return "No detection IDs provided."

        try:
            result = await self.client.close_detections(
                detection_ids=detection_ids, reason=reason
            )
            return json.dumps(result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to close detections {detection_ids}: {str(e)}")

    async def get_detection_history(
        self,
        detection_id: Annotated[
            int,
            Field(description="ID of the detection to retrieve the event history for.", ge=1)
        ],
        change_type: Annotated[
            Literal["new", "append", "triage", "update", "adjust", "state"] | None,
            Field(description=(
                "Restrict to one kind of change. 'new' = first fired, 'append' = "
                "recurred with new activity, 'triage' = triaged, 'adjust' = score or "
                "metadata changed, 'state' = state changed. Leave unset for the full "
                "history."
            ))
        ] = None,
    ) -> str:
        """
        Get the full change history of a single detection — when it first fired,
        each time it recurred, and each time it was triaged, rescored or had
        metadata changed.

        Two things here are on no other endpoint: `change_type`, and `mitre`
        technique IDs. Note the detection's own `grouped_details` covers
        recurrence but not `adjust`/`triage` events, so it is not a substitute.

        Answers "has this been recurring, and has anyone touched it?" — the
        question a daily-recurring detection raises.

        Scoped to one detection deliberately. Each event repeats the detection's
        context, so a queue-wide history query would be enormous.

        Returns:
            str: JSON with the merged event list, oldest first, plus the
                investigation statuses that were queried.
        """
        try:
            result = await self.client.get_detection_events(
                detection_id=detection_id, change_type=change_type
            )
            return json.dumps(result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to get history for detection {detection_id}: {str(e)}")

    async def set_detection_workflow_state(
        self,
        detection_ids: Annotated[
            List[int],
            Field(description="IDs of the detections to update. Pass a single-element list for one.")
        ],
        external_reference_id: Annotated[
            str | None,
            Field(description=(
                "Reference to an item in an external system — typically the ticket "
                "that owns this work, e.g. 'TICKET-12345'. This, not the Vectra "
                "assignment, is where external ownership belongs."
            ))
        ] = None,
        investigation_status: Annotated[
            Literal["open", "acknowledged", "escalated", "paused", "closed", "expired"] | None,
            Field(description="Workflow state for automation. Leave unset to change only the external reference.")
        ] = None,
    ) -> str:
        """
        Set the external reference and/or investigation status on detections.

        This is how a detection is linked to the ticket that owns it, and how its
        position in a workflow is recorded. Distinct from two other things:
        `create_assignment` acknowledges a detection and starts the platform's
        metrics timers; `close_detections` ends its life in the queue. This tool
        does neither — it annotates.

        Both fields are **write-only from the detection resource**: GET
        /detections will not return them. Read them back with
        get_detection_history.

        Returns:
            str: JSON confirmation from the API, or an error message.
        """
        if not detection_ids:
            return "No detection IDs provided."
        if external_reference_id is None and investigation_status is None:
            return "Nothing to set — provide external_reference_id, investigation_status, or both."

        try:
            result = await self.client.set_detection_workflow_state(
                detection_ids=detection_ids,
                external_reference_id=external_reference_id,
                investigation_status=investigation_status,
            )
            return json.dumps(result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to set workflow state on {detection_ids}: {str(e)}")

    async def reopen_detections(
        self,
        detection_ids: Annotated[
            List[int],
            Field(description="IDs of the closed detections to re-open. Pass a single-element list to re-open one.")
        ],
    ) -> str:
        """
        Re-open one or more previously closed detections, returning them to the
        active queue.

        Opening triggers a rescore of the affected entities, so their urgency
        scores may change as a result of this call. This reverses close_detections;
        it does not reverse mark_detection_fixed, which writes separate state.

        Returns:
            str: JSON confirmation from the API, or an error message.
        """
        if not detection_ids:
            return "No detection IDs provided."

        try:
            result = await self.client.reopen_detections(detection_ids=detection_ids)
            return json.dumps(result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to re-open detections {detection_ids}: {str(e)}")

    async def delete_assignment(
        self,
        assignment_id: Annotated[
            int,
            Field(ge=1, description="ID of the assignment to delete")
        ]
    ) -> str:
        """
        Unassign or delete an investigation assignment by its ID. Use list_assignments and list_assignments_for_user to fetch assignment IDs.

        Returns:
            str: Confirmation message of deletion.
        Raises:
            Exception: If deleting assignment fails.
        """
        try:
            await self.client.delete_assignment(assignment_id)
            return f"Assignment {assignment_id} deleted successfully."
        except Exception as e:
            raise Exception(f"Failed to delete assignment {assignment_id}: {str(e)}")

    async def run_investigation(
        self,
        query: Annotated[
            str,
            Field(description=(
                "SQL query in the Vectra Trino-like dialect. "
                "Must be a SELECT statement with a LIMIT clause and a timestamp filter. "
                "CRITICAL FORMATTING RULES: "
                "1) The query MUST be a single line with NO line breaks (no \\n, no newlines). "
                "2) NEVER use double quotes anywhere in the query. Single quotes are for "
                "string literals ONLY. "
                "3) Column aliases MUST be bare identifiers with no quotes of any kind: "
                "write AS failure_count, and ORDER BY failure_count. Never AS 'failure_count' — "
                "that is a syntax error — and never ORDER BY 'failure_count', which is accepted "
                "as an ordering on a string constant and silently returns unsorted rows, so a "
                "top-N query comes back plausible and wrong. ORDER BY 2 (a column position) "
                "also works. "
                "4) NEVER use escaped quotes (no \\\" or \\\\'). "
                "Example: SELECT id.orig_h, count(*) AS failure_count FROM network.kerberos._all WHERE timestamp BETWEEN date_add('day', -7, now()) AND now() GROUP BY id.orig_h ORDER BY failure_count DESC LIMIT 100 "
                "IMPORTANT: Before calling this tool, you MUST first call "
                "get_investigation_sql_reference to learn the supported SQL syntax, "
                "and get_investigation_schema with the relevant data_source to learn "
                "the exact column names available for your query."
            ))
        ],
    ) -> str:
        """
        Submit an investigation SQL query and return the request_id. This tool returns immediately — the query runs asynchronously. Use get_investigation_results with the returned request_id to fetch results. Before using this tool, ALWAYS call get_investigation_sql_reference and get_investigation_schema first. The query MUST be a single line (no newlines), MUST use single quotes for string literals only (no double quotes anywhere), MUST write column aliases as bare unquoted identifiers (AS failure_count, ORDER BY failure_count), and MUST NOT contain escaped quotes.

        Returns:
            str: JSON with request_id and searchable_range. Use request_id with get_investigation_results.
        """
        # Sanitize. Two steps are order-dependent, in opposite directions, and
        # both failures are silent — so this sequence is load-bearing:
        #
        #   strip_sql_comments FIRST, before newlines collapse. Join the lines
        #   with a `--` comment still in place and it swallows every clause
        #   after it, LIMIT included, leaving the query unbounded.
        #
        #   unquote_identifier_aliases LAST, after the double-quote fold. That
        #   fold is what manufactures the broken alias forms, so repairing
        #   before it runs fixes nothing. `ORDER BY 'x'` is the dangerous case:
        #   the dialect accepts it as an ordering on a string constant and
        #   returns unsorted rows without error.
        #
        # The fold itself is not optional — models reach for double quotes on
        # string literals, which this dialect rejects.
        query = strip_sql_comments(query)
        query = " ".join(query.split())
        query = query.replace('\\"', '"').replace("\\'", "'")
        query = query.replace('"', "'")
        query = unquote_identifier_aliases(query)

        from ..vectra_client import VectraAPIError

        logger.info("run_investigation: submitting query: %s", query)

        try:
            submission = await asyncio.wait_for(
                self.client.create_investigation(query),
                timeout=_INVESTIGATION_TIMEOUT,
            )
            request_id = submission.get("requestId") or submission.get("request_id")
            logger.info("run_investigation: query submitted, request_id=%s", request_id)
            return json.dumps({
                "request_id": request_id,
                "query": query,
                "searchable_range": submission.get("searchable_range") or submission.get("searchableRange"),
                "status": "submitted",
                "next_step": "Call get_investigation_results with this request_id to fetch results. The query may take a few seconds to complete.",
            }, indent=2)
        except asyncio.TimeoutError:
            logger.error("run_investigation: API call timed out after %ds for query: %s", _INVESTIGATION_TIMEOUT, query)
            return json.dumps({
                "error": f"Investigation API timed out after {_INVESTIGATION_TIMEOUT}s. The Vectra API may be slow or unreachable. Try again.",
                "query": query,
            }, indent=2)
        except VectraAPIError as e:
            logger.error("run_investigation: API error status_code=%s error=%s", e.status_code, str(e))
            return json.dumps({
                "error": str(e),
                "query": query,
                "status_code": e.status_code,
                "api_response": e.response_data,
            }, indent=2)
        except Exception as e:
            logger.error("run_investigation: unexpected error: %s", str(e), exc_info=True)
            return json.dumps({
                "error": f"Failed to submit investigation query: {str(e)}",
                "query": query,
            }, indent=2)

    async def get_investigation_results(
        self,
        request_id: Annotated[
            str,
            Field(description="The request_id returned by run_investigation.")
        ],
        page: Annotated[
            int,
            Field(description="Page number (1-indexed).", ge=1)
        ] = 1,
        page_size: Annotated[
            int,
            Field(description="Number of rows per page.", ge=1, le=5000)
        ] = 100,
    ) -> str:
        """
        Fetch results for a previously submitted investigation query. If the query is still running, the response will indicate the status — call this tool again after a few seconds. Use the request_id returned by run_investigation.

        Returns:
            str: JSON with query status and results. If status is RUNNING or PENDING, call again after a few seconds.
        """
        from ..vectra_client import VectraAPIError

        logger.info("get_investigation_results: fetching request_id=%s page=%d page_size=%d", request_id, page, page_size)

        try:
            result = await asyncio.wait_for(
                self.client.get_investigation_results(
                    request_id,
                    page=page,
                    page_size=page_size,
                ),
                timeout=_INVESTIGATION_TIMEOUT,
            )

            status = result.get("status")
            query_status = result.get("meta", {}).get("query_status")
            logger.info("get_investigation_results: request_id=%s status=%s query_status=%s", request_id, status, query_status)

            if status == "failed":
                logger.warning("get_investigation_results: query failed request_id=%s error=%s", request_id, result.get("error"))
                return json.dumps({
                    "error": "Investigation query failed",
                    "request_id": request_id,
                    "status": status,
                    "error_details": result.get("error"),
                    "api_response": result,
                }, indent=2)

            if query_status in ("RUNNING", "PENDING") or status in ("pending", "processing"):
                rows = result.get("meta", {}).get("num_rows_available", 0)
                logger.info("get_investigation_results: still running request_id=%s rows_available=%s", request_id, rows)
                return json.dumps({
                    "request_id": request_id,
                    "status": query_status or status,
                    "message": "Query is still running. Call get_investigation_results again in a few seconds.",
                    "rows_available": rows,
                }, indent=2)

            row_count = result.get("meta", {}).get("num_rows_available") or result.get("results", {}).get("row_count", "?")
            logger.info("get_investigation_results: completed request_id=%s rows=%s", request_id, row_count)
            return json.dumps(result, indent=2)

        except asyncio.TimeoutError:
            logger.error("get_investigation_results: API call timed out after %ds for request_id=%s", _INVESTIGATION_TIMEOUT, request_id)
            return json.dumps({
                "error": f"Investigation API timed out after {_INVESTIGATION_TIMEOUT}s. The Vectra API may be slow or unreachable. Try again.",
                "request_id": request_id,
            }, indent=2)
        except VectraAPIError as e:
            logger.error("get_investigation_results: API error request_id=%s status_code=%s error=%s", request_id, e.status_code, str(e))
            return json.dumps({
                "error": str(e),
                "request_id": request_id,
                "status_code": e.status_code,
                "api_response": e.response_data,
            }, indent=2)
        except Exception as e:
            logger.error("get_investigation_results: unexpected error request_id=%s: %s", request_id, str(e), exc_info=True)
            return json.dumps({
                "error": f"Failed to fetch investigation results: {str(e)}",
                "request_id": request_id,
            }, indent=2)