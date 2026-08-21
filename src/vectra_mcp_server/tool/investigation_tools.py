"""MCP tools for security investigations."""

import asyncio
from typing import Literal, List, Annotated
from pydantic import Field
import json

from ..utils.logging import get_logger
from ..utils.validators import validate_date_range
from .base import (
    ADDITIVE_EACH_CALL,
    DESTRUCTIVE,
    READ_ONLY,
    BaseMCPTools,
)

logger = get_logger(__name__)

# Hard timeout for investigation API calls (seconds).
# Prevents a slow/hanging Vectra API from blocking the entire MCP server.
_INVESTIGATION_TIMEOUT = 20


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
        # Suppresses detections from the active queue and from entity scoring.
        self._register_tool(self.mark_detection_fixed, DESTRUCTIVE)
        # Closes a detection, removing it from the queue and from entity scoring.
        self._register_tool(self.close_detection, DESTRUCTIVE)
        # Submits a new async query job; returns a fresh request_id each call.
        self._register_tool(self.run_investigation, ADDITIVE_EACH_CALL)
        self._register_tool(self.get_investigation_results, READ_ONLY)

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
        Marks or unmark detection as fixed.
        For marking as fixed, the detection will be closed as remediated, indicating it has been addressed.
        
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
        
    async def close_detection(
        self,
        detection_id: Annotated[
            int,
            Field(description="ID of the detection to close.", ge=1)
        ],
        reason: Annotated[
            Literal["remediated", "benign"],
            Field(description=(
                "Reason for closing the detection. "
                "'remediated' — a corrective action was taken to address the threat. "
                "'benign' — the activity was reviewed and determined not to be a threat."
            ))
        ],
    ) -> str:
        """
        Close a single detection, removing it from the active queue and stopping it
        from contributing to entity scoring.

        Use 'remediated' when the threat was real and an action was taken to address it.
        Use 'benign' when the detection was reviewed and confirmed not to be a threat
        (equivalent to a Benign True Positive verdict).

        Returns:
            str: JSON confirmation from the API, or an error message.
        """
        try:
            result = await self.client.close_detection(detection_id=detection_id, reason=reason)
            return json.dumps(result, indent=2)
        except Exception as e:
            raise Exception(f"Failed to close detection {detection_id}: {str(e)}")

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
                "2) NEVER use double quotes anywhere in the query. Use single quotes for "
                "string literals AND for column aliases (e.g. AS 'failure_count' not AS \"failure_count\"). "
                "3) NEVER use escaped quotes (no \\\" or \\\\'). "
                "Example: SELECT id.orig_h, count(*) AS 'failure_count' FROM network.kerberos._all WHERE timestamp BETWEEN date_add('day', -7, now()) AND now() GROUP BY id.orig_h ORDER BY 'failure_count' DESC LIMIT 100 "
                "IMPORTANT: Before calling this tool, you MUST first call "
                "get_investigation_sql_reference to learn the supported SQL syntax, "
                "and get_investigation_schema with the relevant data_source to learn "
                "the exact column names available for your query."
            ))
        ],
    ) -> str:
        """
        Submit an investigation SQL query and return the request_id. This tool returns immediately — the query runs asynchronously. Use get_investigation_results with the returned request_id to fetch results. Before using this tool, ALWAYS call get_investigation_sql_reference and get_investigation_schema first. The query MUST be a single line (no newlines), MUST use single quotes only (no double quotes), and MUST NOT contain escaped quotes.

        Returns:
            str: JSON with request_id and searchable_range. Use request_id with get_investigation_results.
        """
        # Sanitize: collapse newlines to spaces, strip double quotes from
        # column aliases (replace with single quotes or remove), and remove
        # any backslash-escaped quotes the LLM may have introduced.
        query = " ".join(query.split())
        query = query.replace('\\"', '"').replace("\\'", "'")
        query = query.replace('"', "'")

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