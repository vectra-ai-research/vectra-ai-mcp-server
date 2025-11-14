"""MCP tools for security investigations."""

from typing import Literal, List, Annotated
from pydantic import Field
import json

from utils.validators import validate_date_range

class InvestigationMCPTools:
    """MCP tools for investigations."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all investigation tools with the MCP server."""
        self.vectra_mcp.tool()(self.create_assignment)
        self.vectra_mcp.tool()(self.list_assignments)
        self.vectra_mcp.tool()(self.list_assignments_for_user)
        self.vectra_mcp.tool()(self.delete_assignment)
        self.vectra_mcp.tool()(self.get_assignment_detail_by_id)
        self.vectra_mcp.tool()(self.get_assignment_for_entity)
        self.vectra_mcp.tool()(self.create_entity_note)
        self.vectra_mcp.tool()(self.mark_detection_fixed)

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
                assignee = user_id,
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
            assignment = await self.client.delete_assignment(assignment_data)
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