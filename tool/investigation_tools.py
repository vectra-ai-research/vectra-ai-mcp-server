"""MCP tools for security investigations."""

from typing import Optional, Literal, List
from pydantic import Field
import json

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
        self.vectra_mcp.tool()(self.get_assignment_detail_by_id)
        self.vectra_mcp.tool()(self.get_assignment_for_entity)
        self.vectra_mcp.tool()(self.create_entity_note)
        self.vectra_mcp.tool()(self.mark_detection_fixed)

    async def list_assignments(
            self,
            assignees: Optional[int] = Field(default=None, description="Vectra platform User ID to filter assignments by. Optional."),
            resolved: Optional[bool] = Field(default=None, description="Filter assignments by resolved state. True for resolved, False for unresolved. Default is None (no filter)."),
        ) -> str:
        """
        List all investigation assignments with optional filtering by assignee and resolved state.

        Args:
            assignees (int):Vectra platform User ID to filter assignments by. Optional.
            resolved (bool): Filter assignments by resolved state. True for resolved, False for unresolved. Default is None (no filter).
        
        Returns:
            str: JSON string with list of assignments.
        """
        try:
            assignments = await self.client.get_assignments()
            if assignments is None:
                return "No assignments found."
            return json.dumps(assignments, indent=2)
        except Exception as e:
            raise Exception(f"Failed to list assignments: {str(e)}")
        
    async def get_assignment_detail_by_id(
        self,
        assignment_id: int = Field(ge=1, description="ID of the assignment to retrieve")    
    ) -> str:
        """
        Retrieve details of a specific investigation assignment.

        Args:
            assignment_id (int): The ID of the assignment to retrieve.
        
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
        entity_ids: List[int] = Field(description="List of entity IDs to retrieve assignment for"),
        entity_type: Literal["host", "account"] = Field(description="Type of entity to retrieve assignment for (host or account)")
    ) -> str:
        """
        Retrieve investigation assignment for a specific account.

        Args:
            entity_ids (List[int]): List of entity IDs to retrieve assignment for.
            entity_type (Literal["host", "account"]): Type of entity to retrieve assignment for (host or account).
        
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
        assign_account_id: Optional[int] = Field(default=None, description="ID of the account to assign. Optional if assigning a host"),
        assign_host_id: Optional[int] = Field(default=None, description="ID of the host to assign. Optional if assigning an account"),
        assign_to_user_id: int = Field(ge=1, description="ID of the user to assign the entity to"),
        notes: Optional[str] = Field(default=None, description="Optional initial investigation notes for the assignment")
    ) -> str:
        """
        Create investigation assignment for an account or host
        
        Args:
            assign_account_id (int): ID of the account to assign. Optional if assigning a host.
            assign_host_id (int): ID of the host to assign. Optional if assigning an account.
            assign_to_user_id (int): ID of the user to assign the entity to.
            notes (str) : Initial investigation notes for the assignment
        Returns:
            str: Formatted string with assignment details.
        Raises:
            Exception: If assignment creation fails.
        """

        # all_users = self.client.get_users()
        # assign_to = next((user['name'] for user in all_users if user['id'] == assign_to_user_id), None)
        # if not assign_to:
        #     raise ValueError(f"User with ID {assign_to_user_id} not found.")

        if not assign_account_id and not assign_host_id:
            raise ValueError("Either assign_account_id or assign_host_id must be provided.")

        # Prepare assignment data
        assignment_data = {
            "assign_to_user_id": assign_to_user_id,
        }

        payload = json.dumps({
            "assign_account_id": "534",
            "assign_to_user_id": "95"
            })

        if assign_account_id:
            assignment_data["assign_account_id"] = assign_account_id

        if assign_host_id:
            assignment_data["assign_host_id"] = assign_host_id

        try:
            # Create the assignment
            assignment = await self.client.create_assignment(assignment_data)
            assignment_id = assignment.get("assignment").get("id")
            
            # Add initial note if provided
            if notes and assignment_id:
                try:
                    note_data = {
                        "note": f"Assignment created: {notes}"
                    }
                    await self.client.add_note(note_data)
                    assignment["note"] = note_data["note"]

                except Exception as e:
                    assignment["note"] = f"Assignment created but note failed: {str(e)}"
            
            # return "\n".join(result_parts)
            return json.dumps(assignment)
            
        except Exception as e:
            raise Exception(f"Failed to create assignment: {str(e)}")
        
    async def create_entity_note(
            self,
            entity_id: int = Field(ge=1, description="ID of the entity to add note to"),
            entity_type: Literal["host", "account"] = Field(..., description="Type of entity to add note to (host or account)"),
            note: str = Field(default=None, description="Note text to add to the entity")
    ) -> str:
        """
        Add an investigation note to an entity (host or account).
        
        Args:
            entity_id (int): ID of the entity to add note to.
            entity_type (Literal["host", "account"]): Type of entity to add note to.
            note (str): Note text to add to the entity.
        
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
            # return f"Note added to entity {entity_id}: {note}"
            return json.dumps(create_note, indent=2)
        except Exception as e:
            raise Exception(f"Failed to add note to entity {entity_id}: {str(e)}")
        
    async def mark_detection_fixed(
        self,
        detection_ids: List[int] = Field(default=None, description="List of detection IDs to mark as fixed or not fixed"),
        mark_fixed: bool = Field(default=True, description="True to mark as fixed, False to unmark as fixed")
    ) -> str:
        """
        Marks or unmark detection as fixed.
        For marking as fixed, the detection will be closed as remediated indication it has been addressed.
        
        Args:
            detection_ids (list): List of detection IDs to mark.
            mark_fixed (bool): True to mark as fixed, False to unmark as fixed.
        
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