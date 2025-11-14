"""MCP tools for platform management."""

from typing import Literal, Annotated
from pydantic import Field
import json

from utils.validators import validate_date_range

class ManagementMCPTools:
    """MCP tools for Vectra AI platform management."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all platform management tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_platform_users)

    async def list_platform_users(
        self,
        role: Annotated[
            Literal["admins", "auditor", "global_analyst", "read_only", "restricted_admins", "security_analyst", "setting_admins", "super_admins"] | None, 
            Field(description="Filter by user role (choices: admins, auditor, global_analyst, read_only, restricted_admins, security_analyst, setting_admins, super_admins). Defaults to None, which returns all users.")
        ] = None,
        last_login_after : Annotated[
            str | None, 
            Field(description="Filter by last login date in ISO format (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        email: Annotated[
            str | None, 
            Field(description="Valid email address of the Vectra platform user to filter by.",pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        ] = None,
        limit: Annotated[
            int, 
            Field(description="Maximum number of users to return. Defaults to 1000", ge=1, le=1000)
        ] = 1000
    ) -> str:
        """
        List users in the Vectra platform.
        
        Returns:
            str: JSON string with list of users.
        """

        try:
            all_users = await self.client.get_users()

            search_params = {}
            if limit:
                search_params['page_size'] = limit

            # Add last login filter if provided
            # Validate and convert date string to datetime object
            last_login_after, end_date = validate_date_range(last_login_after, None)
            if last_login_after:
                search_params['last_login_gte'] = last_login_after

            if role:
                # Validate role
                if role not in ["admins", "auditor", "global_analyst", "read_only", "restricted_admins", "security_analyst", "setting_admins", "super_admins"]:
                    raise ValueError(f"Invalid role: {role}")
                search_params['role'] = role

            if email:
                search_params['email'] = email

            if search_params:
                all_users = await self.client.get_users(**search_params)
            else:
                all_users = await self.client.get_users()

            # Extract user list from response
            user_list = all_users.get('results', [])
            if not user_list:
                return "No users found."
            
            # Get user count
            user_count = len(user_list)

            # Return formatted JSON response
            return json.dumps({"uer_couclnt": user_count, "user_list": user_list}, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to list users : {str(e)}")

    