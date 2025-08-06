"""MCP tools for platform management."""

from typing import Optional, Literal
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
        role: Optional[Literal["admins", "auditor", "global_analyst", "read_only", "restricted_admins", "security_analyst", "setting_admins", "super_admins"]] = Field(default=None, description="Filter by user role (choices: admins, auditor, global_analyst, read_only, restricted_admins, security_analyst, setting_admins, super_admins)"),
        last_login_after : Optional[str] = Field(default=None, description="Filter by last login date in ISO format (YYYY-MM-DD)"),
        email: Optional[str] = Field(default=None, description="Filter by user email address"),
        limit: Optional[int] = Field(default=None, description="Maximum number of users to return", ge=1, le=1000)
    ) -> str:
        """
        List users in the Vectra platform.
        Args:
            role (Optional[str]): Filter by user role. Choices are:
                - admins
                - auditor
                - global_analyst
                - read_only
                - restricted_admins
                - security_analyst
                - setting_admins
                - super_admins
            last_login (Optional[str]): Filter by last login date in ISO format (YYYY-MM-DD).
            email (Optional[str]): Filter by user email address.
            limit (Optional[int]): Maximum number of users to return. Default is None (no limit).
        Returns:
            str: JSON string with list of users.
        """

        try:
            all_users = await self.client.get_users()

            search_params = {}
            if limit:
                search_params['page_size'] = limit

            if last_login_after:
                validate_date_range(last_login_after, last_login_after)
                search_params['last_login_gte'] = last_login_after

            if role:
                # Validate role
                if role not in ["admins", "auditor", "global_analyst", "read_only", "restricted_admins", "security_analyst", "setting_admins", "super_admins"]:
                    raise ValueError(f"Invalid role: {role}")
                search_params['role'] = role

            if email:
                # Validate email format
                if not isinstance(email, str) or '@' not in email:
                    raise ValueError(f"Invalid email format: {email}")
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

    