"""MCP tools for response actions."""

from typing import Optional, Literal
from pydantic import Field
import json

class ResponseMCPTools:
    """MCP tools for response actions."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all response tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_lockdown_entities)

    async def list_lockdown_entities(
        self,
    ) -> str:
        """
        List entities that are currently in lockdown.
        
        Args:
            None
        
        Returns:
            str: JSON string with list of entities in lockdown.
        """
        try:
            lockdown_entities = await self.client.get_lockdown_entities()

            if not lockdown_entities:
                return "No entities currently in lockdown."
            # Format the response as a JSON string
            return json.dumps(lockdown_entities, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch entities in lockdown: {str(e)}")