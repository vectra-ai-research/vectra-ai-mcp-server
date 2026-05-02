"""MCP tools for response actions."""

import json

from .base import BaseMCPTools


class ResponseMCPTools(BaseMCPTools):
    """MCP tools for response actions."""

    def register_tools(self):
        """Register all response tools with the MCP server."""
        self._register_tool(self.list_lockdown_entities)

    async def list_lockdown_entities(
        self,
    ) -> str:
        """
        List entities that are currently in lockdown.
        
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