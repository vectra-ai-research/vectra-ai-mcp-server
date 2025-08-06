"""Entity tools for security investigations."""

from typing import Optional, Literal
from pydantic import Field, IPvAnyAddress
import json

class EntityMCPTools:
    """MCP tools for entity (host or account) analysis and management."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all entity tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_entities)
        self.vectra_mcp.tool()(self.lookup_entity_info_by_name)
        self.vectra_mcp.tool()(self.lookup_host_by_ip)
        self.vectra_mcp.tool()(self.get_host_details)
        self.vectra_mcp.tool()(self.get_account_details)

    async def list_entities(
        self,
        entity_type: Optional[Literal["account", "host"]] = Field(default=None, description="Filter by type of entities to retrieve. Options are 'account' or 'host'"),
        state: Optional[Literal["active", "inactive"]] = Field(default="active", description="Filter by entity state (active, inactive)"),
        name: Optional[str] = Field(default=None, description="Filter by entity name. Can also perform partial word match."),
        host_ip: Optional[str] = Field(default=None, description="Filter by entity IP address. Only applicable for host entities."),
        is_prioritized: Optional[bool] = Field(default=None, description="Filter for prioritized entities (True/False)"),
        tags: Optional[str] = Field(default=None, description="Filter for entities with a particular tag"),
        limit: Optional[int] = Field(default=None, description="Maximum number of detections to return in the batch. Default value is 100", ge = 1, le=1000),
        ordering: Optional[Literal["urgency_score", "-urgency_score", "last_detection_timestamp", "-last_detection_timestamp", "last_modified_timestamp", "-last_modified_timestamp", "name", "-name"]] = Field(default="urgency_score", description="Order by urgency score, last_detection_timestamp, last_modified_timestamp or name. Use '-' prefix for descending order.")
    )-> str:
        """
        List entities in platform based on various filters.
        
        Args:
            entity_type (str): Type of entities to retrieve. Options are 'account' or 'host'.
            state (str): Filter by entity state (active, inactive). Defaults to 'active'.
            name (str): Filter by entity name. Can also perform partial word match.
            host_ip (str): Filter by entity IP address. Only applicable for host entities.
            is_prioritized (bool): Filter for prioritized entities (True/False).
            tags (str): Filter for entities with a particular tag.
            limit (int): Maximum number of entities to return in the batch.
            ordering (str): Order by urgency score, last_detection_timestamp, last_modified_timestamp or name. Use '-' prefix for descending order.

        Returns:
            str: Formatted string with list of detections.
        """
        try:
            params = locals().copy()

            # Remove non-query parameters
            exclude_params = {'self', 'limit', 'entity_type', 'host_ip'}

            search_params = {k: v for k, v in params.items()
                    if v is not None and k not in exclude_params}
            
            if entity_type:
                search_params['type'] = entity_type
            
            entities_response = await self.client.get_entities(**search_params)
            entities = entities_response.get("results", [])
            total_count = entities_response.get("count")

            if not entities:
                return "No entities found matching the specified criteria."
            
            if host_ip:
                # Filter entities by host IP if provided
                entities = [e for e in entities if e.get("ip") == host_ip]
                if not entities:
                    return f"No entities found with the specified IP address: {host_ip}."

            if limit and len(entities) > limit:
                entities = entities[:limit]
            # Format the response as a JSON string
            return json.dumps({"total_count": total_count, "entities": entities}, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch entities: {str(e)}")
        
    async def get_account_details(
        self,
        account_id: int = Field(default=None, description="ID of the account in Vectra platform to retrieve details for", ge=1)
    ) -> str:
        """
        Get complete detailed information about a specific account entity.
        
        Args:
            account_id (int): ID of the account in Vectra platform to retrieve.
        
        Returns:
            str: Formatted string with detailed information about the account entity. 
            If the account is not found, returns a message indicating that no account was found with the specified ID.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            # Fetch account details using the client
            account_details = await self.client.get_entity(
                entity_id = account_id, 
                entity_type = "account"  # Specify the type as account
            )
            # Check if the host was found
            if 'detail' in account_details and account_details['detail'] == 'Not found.':
                return f"No account found with ID: {account_id}."
            
            return json.dumps(account_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch account details: {str(e)}")
        
    async def lookup_entity_info_by_name(
            self,
            entity_name: str = Field(default=None, description="Name or partial name of the entity to look up. No spaces allowed.")
    ):
        """
        Retrieve information about an entity (account or host) by its name. Search is case-insensitive and can match partial names.
        
        Args:
            entity_name (str): Name or partial name of the entity to look up. No spaces allowed.

        Returns:
            str: Formatted string with entity information including name, ID, type, last detection timestamp, prioritization status, urgency score, state, and IP address (when available).
            If no entities are found, returns a message indicating that no matches were found.
        """
        try:

            entity_lookup = await self.client.get_entities(
                name = entity_name
            )

            if entity_lookup.get("count") == 0:
                return f"No entities found matching with name '{entity_name}'."
            
            entity_match_count =  entity_lookup.get("count")
            
            entity_match_list = entity_lookup.get("results", [])  # Get list of entities matching name
            
            entity_lookup_result = [
                {
                    'name': entity['name'],
                    'id': entity['id'], 
                    'type': entity['type'],
                    'last_detection_timestamp': entity['last_detection_timestamp'],
                    'is_prioritized': entity['is_prioritized'],
                    'urgency_score': entity.get('urgency_score', 0),  # Default to 0 if not available
                    'state': entity.get('state', 'unknown'),
                    'ip': entity.get('ip', 'N/A'),  # Include IP if available
                }
                for entity in entity_match_list
            ]

            return json.dumps({"match_count": entity_match_count, "matched_entities": entity_lookup_result}, indent=2)

        except Exception as e:
            raise Exception(f"Failed to fetch entity info: {str(e)}")
        
    async def get_host_details(
        self,
        host_id: int = Field(default=None, description="ID of the host entity to retrieve details for", ge=1)
    ):
        """
        Get complete detailed information about a specific host entity.
        
        Args:
            host_id (int): ID of the host entity in Vectra platform to retrieve details for.
        
        Returns:
            str: Formatted string with detailed information about the host entity. 
            If the host is not found, returns a message indicating that no host was found with the specified ID.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            host_details = await self.client.get_host(host_id)

            # Check if the host was found
            if 'detail' in host_details and host_details['detail'] == 'Not found.':
                return f"No host found with ID: {host_id}."
            
            return json.dumps(host_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch host details: {str(e)}")
        
    async def lookup_host_by_ip(
            self,
            host_ip: IPvAnyAddress = Field(default=None, description="IP address of the host to look up. Must be a valid IPv4 or IPv6 address.")
    ):
        """
        Retrieve information about a host entity by its IP address.
        
        Args:
            host_ip (IPvAnyAddress): IP address of the host to look up. Must be a valid IPv4 or IPv6 address.

        Returns:
            str: Formatted string with host information including name, ID, type, last detection timestamp, prioritization status, urgency score, state, and IP address.
            If no hosts are found with the specified IP address, returns a message indicating that no matches were found.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            all_states = ["active", "inactive"]  # Define the states to search in

            for state in all_states:
                # Perform the lookup in active then inactive states
                host_lookup = await self.client.get_entities(
                    type = "host",
                    state = state,
                    auto_paginate = True # Enable auto-pagination to fetch all results
                )

                all_hosts = host_lookup.get("results", [])

                for host in all_hosts:
                    if host.get('ip') == str(host_ip):
                        return json.dumps({"matched_host" : host}, indent=2)
            
            # If no match found in any state, return not found message
            return f"No hosts found associated with IP address: {host_ip}."

        except Exception as e:
            raise Exception(f"Failed to fetch host info: {str(e)}")