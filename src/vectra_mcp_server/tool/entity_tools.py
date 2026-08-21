"""Entity tools for security investigations."""

from typing import Literal, Annotated
from pydantic import Field, IPvAnyAddress
import json

from .base import READ_ONLY, BaseMCPTools


class EntityMCPTools(BaseMCPTools):
    """MCP tools for entity (host or account) analysis and management."""

    def register_tools(self):
        """Register all entity tools with the MCP server."""
        self._register_tool(self.list_entities, READ_ONLY)
        self._register_tool(self.lookup_entity_info_by_name, READ_ONLY)
        self._register_tool(self.lookup_host_by_ip, READ_ONLY)
        self._register_tool(self.get_host_details, READ_ONLY)
        self._register_tool(self.get_account_details, READ_ONLY)
    
    async def list_entities(
        self,
        entity_type: Annotated[
            Literal["account", "host"] | None,
            Field(description="Restrict results to one entity type. Leave unset (None, the default) to return hosts and accounts together — the underlying `type` filter is optional, and omitting it gives the unified queue view. Sent to the API as `type`.")
        ] = None,
        state: Annotated[
            Literal["active", "inactive"], 
            Field(description="Filter by entity state (active, inactive)")
        ] = "active",
        ordering: Annotated[
            Literal["urgency_score", "-urgency_score", "last_detection_timestamp", "-last_detection_timestamp", "last_modified_timestamp", "-last_modified_timestamp", "name", "-name"], 
            Field(description="Order by 'urgency_score', '-urgency_score', 'last_detection_timestamp', '-last_detection_timestamp', 'last_modified_timestamp', '-last_modified_timestamp', 'name', '-name'. The '-' prefix indicates descending order.")
        ] = "urgency_score",
        name: Annotated[
            str | None, 
            Field(description="Filter by entity name. Can also perform partial word match.")
        ] = None,
        host_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by entity IP address. Only applicable for host entities.")
        ] = None,
        is_prioritized: Annotated[
            bool | None,
            Field(description="Filter for prioritized entities (True) or non-prioritized entities (False). 'Prioritized' is a manual/platform flag and is independent of urgency_score — it is not a proxy for urgency. Setting it narrows the result set silently. Leave unset (None, the default) to return entities regardless of prioritization status.")
        ] = None,
        tags: Annotated[
            str | None, 
            Field(description="Filter for entities with a particular tag")
        ] = None,
        limit: Annotated[
            int, 
            Field(description="Maximum number of detections to return in the batch. None means no limit", ge = 1, le=1000)
        ] = 1000
    )-> str:
        """
        List entities (hosts & accounts) in Vectra platform based on various filters. This tool returns entities with all their detailed information.

        By default both hosts and accounts are returned in one call; set
        entity_type only to restrict to one of them.

        Ordering by urgency_score (ascending) or -urgency_score (descending) is
        independent of the is_prioritized filter; the two are unrelated fields.

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
        account_id: Annotated[int, Field(description="ID of the account in Vectra platform to retrieve details for", ge=1)],
        fields: Annotated[
            list[str] | None, 
            Field(description="Fields to return in the results. Available fields: id, url, account_type, assignment, associated_accounts, certainty, data_source, detection_set, detection_summaries, last_detection_timestamp, name, note, note_modified_by, note_modified_timestamp, notes, past_assignments, privilege_category, privilege_level, probable_home, sensors, severity, state, tags, threat")
        ] = None,
        exclude_fields: Annotated[
            list[str] | None, 
            Field(description="Fields to exclude in the response object. Accepts comma-separated list. Available fields: 'id', 'url', 'name', 'state', 'threat', 'certainty', 'severity', 'account_type', 'tags', 'note', 'notes', 'note_modified_by', 'note_modified_timestamp', 'privilege_level', 'privilege_category', 'last_detection_timestamp', 'detection_set', 'probable_home'.")
        ] = None,
        include_access_history: Annotated[
            bool, 
            Field(description="Include account access history in the response")
        ] = False,
        include_detection_summaries: Annotated[
            bool, 
            Field(description="Include detection summaries for the detections on the account in the response object.")
        ] = True,
        include_external: Annotated[
            bool, 
            Field(description="Include external data in the response object.")
        ] = False,
        src_linked_account: Annotated[
            str | None, 
            Field(description="Source linked account filter")
        ] = None
    ) -> str:
        """
        Get complete detailed information about a specific account entity. This tool returns account details including detections, scoring information, associated accounts, access history, detection summaries, external data, and more. Response can be customized using various parameters to include or exclude specific fields and related data.
        
        Returns:
            str: JSON string with detailed information about the account. It includes detections, scoring information, associated accounts, access history, detection summaries, external data, and more.
            If the account is not found, returns a message indicating that no account was found with the specified ID.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            # Fetch account details using the v3.4 accounts API endpoint
            account_details = await self.client.get_account(
                account_id=account_id,
                fields=fields,
                exclude_fields=exclude_fields,
                include_access_history=include_access_history,
                include_detection_summaries=include_detection_summaries,
                include_external=include_external,
                src_linked_account=src_linked_account
            )
            
            # Check if the account was found
            if 'detail' in account_details and account_details['detail'] == 'Not found.':
                return f"No account found with ID: {account_id}."
            
            return json.dumps(account_details, indent=2)
        except Exception as e:
            raise Exception(f"Failed to fetch account details: {str(e)}")
        
    async def lookup_entity_info_by_name(
            self,
            entity_name: Annotated[str, Field(description="Name or partial name of the entity to look up. No spaces allowed.")]
    ):
        """
        Retrieve information about an entity (account or host) by its name. Search is case-insensitive and can match partial names.

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
        host_id: Annotated[int, Field(description="ID of the host entity to retrieve details for", ge=1)]
    ):
        """
        Get complete detailed information about a specific host entity.
        
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
            host_ip: Annotated[IPvAnyAddress, Field(description="IP address of the host to look up. Must be a valid IPv4 or IPv6 address.")]
    ):
        """
        Retrieve information about a host entity by its IP address.

        Uses the /hosts endpoint with a last_source filter to identify the host
        directly by IP address — no full-scan pagination required.

        Returns:
            str: Formatted string with host information including name, ID, type, last detection timestamp, prioritization status, urgency score, state, and IP address.
            If no hosts are found with the specified IP address, returns a message indicating that no matches were found.
            If an error occurs during the request, raises an exception with the error message.
        """
        try:
            host_lookup = await self.client.get_hosts(last_source=str(host_ip))
            matched_hosts = host_lookup.get("results", [])

            if not matched_hosts:
                return f"No hosts found associated with IP address: {host_ip}."

            return json.dumps({"match_count": len(matched_hosts), "matched_hosts": matched_hosts}, indent=2)

        except Exception as e:
            raise Exception(f"Failed to fetch host info: {str(e)}")
