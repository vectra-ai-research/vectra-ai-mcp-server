"""Detection analysis tools for security investigations."""

from typing import Literal, Annotated
from pydantic import Field, IPvAnyAddress
import json
import base64

from utils.validators import validate_date_range

class DetectionMCPTools:
    """MCP tools for detection analysis and management."""
    
    def __init__(self, vectra_mcp, client):
        """Initialize with FastMCP instance and Vectra client.
        
        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
    
    def register_tools(self):
        """Register all detection tools with the MCP server."""
        self.vectra_mcp.tool()(self.list_detection_ids)
        self.vectra_mcp.tool()(self.list_detections_with_basic_info)
        self.vectra_mcp.tool()(self.list_detections_with_details)
        self.vectra_mcp.tool()(self.list_entity_detections)
        self.vectra_mcp.tool()(self.get_detection_count)
        self.vectra_mcp.tool()(self.get_detection_details)
        self.vectra_mcp.tool()(self.get_detection_summary)
        self.vectra_mcp.tool()(self.get_detection_pcap)
    
    async def get_detection_details(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve details for")
        ]
    ) -> str:
        """
        Get complete detailed information for a particular detection.
        
        Returns:
            str: JSON string with detection details.

        Raises:
            Exception: If fetching detection details fails.
        """
        try:
            # Get detection details
            detection = await self.client.get_detection(detection_id)
            
            return json.dumps(detection)
        except Exception as e:
            raise Exception(f"Failed to retrieve details for detection {detection_id}: {str(e)}")

    async def list_detections_with_details(
        self,
        ordering: Annotated[
            Literal['created_datetime', 'last_timestamp', 'id'], 
            Field(description="Order by last_timestamp, created_datetime, or id. Defaults to ordering by last_timestamp")
        ] = "last_timestamp",
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection. Must be a valid IPv4 or IPv6 address.")
        ] = None,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False,
        limit: Annotated[
            int, 
            Field(description="Maximum number of detections to return in the batch. Defaults to 1000", ge = 1, le=1000)
        ] = 1000
    )-> str:
        """
        List detections with filtering and sorting options. Use this to get a detailed list of detections based on various criteria.

        Returns:
            str: JSON string with list of detections.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_name'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_name:
            search_params['detection_type'] = detection_name
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."

        response = {"detection_count": total_count, "detections": detections}
        
        if limit:
            if total_count > limit:
            # Limit the number of detections returned to reduce response size
                detections = detections[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections"] = detections
            
        return json.dumps(response, indent=2)

    async def get_detection_count(
        self,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category")
        ] = None,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active' which returns only currently active detections.")
        ] = "active",
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection.")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False
    ) -> str:
        """
        Get the total count of detections matching the specified criteria.

        Returns:
            str: Count of detections matching the criteria.
        """
        params = locals().copy()
        exclude_params = {'self', 'start_date', 'end_date'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        # Add date filters if provided
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        detections_response = await self.client.get_detections(**search_params)
        total_count = detections_response.get("count")
        
        return f"Total detections matching criteria: {total_count}"
    
    async def get_detection_pcap(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve pcap for")
        ]
    ) -> str:
        """
        Get pcap file for a specific detection.
        
        Returns:
            str: Base64 encoded pcap data or error message.

        Raises:
            Exception: If retrieval fails.
        """
        try:
            pcap_data = await self.client.get_detection_pcap(detection_id)

            if not pcap_data:
                return f"No pcap data found for detection ID {detection_id}."
            
            # Encode binary content as base64
            encoded_content = base64.b64encode(pcap_data).decode('utf-8')

            return f"PCAP data for detection ID {detection_id}:\n{encoded_content}"

        except Exception as e:
            raise Exception(f"Failed to retrieve pcap for detection {detection_id}: {str(e)}")
        
    async def list_entity_detections(
        self,
        entity_id: Annotated[
            int, 
            Field(ge=1, description="ID of the entity to list detections for")
        ],
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'. If no value specified (None), returns detection with all states.")
        ] = "active"
    ) -> str:
        """
        List all detections with full details for a specific entity. 
        
        Returns:
            str: JSON string with list of detections for the entity.
        """
        if not entity_id:
            return "Entity ID is required."
        
        try:
            search_params = {
                "entity_id": entity_id
            }
            if state:
                search_params["state"] = state

            detections_response = await self.client.get_detections(**search_params)
            detections = detections_response.get("results", [])
            total_count = detections_response.get("count")
            
            if not detections:
                return f"No detections found for entity ID {entity_id}."
            
            return json.dumps({"detection_count": total_count, "detections": detections}, indent=2)
        
        except Exception as e:
            raise Exception(f"Failed to list detections for entity {entity_id}: {str(e)}")
        
    async def list_detections_with_basic_info(
        self,
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        ordering: Annotated[
            Literal['created_datetime', 'last_timestamp', 'id'] | None, 
            Field(description="Order by last_timestamp, created_datetime, or id. Defaults to 'last_timestamp'")
        ] = "last_timestamp",
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection")
        ] = None,
        start_date: Annotated[str | None, Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")] = None,
        end_date: Annotated[str | None, Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")] = None,
        is_targeting_key_asset: Annotated[bool, Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")] = False,
        limit: Annotated[int, Field(description="Maximum number of detections to return in the batch.", ge = 1, le=1000)] = None
    )-> str:
        """
        List detections with basic information and filtering options. Use this to get a quick overview of detections without detailed information.
        
        Returns:
            str: JSON string with list of detections ids.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_name'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_name:
            search_params['detection_type'] = detection_name
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."
        
        detection_list = [
                {
                    'id': dets['id'], 
                    'name': dets['detection'],
                    'detection_category': dets['detection_category'],
                    'last_timestamp': dets['last_timestamp'],
                    'is_triaged': dets.get('is_triaged'),
                    'state': dets.get('state', 'unknown'),
                    'entity_type': dets.get('type', 'unknown')
                }
                for dets in detections
            ]

        response = {"detection_count": total_count, "detections": detection_list}
        
        if limit:
            if total_count > limit:
            # Limit the number of detections returned to reduce response size
                detections = detections[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections"] = detection_list
            
        return json.dumps(response, indent=2)
    
    async def get_detection_summary(
        self,
        detection_id: Annotated[
            int, 
            Field(ge=1, description="ID of the detection to retrieve summary for")
        ]
    ) -> str:
        """
        Get a concise summary of a detection including its ID, name, category, last timestamp, triage status, state, entity type, and detection summary. The detection summary includes key details about the detection including event specific details and description.
        
        Returns:
            str: Formatted string with detection summary.
        """
        try:
            detection = await self.client.get_detection(detection_id)
            if not detection:
                return f"Detection with ID {detection_id} not found."
            
            detection_summary = {
                "id": detection.get("id"),
                "name": detection.get("detection"),
                "category": detection.get("detection_category", detection.get("category")),
                "last_timestamp": detection.get("last_timestamp"),
                "is_triaged": detection.get("is_triaged"),
                "state": detection.get("state", "unknown"),
                "entity_type": detection.get("type", "unknown"),
                "detection_summary": detection.get("summary", "No summary available"),
            }
            
            return json.dumps(detection_summary, indent=2)
        
        except Exception as e:
            raise Exception(f"Failed to retrieve detection summary: {str(e)}")
        
    async def list_detection_ids(
        self,
        ordering: Annotated[
            Literal['created_datetime', 'last_timestamp', 'id'] | None, 
            Field(description="Order by last_timestamp, created_datetime, or id")
        ] = "last_timestamp",
        state: Annotated[
            Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"] | None, 
            Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
        ] = "active",
        detection_category: Annotated[
            Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"] | None, 
            Field(description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match")
        ] = None,
        detection_name: Annotated[
            str | None, 
            Field(description="Filter by detection name. Can also perform partial word match")
        ] = None,
        src_ip: Annotated[
            IPvAnyAddress | None, 
            Field(description="Filter by source IP address of the host that generated the detection")
        ] = None,
        start_date: Annotated[
            str | None, 
            Field(description="Filter by start date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        end_date: Annotated[
            str | None, 
            Field(description="Filter by end date (YYYY-MM-DDTHH:MM:SS)")
        ] = None,
        is_targeting_key_asset: Annotated[
            bool, 
            Field(description="Filter for detections targeting a key asset. Defaults to 'False'. Set to 'True' to filter for detections that are targeting key assets. To get all detections regardless of key asset targeting, search for both True and False values.")
        ] = False,
        limit: Annotated[
            int, 
            Field(description="Maximum number of detections to return in the batch. Defaults to 1000.", ge = 1, le=1000)
        ] = 1000
    )-> str:
        """
        List detection IDs with filtering and sorting options. Use this to get a list of detection IDs based on various criteria.

        Returns:
            str: JSON string with list of detection IDs.
        """
        params = locals().copy()

        # Remove non-query parameters
        exclude_params = {'self', 'limit', 'start_date', 'end_date', 'detection_name'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        if detection_name:
            search_params['detection_type'] = detection_name
        
        # Add date filters if provided
        # Validate and convert date strings to datetime objects
        start_date, end_date = validate_date_range(start_date, end_date)
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        search_params["auto_paginate"] = True  # Enable auto-pagination
        
        detections_response = await self.client.get_detections(**search_params)
        detections = detections_response.get("results", [])
        total_count = detections_response.get("count")

        if not detections:
            return "No detections found matching the specified criteria."
        
        # Extract only detection IDs
        detection_ids = [
            {
                'id': dets['id']
            }
            for dets in detections
        ]

        response = {"detection_count": total_count, "detections_ids": detection_ids}
        
        if limit:
            if total_count > limit:
            # Limit the number of detection IDs returned to reduce response size
                detection_ids = detection_ids[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections_ids"] = detection_ids
            
        return json.dumps(response, indent=2)