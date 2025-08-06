"""Detection analysis tools for security investigations."""

from typing import Optional, Literal, List, Dict, Any
from pydantic import Field
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
        detection_id: int = Field(ge=1, description="ID of the detection to retrieve details for")
    ) -> str:
        """
        Get complete detailed information for a particular detection.
        
        Args:
            detection_id (int): The ID of the detection to retrieve.
        
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
        detection_category: Optional[Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"]] = Field(default=None, description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match"),
        detection_name: Optional[str] = Field(default=None, description="Filter by detection name. Can also perform partial word match"),
        state: Optional[Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"]] = Field(default="active", description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'."),
        src_ip: str = Field(default=None, description="Filter by source IP address of the host that generated the detection"),
        start_date: str = Field(default=None, description="Filter by start date (YYYY-MM-DD)"),
        end_date: str = Field(default=None, description="Filter by end date (YYYY-MM-DD)"),
        is_targeting_key_asset: bool = Field(default=None, description="Filter by detection targets a key asset"),
        limit: Optional[int] = Field(default=None, description="Maximum number of detections to return in the batch.", ge = 1, le=1000),
        ordering: Optional[Literal['created_datetime', 'last_timestamp', 'id']] = Field(default=None, description="Order by last_timestamp, created_datetime, or id")
    )-> str:
        """
        List detections with filtering and sorting options. Use this to get a detailed list of detections based on various criteria.
        
        Args:
            detection_category (Optional[str]): Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match.
            detection_name (Optional[str]): Filter by detection name. Can also perform partial word match.
            state (Optional[str]): Filter by state (active, inactive, fixed). Default is 'active'.
            src_ip (Optional[str]): Filter by source IP address of the host that generated the detection.
            start_date (Optional[str]): Filter by start date (YYYY-MM-DD).
            end_date (Optional[str]): Filter by end date (YYYY-MM-DD).
            is_targeting_key_asset (Optional[bool]): Filter by key asset targeting.
            limit (Optional[int]): Maximum number of detections to return if the total count exceeds this limit. Default is None (no limit).
            ordering (Optional[str]): Order by last_timestamp, created_datetime, or id.

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
        
        # Validate date range
        start_date, end_date = validate_date_range(start_date, end_date)
        # Add date filters if provided
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
        detection_category: Optional[Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"]] = Field(default=None, description="Filter by detection category"),
        detection_name: Optional[str] = Field(default=None, description="Filter by detection name. Can also perform partial word match"),
        state: Optional[Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"]] = Field(default="active", description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'."),
        src_ip: Optional[str] = Field(default=None, description="Filter by source IP address of the host that generated the detection."),
        start_date: Optional[str] = Field(default=None, description="Filter by start date (YYYY-MM-DD)"),
        end_date: Optional[str] = Field(default=None, description="Filter by end date (YYYY-MM-DD)"),
        is_targeting_key_asset: Optional[bool] = Field(default=None, description="Filter by detection targets a key asset")
    ) -> str:
        """
        Get the total count of detections matching the specified criteria.
        
        Args:
            detection_category (str): Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match.
            detection_name (str): Filter by detection name. Can also perform partial word match.
            state (str): Filter by state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.
            src_ip (str): Filter by source IP address of the host that generated the detection.
            start_date (str): Filter by start date (YYYY-MM-DD).
            end_date (str): Filter by end date (YYYY-MM-DD).
            is_targeting_key_asset (Optional[bool]): Filter by detection targets a key asset.

        Returns:
            str: Count of detections matching the criteria.
        """
        params = locals().copy()
        exclude_params = {'self', 'start_date', 'end_date'}

        search_params = {k: v for k, v in params.items()
                   if v is not None and k not in exclude_params}

        # Validate date range
        start_date, end_date = validate_date_range(start_date, end_date)
        # Add date filters if provided
        if start_date:
            search_params["last_timestamp_gte"] = start_date.isoformat()
        if end_date:
            search_params["last_timestamp_lte"] = end_date.isoformat()

        detections_response = await self.client.get_detections(**search_params)
        total_count = detections_response.get("count")
        
        return f"Total detections matching criteria: {total_count}"
    
    async def get_detection_pcap(
        self,
        detection_id: int = Field(ge=1, description="ID of the detection to retrieve pcap for")
    ) -> str:
        """
        Get pcap file for a specific detection.
        
        Args:
            detection_id (int): The ID of the detection to retrieve pcap for.
        
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
        entity_id: int = Field(ge=1, description="ID of the entity to list detections for"),
        state: Optional[Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"]] = Field(description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'.")
    ) -> str:
        """
        List all detections with full details for a specific entity. 
        
        Args:
            entity_id (int): The ID of the entity to list detections for.
            state (Optional[str]): Optionally filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule).
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
        detection_category: Optional[Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"]] = Field(default=None, description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match"),
        detection_name: Optional[str] = Field(default=None, description="Filter by detection name. Can also perform partial word match"),
        state: Optional[Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"]] = Field(default="active", description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'."),
        src_ip: str = Field(default=None, description="Filter by source IP address of the host that generated the detection"),
        start_date: str = Field(default=None, description="Filter by start date (YYYY-MM-DD)"),
        end_date: str = Field(default=None, description="Filter by end date (YYYY-MM-DD)"),
        is_targeting_key_asset: bool = Field(default=None, description="Filter by detection targets a key asset"),
        limit: Optional[int] = Field(default=None, description="Maximum number of detections to return in the batch.", ge = 1, le=1000),
        ordering: Optional[Literal['created_datetime', 'last_timestamp', 'id']] = Field(default=None, description="Order by last_timestamp, created_datetime, or id")
    )-> str:
        """
        List detections with basic information and filtering options. Use this to get a quick overview of detections without detailed information.
        
        Args:
            detection_category (Optional[str]): Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match.
            detection_name (Optional[str]): Filter by detection name. Can also perform partial word match.
            state (Optional[str]): Filter by state (active, inactive, fixed). Default is 'active'.
            src_ip (Optional[str]): Filter by source IP address of the host that generated the detection.
            start_date (Optional[str]): Filter by start date (YYYY-MM-DD).
            end_date (Optional[str]): Filter by end date (YYYY-MM-DD).
            is_targeting_key_asset (Optional[bool]): Filter by key asset targeting.
            limit (Optional[int]): Maximum number of detections to return if the total count exceeds this limit. Default is None (no limit).
            ordering (Optional[str]): Order by last_timestamp, created_datetime, or id.

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
        
        # Validate date range
        start_date, end_date = validate_date_range(start_date, end_date)
        # Add date filters if provided
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
                for dets in detection_list
            ]

        response = {"detection_count": total_count, "detections": detections}
        
        if limit:
            if total_count > limit:
            # Limit the number of detections returned to reduce response size
                detections = detections[:limit]
                response["note"] = f"Results limited to {limit} detections. Total detections found: {total_count}."
                response["detections"] = detections
            
        return json.dumps(response, indent=2)
    

    async def get_detection_summary(
        self,
        detection_id: int = Field(ge=1, description="ID of the detection to retrieve summary for")
    ) -> str:
        """
        Get a concise summary of a detection including its ID, name, category, last timestamp, triage status, state, entity type, and detection summary. The detection summary includes key details about the detection including event specific details and description.
        
        Args:
            detection_id (int): The ID of the detection to retrieve summary for.
        
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
        detection_category: Optional[Literal["command", "botnet", "lateral", "reconnaissance", "exfiltration", "info"]] = Field(default=None, description="Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match"),
        detection_name: Optional[str] = Field(default=None, description="Filter by detection name. Can also perform partial word match"),
        state: Optional[Literal["active", "inactive", "fixed", "filteredbyai", "filteredbyrule"]] = Field(default="active", description="Filter by detection state (active, inactive, fixed, filteredbyai, filteredbyrule). Default is 'active'."),
        src_ip: str = Field(default=None, description="Filter by source IP address of the host that generated the detection"),
        start_date: str = Field(default=None, description="Filter by start date (YYYY-MM-DD)"),
        end_date: str = Field(default=None, description="Filter by end date (YYYY-MM-DD)"),
        is_targeting_key_asset: bool = Field(default=None, description="Filter by detection targets a key asset"),
        limit: Optional[int] = Field(default=None, description="Maximum number of detections to return in the batch.", ge = 1, le=1000),
        ordering: Optional[Literal['created_datetime', 'last_timestamp', 'id']] = Field(default=None, description="Order by last_timestamp, created_datetime, or id")
    )-> str:
        """
        List detection IDs with filtering and sorting options. Use this to get a list of detection IDs based on various criteria.
        
        Args:
            detection_category (Optional[str]): Filter by detection category. Detections are grouped into one of the following categories: Command & Control, Botnet, Exfiltration, Lateral Movement, Reconnaissance, Info. Can also perform partial word match.
            detection_name (Optional[str]): Filter by detection name. Can also perform partial word match.
            state (Optional[str]): Filter by state (active, inactive, fixed). Default is 'active'.
            src_ip (Optional[str]): Filter by source IP address of the host that generated the detection.
            start_date (Optional[str]): Filter by start date (YYYY-MM-DD).
            end_date (Optional[str]): Filter by end date (YYYY-MM-DD).
            is_targeting_key_asset (Optional[bool]): Filter by key asset targeting.
            limit (Optional[int]): Maximum number of detections to return if the total count exceeds this limit. Default is None (no limit).
            ordering (Optional[str]): Order by last_timestamp, created_datetime, or id.

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
        
        # Validate date range
        start_date, end_date = validate_date_range(start_date, end_date)
        # Add date filters if provided
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