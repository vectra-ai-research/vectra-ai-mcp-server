"""MCP tools for platform management."""

from typing import Literal, Annotated
from pydantic import Field
import json

from ..utils.validators import validate_date_range
from .base import BaseMCPTools


class ManagementMCPTools(BaseMCPTools):
    """MCP tools for Vectra AI platform management."""

    def register_tools(self):
        """Register all platform management tools with the MCP server."""
        self._register_tool(self.list_platform_users)
        self._register_tool(self.get_platform_health)

    async def get_platform_health(
        self,
        health_type: Annotated[
            Literal[
                "all",
                "platform",
                "edr",
                "edr_details",
                "external_connectors",
                "external_connectors_details",
                "network_brain_ping",
            ],
            Field(
                description=(
                    "Health information to fetch. Defaults to all, which returns platform, "
                    "EDR, external connector, and Network Brain health information."
                )
            ),
        ] = "all",
        connector_type: Annotated[
            str | None,
            Field(
                description=(
                    "Comma-separated external connector types to include in detailed "
                    "connector health. Valid values: active_directory, azure_ad_lockdown, "
                    "aws, azure, google_cloud, reverse_lookup_dns, siem, vcenter, "
                    "windows_event_log_ingestion, zscaler_private_access."
                )
            ),
        ] = None,
        edr_type: Annotated[
            str | None,
            Field(
                description=(
                    "Optional comma-separated EDR type filter for detailed EDR health. "
                    "Passed directly to Vectra's edr_type query parameter."
                )
            ),
        ] = None,
        live: Annotated[
            bool | None,
            Field(
                description=(
                    "For detailed EDR and external-connector health, request a live "
                    "refresh instead of cached health information."
                )
            ),
        ] = None,
    ) -> str:
        """Get platform health, a specific health category, or complete diagnostics."""
        self._validate_health_filters(health_type, connector_type, edr_type, live)

        requests = {
            "platform": self.client.get_health,
            "edr": self.client.get_edr_health,
            "edr_details": lambda: self.client.get_edr_health_details(
                edr_type=edr_type, live=live
            ),
            "external_connectors": self.client.get_external_connectors_health,
            "external_connectors_details": lambda: self.client.get_external_connectors_health_details(
                connector_type=connector_type, live=live
            ),
            "network_brain_ping": self.client.ping_network_brain,
        }

        if health_type != "all":
            try:
                return json.dumps(await requests[health_type](), indent=2)
            except Exception as exc:
                raise Exception(
                    f"Failed to fetch {health_type} health information: {exc}"
                ) from exc

        results = {}
        errors = {}
        for category, request in requests.items():
            try:
                results[category] = await request()
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)}
                if getattr(exc, "status_code", None) is not None:
                    error["status_code"] = exc.status_code
                errors[category] = error

        response = {"results": results}
        if errors:
            response["errors"] = errors
        return json.dumps(response, indent=2)

    @staticmethod
    def _validate_health_filters(
        health_type: str,
        connector_type: str | None,
        edr_type: str | None,
        live: bool | None,
    ) -> None:
        """Validate filters before dispatching health requests."""
        connector_detail_types = {"all", "external_connectors_details"}
        edr_detail_types = {"all", "edr_details"}
        detail_types = connector_detail_types | edr_detail_types

        if connector_type and health_type not in connector_detail_types:
            raise ValueError(
                "connector_type is only valid for external_connectors_details or all"
            )
        if edr_type and health_type not in edr_detail_types:
            raise ValueError("edr_type is only valid for edr_details or all")
        if live is not None and health_type not in detail_types:
            raise ValueError(
                "live is only valid for edr_details, external_connectors_details, or all"
            )

        valid_connector_types = {
            "active_directory",
            "azure_ad_lockdown",
            "aws",
            "azure",
            "google_cloud",
            "reverse_lookup_dns",
            "siem",
            "vcenter",
            "windows_event_log_ingestion",
            "zscaler_private_access",
        }
        if connector_type:
            requested_types = {item.strip() for item in connector_type.split(",") if item.strip()}
            invalid_types = requested_types - valid_connector_types
            if not requested_types or invalid_types:
                raise ValueError(
                    "Invalid connector_type values: "
                    + ", ".join(sorted(invalid_types or {connector_type}))
                )

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
            return json.dumps({"user_count": user_count, "user_list": user_list}, indent=2)
            
        except Exception as e:
            raise Exception(f"Failed to list users : {str(e)}")
