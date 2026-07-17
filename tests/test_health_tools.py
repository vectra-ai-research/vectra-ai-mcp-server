import json
from unittest.mock import AsyncMock

import pytest

from vectra_mcp_server.tool.management_tools import ManagementMCPTools
from vectra_mcp_server.vectra_client import VectraAPIError


class FakeHealthClient:
    def __init__(self):
        self.get_health = AsyncMock(return_value={"platform": "healthy"})
        self.get_edr_health = AsyncMock(return_value={"edr": "healthy"})
        self.get_edr_health_details = AsyncMock(return_value={"edr_details": "healthy"})
        self.get_external_connectors_health = AsyncMock(
            return_value={"external_connectors": "healthy"}
        )
        self.get_external_connectors_health_details = AsyncMock(
            return_value={"external_connector_details": "healthy"}
        )
        self.ping_network_brain = AsyncMock(return_value={"network_brain": "healthy"})


def make_tools(client):
    return ManagementMCPTools(vectra_mcp=None, client=client)


async def test_get_platform_health_routes_to_requested_category():
    client = FakeHealthClient()

    result = json.loads(
        await make_tools(client).get_platform_health(
            health_type="external_connectors_details",
            connector_type="aws,azure",
            live=True,
        )
    )

    assert result == {"external_connector_details": "healthy"}
    client.get_external_connectors_health_details.assert_awaited_once_with(
        connector_type="aws,azure", live=True
    )
    client.get_health.assert_not_awaited()


async def test_get_platform_health_all_returns_partial_results_and_errors():
    client = FakeHealthClient()
    client.get_edr_health.side_effect = VectraAPIError("not authorized", status_code=403)

    result = json.loads(await make_tools(client).get_platform_health())

    assert result["results"]["platform"] == {"platform": "healthy"}
    assert "edr" not in result["results"]
    assert result["errors"]["edr"] == {
        "type": "VectraAPIError",
        "message": "not authorized",
        "status_code": 403,
    }
    client.get_edr_health_details.assert_awaited_once_with(edr_type=None, live=None)
    client.get_external_connectors_health_details.assert_awaited_once_with(
        connector_type=None, live=None
    )


@pytest.mark.parametrize(
    ("health_type", "connector_type", "edr_type", "live"),
    [
        ("platform", "aws", None, None),
        ("edr", None, "crowdstrike", None),
        ("network_brain_ping", None, None, True),
        ("external_connectors_details", "not_a_connector", None, None),
    ],
)
async def test_get_platform_health_rejects_inapplicable_or_invalid_filters(
    health_type, connector_type, edr_type, live
):
    with pytest.raises(ValueError):
        await make_tools(FakeHealthClient()).get_platform_health(
            health_type=health_type,
            connector_type=connector_type,
            edr_type=edr_type,
            live=live,
        )
