from unittest.mock import AsyncMock

import pytest

from vectra_mcp_server.vectra_client import VectraClient


@pytest.mark.parametrize(
    ("method_name", "kwargs", "endpoint", "params"),
    [
        ("get_health", {}, "health", None),
        ("get_edr_health", {}, "health/edr", None),
        (
            "get_edr_health_details",
            {"edr_type": "crowdstrike", "live": True},
            "health/edr/details",
            {"edr_type": "crowdstrike", "live": True},
        ),
        ("get_external_connectors_health", {}, "health/external_connectors", None),
        (
            "get_external_connectors_health_details",
            {"connector_type": "aws", "live": False},
            "health/external_connectors/details",
            {"connector_type": "aws", "live": False},
        ),
        ("ping_network_brain", {}, "health/network_brain/ping", None),
    ],
)
async def test_health_client_methods_use_expected_endpoint(method_name, kwargs, endpoint, params):
    client = VectraClient.__new__(VectraClient)
    client._make_request = AsyncMock(return_value={"ok": True})

    assert await getattr(client, method_name)(**kwargs) == {"ok": True}
    if params is None:
        client._make_request.assert_awaited_once_with("GET", endpoint)
    else:
        client._make_request.assert_awaited_once_with("GET", endpoint, params=params)
