"""Listing tools must not silently over-restrict or over-fetch.

Two failure modes, both previously live:

* **Over-restriction.** `list_entities(is_prioritized=...)` defaulted to `True`,
  so every call silently returned only prioritized entities. "Prioritized" is a
  manual platform flag unrelated to `urgency_score`, so a queue sweep ordered by
  urgency was quietly filtered to a subset.

* **Over-fetching.** `list_detections_with_details` defaulted to `limit=1000`
  and returned every field. Two fields dominate a detection's size — a
  CrowdStrike query link (~4KB) and `grouped_details`, which repeats one payload
  per occurrence — so a broad pull produced "tool result too large".

These tests pin the defaults. They are behavioural guarantees, not style.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from vectra_mcp_server.tool.detection_tools import DetectionMCPTools
from vectra_mcp_server.tool.entity_tools import EntityMCPTools

#: What the listing tools exclude by default. `grouped_details` only —
#: `process_context_data` is NOT in the API's accepted enum, and defaulting to
#: it made the API reject the whole parameter and return an empty list against
#: a 162-detection queue. Silent, and the same failure shape this module exists
#: to prevent.
HEAVY = {"grouped_details"}


@pytest.fixture
def client():
    c = MagicMock()
    c.get_detections = AsyncMock(return_value={"results": [], "count": 0})
    c.get_entities = AsyncMock(return_value={"results": [], "count": 0})
    return c


# ---------------------------------------------------------------------------
# Over-fetching
# ---------------------------------------------------------------------------

async def test_details_excludes_heavy_fields_by_default(client):
    await DetectionMCPTools(None, client).list_detections_with_details()
    sent = client.get_detections.await_args.kwargs
    assert set(sent["exclude_fields"].split(",")) == HEAVY


async def test_basic_info_excludes_heavy_fields_by_default(client):
    await DetectionMCPTools(None, client).list_detections_with_basic_info()
    sent = client.get_detections.await_args.kwargs
    assert set(sent["exclude_fields"].split(",")) == HEAVY


async def test_exclusion_is_overridable(client):
    """The caller can still ask for everything — the default is a guard, not a wall."""
    await DetectionMCPTools(None, client).list_detections_with_details(exclude_fields=None)
    assert "exclude_fields" not in client.get_detections.await_args.kwargs


async def test_default_exclusions_are_all_accepted_by_the_api(client):
    """The regression that shipped: a field name outside the API's enum makes it
    reject the parameter and return nothing, so both listing tools came back
    empty against a real queue. Pin every default against the accepted set."""
    from vectra_mcp_server.tool.base import DETECTION_FIELD_NAMES
    import inspect
    tools = DetectionMCPTools(None, client)
    for fn in (tools.list_detections_with_details, tools.list_detections_with_basic_info):
        default = inspect.signature(fn).parameters["exclude_fields"].default
        for name in default.split(","):
            assert name.strip() in DETECTION_FIELD_NAMES, (
                f"{fn.__name__} defaults to excluding '{name.strip()}', which the "
                f"detections API does not accept — the call will return empty"
            )


async def test_invalid_exclude_field_fails_loudly(client):
    """An unrecognised name must raise, not silently empty the result."""
    with pytest.raises(ValueError, match="does not accept"):
        await DetectionMCPTools(None, client).list_detections_with_details(
            exclude_fields="process_context_data"
        )
    client.get_detections.assert_not_awaited()


async def test_process_context_data_is_not_excludable(client):
    """It appears on the response but is absent from the enum — the exact trap."""
    from vectra_mcp_server.tool.base import DETECTION_FIELD_NAMES
    assert "process_context_data" not in DETECTION_FIELD_NAMES
    assert "grouped_details" in DETECTION_FIELD_NAMES


async def test_details_limit_defaults_low(client):
    """1000 full detections is ~15MB. 25 is a usable page."""
    tools = DetectionMCPTools(None, client)
    import inspect
    assert inspect.signature(tools.list_detections_with_details).parameters["limit"].default == 25


# ---------------------------------------------------------------------------
# Over-restriction
# ---------------------------------------------------------------------------

async def test_list_entities_does_not_filter_on_prioritized_by_default(client):
    """The regression this module exists for: a default of True silently
    returned only prioritized entities on every call."""
    await EntityMCPTools(None, client).list_entities()
    assert "is_prioritized" not in client.get_entities.await_args.kwargs


async def test_list_entities_still_honours_an_explicit_prioritized_filter(client):
    await EntityMCPTools(None, client).list_entities(is_prioritized=True)
    assert client.get_entities.await_args.kwargs["is_prioritized"] is True


async def test_list_entities_orders_by_urgency_by_default(client):
    await EntityMCPTools(None, client).list_entities()
    assert client.get_entities.await_args.kwargs["ordering"] == "urgency_score"


async def test_list_entities_returns_both_types_by_default(client):
    """The API's `type` filter is optional (required: false). The tool made it a
    required positional, so a 'hosts + accounts unified view' — which is how the
    starter's tool table describes this tool — was impossible in one call."""
    await EntityMCPTools(None, client).list_entities()
    assert "type" not in client.get_entities.await_args.kwargs


async def test_list_entities_translates_entity_type_to_the_api_type_param(client):
    """The tool exposes entity_type (avoiding the `type` builtin) and sends `type`."""
    await EntityMCPTools(None, client).list_entities(entity_type="account")
    sent = client.get_entities.await_args.kwargs
    assert sent["type"] == "account"
    assert "entity_type" not in sent


# ---------------------------------------------------------------------------
# Description hygiene
# ---------------------------------------------------------------------------

def test_is_prioritized_description_states_the_footgun():
    """A caller must be able to learn from the description alone that this
    field is unrelated to urgency and narrows results."""
    import inspect
    p = inspect.signature(EntityMCPTools.list_entities).parameters["is_prioritized"]
    text = str(p.annotation).lower()
    assert "urgency_score" in text
    assert "narrows" in text or "not a proxy" in text
