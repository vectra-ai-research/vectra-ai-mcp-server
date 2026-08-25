"""The single list of tool classes the server registers.

This exists because there were three copies of it — `server.py`,
`scripts/list_tools.py`, and `tests/test_tool_annotations.py` — with nothing
checking they agreed. Adding `FindingsMCPTools` to two of the three left the
test suite green (it had been updated) while the tool inventory still reported
the old count (it had not). Silent, and the kind of drift that only shows up as
"why isn't my tool there".

Anything that needs to enumerate tool classes imports `TOOL_CLASSES` from here.
Adding a class is one edit in one place.

Prompts are deliberately excluded — they register through `register_prompts()`
rather than `register_tools()`, so they are handled separately in `server.py`.
"""

from .resources.investigation_resources import InvestigationResourceTools
from .tool.detection_tools import DetectionMCPTools
from .tool.entity_tools import EntityMCPTools
from .tool.findings_tools import FindingsMCPTools
from .tool.investigation_tools import InvestigationMCPTools
from .tool.management_tools import ManagementMCPTools
from .tool.response_tools import ResponseMCPTools

#: Every class exposing MCP tools, in registration order. Each takes
#: (server, client, prefix=..., tenant_label=...) and exposes register_tools().
TOOL_CLASSES = (
    DetectionMCPTools,
    EntityMCPTools,
    FindingsMCPTools,
    InvestigationMCPTools,
    ManagementMCPTools,
    ResponseMCPTools,
    InvestigationResourceTools,
)

__all__ = ["TOOL_CLASSES"]
