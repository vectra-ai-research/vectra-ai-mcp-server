"""Base class for MCP tool registration with multi-tenant prefix support."""

import functools
import inspect
from typing import Optional

from mcp.types import ToolAnnotations

from ..client_access import ClientHolder


# ---------------------------------------------------------------------------
# Tool behaviour annotations
#
# Every registered tool must declare one of the constants below. Annotations
# are advisory hints (per the MCP spec) that let a host tell a safe read apart
# from a call that changes tenant state. For a client driving this server
# without any SOC playbook loaded, they are the *only* such signal available,
# so an unannotated mutating tool is indistinguishable from a query.
#
# ``openWorldHint`` is False throughout: every tool addresses one Vectra
# tenant's own data — a closed, enumerable domain — rather than an open-ended
# external world such as a web search.
# ---------------------------------------------------------------------------

#: Pure query. Changes nothing; safe to call repeatedly.
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    idempotentHint=True,
    openWorldHint=False,
)

#: Adds state without removing or overwriting any. Repeating leaves the same
#: end state (e.g. appending a member that is already present).
ADDITIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

#: Adds state, and every call creates a distinct new object (a new note, a new
#: assignment, a new query job). Repeating is not a no-op.
ADDITIVE_EACH_CALL = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)

#: Removes, closes, or suppresses existing state. A host should treat these as
#: requiring explicit human approval.
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=False,
)


#: Values the detections API accepts for `fields` / `exclude_fields`. Passing
#: anything outside this set makes the API reject the whole parameter, and the
#: call comes back **empty rather than erroring** — a silent empty queue.
#: Learned the hard way: `process_context_data` looks like a field on the
#: response (it is) but is not in the enum, and defaulting to it emptied both
#: detection-listing tools against a 162-detection queue.
DETECTION_FIELD_NAMES = frozenset({
    "id", "assigned_to", "assigned_date", "certainty", "created_timestamp",
    "custom_detection", "data_source", "description", "detection",
    "detection_category", "detection_type", "detection_url", "groups",
    "filtered_by_rule", "filtered_by_ai", "filtered_by_user",
    "first_timestamp", "grouped_details", "last_timestamp", "is_custom_model",
    "is_marked_custom", "is_targeting_key_asset", "is_triaged", "note",
    "notes", "note_modified_by", "note_modified_timestamp", "reason",
    "sensor", "sensor_name", "src_account", "src_host", "src_ip", "state",
    "summary", "tags", "threat", "triage_rule_id", "type", "url",
})


def validate_detection_fields(value: Optional[str], param: str = "exclude_fields") -> None:
    """Raise on a field name the detections API will reject.

    Fail loudly here rather than let the API silently return nothing. An empty
    result that means "your parameter was invalid" is indistinguishable from
    one that means "no detections match".
    """
    if not value:
        return
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in DETECTION_FIELD_NAMES]
    if unknown:
        raise ValueError(
            f"{param} contains value(s) the detections API does not accept: "
            f"{', '.join(unknown)}. Accepted: "
            f"{', '.join(sorted(DETECTION_FIELD_NAMES))}"
        )


class BaseMCPTools(ClientHolder):
    """Base class providing prefixed tool registration for multi-tenancy."""

    def __init__(
        self,
        vectra_mcp,
        client=None,
        prefix: Optional[str] = None,
        tenant_label: Optional[str] = None,
        *,
        client_provider=None,
    ):
        """Initialize with FastMCP instance, Vectra client, and optional tenant prefix.

        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance, resolved once. The historical form;
                still what the server passes.
            prefix: Tool name prefix for multi-tenant mode (e.g., "prod")
            tenant_label: Human-readable tenant label for descriptions (e.g., "prod (https://prod.vectra.ai)")
            client_provider: Keyword-only alternative to *client*: a
                zero-argument callable resolved on every ``self.client``
                access. This is what allows the active profile to change
                without restarting the server. See ``client_access``.

        *client* stays the second positional parameter, so every existing
        ``cls(server, client, prefix=..., tenant_label=...)`` call site — the
        server, the tool inventory script, and every test — is unaffected.
        """
        self.vectra_mcp = vectra_mcp
        self._init_client(client=client, client_provider=client_provider)
        self.prefix = prefix
        self.tenant_label = tenant_label

    def _register_tool(self, method, annotations: ToolAnnotations):
        """Register a tool with behaviour annotations and an optional tenant prefix.

        In single-tenant mode (prefix=None), this behaves identically to
        ``self.vectra_mcp.tool()(method)`` apart from attaching ``annotations``
        -- no name or description override.

        In multi-tenant mode, the tool name becomes ``{prefix}_{method.__name__}``
        and the whole docstring is prefixed with ``[{tenant_label}]``.

        Args:
            method: The bound coroutine to expose as a tool.
            annotations: One of ``READ_ONLY``, ``ADDITIVE``,
                ``ADDITIVE_EACH_CALL``, or ``DESTRUCTIVE``. Required -- a new
                tool cannot be added without classifying its side effects.
        """
        if self.prefix:
            name = f"{self.prefix}_{method.__name__}"
            # Prefix the tenant label onto the *whole* docstring.
            #
            # This previously kept only the first line, which silently discarded
            # everything below it: the ``Returns:`` block (present on 25 of the
            # 28 tools), second-paragraph semantics, and any multi-line guidance a
            # tool carries. Tool descriptions therefore got materially worse in
            # multi-tenant deployments -- the environments where precision about
            # which tenant a call lands on matters most.
            #
            # The single-tenant path never had the bug: it passes no description,
            # so FastMCP falls back to the full ``fn.__doc__``.
            description = None
            if method.__doc__:
                label = self.tenant_label or self.prefix
                description = f"[{label}] {inspect.cleandoc(method.__doc__)}"

            # We need a wrapper with a distinct identity so FastMCP doesn't
            # reject duplicate registrations of the same function object.
            @functools.wraps(method)
            async def wrapper(*args, **kwargs):
                return await method(*args, **kwargs)

            kwargs = {"name": name, "annotations": annotations}
            if description:
                kwargs["description"] = description
            self.vectra_mcp.tool(**kwargs)(wrapper)
        else:
            # Single-tenant: register as-is (backward compatible)
            self.vectra_mcp.tool(annotations=annotations)(method)
