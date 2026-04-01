"""Base class for MCP tool registration with multi-tenant prefix support."""

import functools
from typing import Optional


class BaseMCPTools:
    """Base class providing prefixed tool registration for multi-tenancy."""

    def __init__(self, vectra_mcp, client, prefix: Optional[str] = None, tenant_label: Optional[str] = None):
        """Initialize with FastMCP instance, Vectra client, and optional tenant prefix.

        Args:
            vectra_mcp: FastMCP server instance
            client: VectraClient instance
            prefix: Tool name prefix for multi-tenant mode (e.g., "prod")
            tenant_label: Human-readable tenant label for descriptions (e.g., "prod (https://prod.vectra.ai)")
        """
        self.vectra_mcp = vectra_mcp
        self.client = client
        self.prefix = prefix
        self.tenant_label = tenant_label

    def _register_tool(self, method):
        """Register a tool with optional tenant prefix on the name and description.

        In single-tenant mode (prefix=None), this behaves identically to
        ``self.vectra_mcp.tool()(method)`` -- no name or description override.

        In multi-tenant mode, the tool name becomes ``{prefix}_{method.__name__}``
        and the first line of the docstring is prefixed with ``[{tenant_label}]``.
        """
        if self.prefix:
            name = f"{self.prefix}_{method.__name__}"
            # Build a prefixed description from the docstring's first line
            description = None
            if method.__doc__:
                first_line = method.__doc__.strip().split("\n")[0].strip()
                description = f"[{self.tenant_label or self.prefix}] {first_line}"

            # We need a wrapper with a distinct identity so FastMCP doesn't
            # reject duplicate registrations of the same function object.
            @functools.wraps(method)
            async def wrapper(*args, **kwargs):
                return await method(*args, **kwargs)

            kwargs = {"name": name}
            if description:
                kwargs["description"] = description
            self.vectra_mcp.tool(**kwargs)(wrapper)
        else:
            # Single-tenant: register as-is (backward compatible)
            self.vectra_mcp.tool()(method)
