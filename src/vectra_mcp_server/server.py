#!/usr/bin/env python3
"""Vectra AI MCP Server with support for stdio, SSE, and streamable-http transports."""

import argparse
import json
import logging
import os
import sys
from typing import Optional

import uvicorn
from mcp.server.fastmcp import FastMCP

from .vectra_client import VectraClient
from .config import load_configuration, ServerConfiguration
from .utils.logging import setup_logging, get_logger, configure_debug_logging

from .tool.base import READ_ONLY
from .tool.detection_tools import DetectionMCPTools
from .tool.entity_tools import EntityMCPTools
from .tool.investigation_tools import InvestigationMCPTools
from .tool.management_tools import ManagementMCPTools
from .tool.response_tools import ResponseMCPTools
from .prompt.prompt import VectraMCPPrompts
from .resources.investigation_resources import InvestigationResourceTools

logger = get_logger(__name__)


class VectraMCPServer:
    """Main server class for the Vectra MCP server."""

    def __init__(self, debug: bool = False, config_file: Optional[str] = None):
        """Initialize the Vectra MCP server.

        Args:
            debug: Enable debug logging
            config_file: Optional path to YAML config file for multi-tenant setup
        """
        self.debug = debug

        # Configure logging system
        log_file = os.environ.get('VECTRA_LOG_FILE')
        setup_logging(
            level='DEBUG' if debug else 'INFO',
            log_file=log_file,
            enable_console=True
        )

        if self.debug:
            configure_debug_logging()
            logger.info("Debug logging enabled")

        logger.info("Initializing Vectra MCP Server")

        # Load configuration (single-tenant or multi-tenant)
        self.config = load_configuration(config_file)

        # Initialize the MCP server
        self.server = FastMCP(
            name="Vectra MCP Server",
            instructions="This server provides access to Vectra AI security detection and investigation capabilities.",
            debug=self.debug,
            log_level="DEBUG" if self.debug else "INFO",
        )

        # Create per-tenant clients and register tools
        self.clients = {}  # tenant_name -> VectraClient
        tool_count = self._register_tools()
        tool_word = "tool" if tool_count == 1 else "tools"

        tenant_word = "tenant" if len(self.config.tenants) == 1 else "tenants"
        logger.info(
            "Initialized server with %d %s across %d %s",
            tool_count, tool_word, len(self.config.tenants), tenant_word
        )

    def _register_tools(self) -> int:
        """Register all tools with the MCP server.

        In single-tenant mode, tools are registered without a prefix (backward compatible).
        In multi-tenant mode, each tenant's tools are prefixed with the tenant name.

        Returns:
            int: Number of tools registered
        """
        if self.config.is_multi_tenant:
            # Register list_tenants meta-tool
            self._register_list_tenants_tool()

            # Register per-tenant tools
            for tenant in self.config.tenants:
                vectra_cfg = self.config.vectra_config_for_tenant(tenant)
                client = VectraClient(vectra_cfg)
                self.clients[tenant.name] = client

                tenant_label = f"{tenant.name} ({tenant.base_url})"
                logger.info("Registering tools for tenant '%s' (%s)", tenant.name, tenant.base_url)
                self._register_tenant_tools(client, prefix=tenant.name, tenant_label=tenant_label)
        else:
            # Single-tenant: no prefix (backward compatible)
            tenant = self.config.tenants[0]
            vectra_cfg = self.config.vectra_config_for_tenant(tenant)
            client = VectraClient(vectra_cfg)
            self.clients[tenant.name] = client
            self._register_tenant_tools(client, prefix=None, tenant_label=None)

        # Get tool count
        return len(self.server._tool_manager.list_tools())

    def _register_tenant_tools(self, client: VectraClient, prefix: Optional[str], tenant_label: Optional[str]):
        """Register all tool classes for a single tenant."""
        DetectionMCPTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        EntityMCPTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        InvestigationMCPTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        ManagementMCPTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        ResponseMCPTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        InvestigationResourceTools(self.server, client, prefix=prefix, tenant_label=tenant_label).register_tools()
        VectraMCPPrompts(self.server, client, prefix=prefix, tenant_label=tenant_label).register_prompts()

    def _register_list_tenants_tool(self):
        """Register the list_tenants meta-tool (multi-tenant mode only)."""
        tenant_info = [
            {"name": t.name, "base_url": t.base_url}
            for t in self.config.tenants
        ]

        # NOTE: registered directly rather than through BaseMCPTools._register_tool,
        # so its annotations must be set here.
        @self.server.tool(
            name="list_tenants",
            description="List all configured Vectra tenants and their tool name prefixes.",
            annotations=READ_ONLY,
        )
        async def list_tenants() -> str:
            """List all configured Vectra tenants and their tool name prefixes."""
            return json.dumps({"tenants": tenant_info}, indent=2)

    def run(self, transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000):
        """Run the MCP server.

        Args:
            transport: Transport protocol to use ("stdio", "sse", or "streamable-http")
            host: Host to bind to for HTTP transports (default: 127.0.0.1)
            port: Port to listen on for HTTP transports (default: 8000)
        """
        if transport == "streamable-http":
            # For streamable-http, use uvicorn directly for custom host/port
            logger.info("Starting streamable-http server on %s:%d (MCP endpoint at /mcp)", host, port)

            # Get the ASGI app from FastMCP (serves MCP protocol at root path)
            app = self.server.streamable_http_app()

            # Run with uvicorn for custom host/port configuration
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level="info" if not self.debug else "debug",
            )
        elif transport == "sse":
            # For sse, use uvicorn directly for custom host/port (same pattern as streamable-http)
            logger.info("Starting sse server on %s:%d (MCP endpoint at /sse)", host, port)

            # Get the ASGI app from FastMCP (serves MCP protocol at root path)
            app = self.server.sse_app()

            # Run with uvicorn for custom host/port configuration
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level="info" if not self.debug else "debug",
            )
        else:
            # For stdio, use the default FastMCP run method (no host/port needed)
            logger.info("Starting stdio server")
            self.server.run(transport)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Vectra AI MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        # Run with stdio transport (default)
        vectra-ai-mcp-server
        vectra-ai-mcp-server --transport stdio

        # Run with SSE transport (MCP endpoint at http://host:port/sse)
        vectra-ai-mcp-server --transport sse
        vectra-ai-mcp-server --transport sse --host 0.0.0.0 --port 8080

        # Run with streamable-http transport (MCP endpoint at http://host:port/mcp)
        vectra-ai-mcp-server --transport streamable-http
        vectra-ai-mcp-server --transport streamable-http --host 0.0.0.0 --port 8000

        # Run with multi-tenant YAML config
        vectra-ai-mcp-server --config tenants.yaml
        vectra-ai-mcp-server -c tenants.yaml --transport sse

        # Equivalent forms:
        python -m vectra_mcp_server
        uvx vectra-ai-mcp-server                       # once published to PyPI
        uvx --from . vectra-ai-mcp-server              # from a source checkout
        """
    )

    # Transport options
    parser.add_argument(
        "--transport",
        "-t",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("VECTRA_MCP_TRANSPORT", "stdio"),
        help="Transport protocol to use (default: stdio, env: VECTRA_MCP_TRANSPORT)"
    )

    # Configuration file
    parser.add_argument(
        "--config",
        "-c",
        default=os.environ.get("VECTRA_CONFIG_FILE", None),
        help="Path to YAML configuration file for multi-tenant setup (env: VECTRA_CONFIG_FILE)"
    )

    # Debug mode
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=os.environ.get("VECTRA_MCP_DEBUG", "").lower() == "true",
        help="Enable debug logging (env: VECTRA_MCP_DEBUG)"
    )

    # HTTP transport configuration
    parser.add_argument(
        "--host",
        default=os.environ.get("VECTRA_MCP_HOST", "0.0.0.0"),
        help="Host to bind to for HTTP transports (default: 0.0.0.0, env: VECTRA_MCP_HOST)"
    )

    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=int(os.environ.get("VECTRA_MCP_PORT", "8000")),
        help="Port to listen on for HTTP transports (default: 8000, env: VECTRA_MCP_PORT)"
    )

    return parser.parse_args()


def main():
    """Main entry point for the Vectra MCP server."""
    # Parse command line arguments (includes environment variable defaults)
    args = parse_args()

    try:
        # Create and run the server
        server = VectraMCPServer(debug=args.debug, config_file=args.config)
        logger.info("Starting server with %s transport", args.transport)
        server.run(args.transport, host=args.host, port=args.port)
    except RuntimeError as e:
        logger.error("Runtime error: %s", e)
        sys.exit(1)
    except ValueError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        # Catch any other exceptions to ensure graceful shutdown
        logger.error("Unexpected error running server: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
