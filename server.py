#!/usr/bin/env python3
"""Vectra AI MCP Server with support for stdio, SSE, and streamable-http transports."""

import argparse
import logging
import os
import sys
from typing import Optional

import uvicorn
from mcp.server.fastmcp import FastMCP

from vectra_client import VectraClient
from config import init_config
from utils.logging import setup_logging, get_logger, configure_debug_logging

# Import MCP tools and prompts
from tool.detection_tools import DetectionMCPTools
from tool.entity_tools import EntityMCPTools
from tool.investigation_tools import InvestigationMCPTools
from tool.management_tools import ManagementMCPTools
from tool.response_tools import ResponseMCPTools
from prompt.prompt import VectraMCPPrompts

logger = get_logger(__name__)


class VectraMCPServer:
    """Main server class for the Vectra MCP server."""

    def __init__(self, debug: bool = False):
        """Initialize the Vectra MCP server.
        
        Args:
            debug: Enable debug logging
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
        
        # Initialize Vectra API client
        config = init_config()
        self.client = VectraClient(config)
        
        # Initialize the MCP server
        self.server = FastMCP(
            name="Vectra MCP Server",
            instructions="This server provides access to Vectra AI security detection and investigation capabilities.",
            debug=self.debug,
            log_level="DEBUG" if self.debug else "INFO",
        )
        
        # Initialize and register tools
        tool_count = self._register_tools()
        tool_word = "tool" if tool_count == 1 else "tools"
        
        logger.info("Initialized server with %d %s", tool_count, tool_word)
    
    def _register_tools(self) -> int:
        """Register all tools with the MCP server.
        
        Returns:
            int: Number of tools registered
        """
        # Initialize and register detection tools
        detection_mcp_tools = DetectionMCPTools(self.server, self.client)
        detection_mcp_tools.register_tools()
        
        # Initialize and register entity tools
        entity_mcp_tools = EntityMCPTools(self.server, self.client)
        entity_mcp_tools.register_tools()
        
        # Initialize and register investigation tools
        investigation_mcp_tools = InvestigationMCPTools(self.server, self.client)
        investigation_mcp_tools.register_tools()
        
        # Initialize and register management tools
        management_mcp_tools = ManagementMCPTools(self.server, self.client)
        management_mcp_tools.register_tools()
        
        # Initialize and register response tools
        response_mcp_tools = ResponseMCPTools(self.server, self.client)
        response_mcp_tools.register_tools()

        # Initialize and register prompts
        vectra_mcp_prompts = VectraMCPPrompts(self.server, self.client)
        vectra_mcp_prompts.register_prompts()
        
        # Get tool count
        return len(self.server._tool_manager.list_tools())
    
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
        python server.py
        python server.py --transport stdio
        
        # Run with SSE transport (MCP endpoint at http://host:port/)
        python server.py --transport sse
        python server.py --transport sse --host 0.0.0.0 --port 8080
        
        # Run with streamable-http transport (MCP endpoint at http://host:port/)
        python server.py --transport streamable-http
        python server.py --transport streamable-http --host 0.0.0.0 --port 8000
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
        server = VectraMCPServer(debug=args.debug)
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