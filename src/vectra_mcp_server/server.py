#!/usr/bin/env python3
"""Vectra AI MCP Server with support for stdio, SSE, and streamable-http transports."""

import argparse
import ipaddress
import json
import logging
import os
import sys
from typing import Optional

import uvicorn
from mcp.server.fastmcp import FastMCP

from .vectra_client import VectraClient
from .config import load_configuration, ServerConfiguration
from .profiles.provider import FOLLOW_ENV, ProfileClientProvider, follow_active_enabled
from .profiles.resolver import ConfigurationError, resolve
from .utils.logging import setup_logging, get_logger, configure_debug_logging

from .registry import TOOL_CLASSES
from .tool.base import READ_ONLY
from .prompt.prompt import VectraMCPPrompts

logger = get_logger(__name__)


def _is_loopback(host: str) -> bool:
    """True when binding *host* reaches only this machine.

    An unparseable hostname is reported as NOT loopback. Warning about a bind
    that turned out to be safe costs one log line; staying quiet about one that
    is exposed costs the tenant's API credentials.
    """
    if not host:
        # uvicorn treats an empty host as all interfaces.
        return False
    if host.strip().lower() in {"localhost", "localhost."}:
        return True
    try:
        # strip brackets so the IPv6 literal form [::1] parses.
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


class VectraMCPServer:
    """Main server class for the Vectra MCP server."""

    def __init__(
        self,
        debug: bool = False,
        config_file: Optional[str] = None,
        profile: Optional[str] = None,
    ):
        """Initialize the Vectra MCP server.

        Args:
            debug: Enable debug logging
            config_file: Optional path to YAML config file for multi-tenant setup
            profile: Optional named local profile to use for this run. Mutually
                exclusive with *config_file*.
        """
        self.debug = debug
        self.profile = profile

        # Configure logging system
        log_file = os.environ.get('VECTRA_LOG_FILE')

        # LOG_FORMAT is read from the environment directly rather than from
        # VectraConfig, because logging has to be running before configuration
        # loads — load_configuration() logs, and it can raise, and a
        # configuration error is exactly the message an operator must see.
        #
        # Until now this argument was never passed at all, so LOG_FORMAT was
        # validated by the config layer and then silently ignored: a customer
        # setting json got text and no warning. The config default has been
        # corrected to "text" to match the behaviour that has always shipped —
        # wiring it up without that change would have flipped every existing
        # deployment to JSON on upgrade.
        log_format = os.environ.get('LOG_FORMAT', 'text').strip().lower()

        setup_logging(
            level='DEBUG' if debug else 'INFO',
            log_file=log_file,
            enable_console=True,
            json_format=(log_format == 'json'),
        )

        if self.debug:
            configure_debug_logging()
            logger.info("Debug logging enabled")

        logger.info("Initializing Vectra MCP Server")

        # Configuration comes from one of two places, and they are not
        # interchangeable:
        #
        #   a YAML tenants file  -> multi-tenant mode, every tenant's tools
        #                           registered with a name prefix. Unchanged.
        #   anything else        -> the profile/environment precedence chain,
        #                           one tenant, tools registered unprefixed.
        #
        # The second path ends at the legacy VECTRA_BASE_URL / _CLIENT_ID /
        # _CLIENT_SECRET variables, so a deployment that has never heard of
        # profiles behaves exactly as before.
        yaml_path = config_file or os.environ.get("VECTRA_CONFIG_FILE")

        if profile and yaml_path:
            # Refused rather than ordered by precedence. These are different
            # features answering the same question, and quietly honouring one
            # would mean an operator who asked for a tenant got a different
            # one — the failure this whole change exists to remove.
            raise ValueError(
                "--profile and --config are mutually exclusive: --config selects "
                "multi-tenant mode (prefixed tools for every tenant in the file), "
                "while --profile selects a single tenant. Choose one."
            )

        self.resolution = None
        if yaml_path and os.path.isfile(yaml_path):
            self.config = load_configuration(yaml_path)
        else:
            self.resolution = resolve(profile)
            self.config = self.resolution.server_config

        self.follow_active = follow_active_enabled()
        if self.follow_active and self.resolution is not None:
            logger.warning(
                "%s is set: the active profile will be re-read when it changes, "
                "so the tenant can change mid-conversation. Vectra's audit log "
                "records the API client rather than the analyst or the session, "
                "so a cross-tenant action would leave no trace downstream.",
                FOLLOW_ENV,
            )

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
            # Single-tenant: no prefix (backward compatible).
            #
            # Tools are given a *provider* rather than a client. Registration
            # therefore builds nothing and authenticates nothing — the first
            # client appears on the first tool call. That is what allows the
            # active profile to be re-read later, and it also means the server
            # can list its own tools without valid credentials.
            # Non-multi-tenant configuration only ever comes from resolve(),
            # which always returns a Resolution — load_configuration() sets
            # is_multi_tenant=True for every YAML path. Asserted rather than
            # defended with a fallback: a None here would mean the two loaders
            # had started disagreeing, and a quiet fallback would hide it.
            assert self.resolution is not None, "single-tenant config without a resolution"

            self.client_provider = ProfileClientProvider(
                self.resolution,
                client_factory=self._build_client,
                follow_active=self.follow_active,
                explicit_profile=self.profile,
            )
            self._register_get_active_profile_tool()
            self._register_tenant_tools(
                client_provider=self.client_provider, prefix=None, tenant_label=None
            )

        # Get tool count
        return len(self.server._tool_manager.list_tools())

    def _build_client(self, config: ServerConfiguration) -> VectraClient:
        """Construct a client for a resolved configuration. The client factory."""
        return VectraClient(config.vectra_config_for_tenant(config.tenants[0]))

    def _register_tenant_tools(
        self,
        client: Optional[VectraClient] = None,
        prefix: Optional[str] = None,
        tenant_label: Optional[str] = None,
        *,
        client_provider=None,
    ):
        """Register all tool classes for a single tenant.

        Takes a concrete *client* (multi-tenant mode, where each tenant's
        client is fixed) or a *client_provider* (single-tenant mode, where the
        tenant may be re-resolved). Exactly one, enforced by ClientHolder.

        Driven by registry.TOOL_CLASSES so this, the tool inventory script, and
        the annotation tests cannot disagree about which classes exist.
        """
        kwargs = {"prefix": prefix, "tenant_label": tenant_label}
        if client_provider is not None:
            kwargs["client_provider"] = client_provider
        else:
            kwargs["client"] = client

        for cls in TOOL_CLASSES:
            cls(self.server, **kwargs).register_tools()
        VectraMCPPrompts(self.server, **kwargs).register_prompts()

    def _register_get_active_profile_tool(self):
        """Expose which tenant the server is talking to. Read-only.

        Deliberately reports rather than controls: the model must not be able
        to change the tenant, which is why there is no matching setter tool.

        It earns its place because of the audit gap. With out-of-band switching
        an operator can change tenant mid-conversation, and nothing else in the
        transcript would say so — Vectra records the API client, not the
        analyst or the session. This lets an agent state, in its own report,
        which tenant the finding came from.
        """
        provider = self.client_provider

        # Registered directly rather than through BaseMCPTools._register_tool,
        # so its annotations are set here — same pattern as list_tenants.
        @self.server.tool(
            name="get_active_profile",
            description=(
                "Report which Vectra tenant this server is currently configured "
                "to use, and where that configuration came from. Read-only: it "
                "cannot change the tenant. Call it when a finding needs to name "
                "the tenant it came from, or to confirm the intended tenant "
                "before a state-changing action."
            ),
            annotations=READ_ONLY,
        )
        async def get_active_profile() -> str:
            """Report the active Vectra tenant and the source of that choice."""
            resolution = provider.resolution
            return json.dumps({
                "profile": resolution.profile_name,
                "base_url": resolution.base_url,
                # The non-secret half of the credential, and the identity that
                # appears in Vectra's own audit log for every action taken.
                "client_id": resolution.client_id,
                "configured_by": resolution.source,
                "follows_active_profile": provider.following,
            }, indent=2)

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
        if transport in ("streamable-http", "sse") and not _is_loopback(host):
            # Deliberately a warning and not an error: someone fronting this
            # with their own authenticating proxy has a legitimate reason to
            # bind wide. But it must never be silent — anyone who can reach
            # this port holds the tenant's API credentials by proxy, with no
            # authentication and no per-caller attribution in the audit trail.
            logger.warning(
                "Binding %s transport to %s, which is not loopback. The HTTP "
                "transports do NOT authenticate callers: anyone who can reach "
                "%s:%d can use this server's Vectra credentials. Bind "
                "127.0.0.1 unless an authenticating proxy sits in front.",
                transport, host, host, port,
            )

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

        # Use a named local profile (credentials from the OS keychain)
        vectra-ai-mcp-server                           # the active profile
        vectra-ai-mcp-server --profile acme            # this profile, whatever is active
        VECTRA_PROFILE=acme vectra-ai-mcp-server       # same, via the environment

        # Manage profiles with the companion command:
        vectra-mcp profile add acme
        vectra-mcp profile use acme

        # Run with multi-tenant YAML config (prefixed tools for every tenant)
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

    # Named local profile. Note there is no default from VECTRA_PROFILE here:
    # the environment variable is read by the resolver, one rank below an
    # explicit flag, so wiring it in as an argparse default would collapse two
    # distinct precedence levels into one and make the shadow warning wrong.
    parser.add_argument(
        "--profile",
        help="Named local profile to use (see 'vectra-mcp profile list'). "
             "Mutually exclusive with --config. Without it the server uses "
             "VECTRA_PROFILE, then the active profile, then the legacy "
             "VECTRA_BASE_URL / VECTRA_CLIENT_ID / VECTRA_CLIENT_SECRET "
             "variables."
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
    # Loopback by default. Neither HTTP transport authenticates its callers, so
    # the previous 0.0.0.0 default published an unauthenticated, fully
    # privileged Vectra API proxy to every host on the operator's network —
    # coffee-shop Wi-Fi included. The tunnelled ChatGPT case wants loopback
    # anyway: the tunnel connects outward from this machine.
    #
    # Binding wider is still supported and still one flag away; it is now a
    # decision rather than a default. See the warning in run().
    parser.add_argument(
        "--host",
        default=os.environ.get("VECTRA_MCP_HOST", "127.0.0.1"),
        help=(
            "Host to bind to for HTTP transports (default: 127.0.0.1, env: "
            "VECTRA_MCP_HOST). The HTTP transports have no authentication — "
            "bind a non-loopback address only behind your own auth layer."
        )
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
        server = VectraMCPServer(
            debug=args.debug, config_file=args.config, profile=args.profile
        )
        logger.info("Starting server with %s transport", args.transport)
        server.run(args.transport, host=args.host, port=args.port)
    except ConfigurationError as e:
        # Its own branch because the message is the whole value: it names every
        # way to configure a tenant. Logged without a traceback, which is all
        # an operator reading an MCP client's log pane can use.
        logger.error("%s", e)
        sys.exit(1)
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
