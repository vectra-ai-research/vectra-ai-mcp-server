"""Vectra AI MCP Server package."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("vectra-ai-mcp-server")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0+unknown"

from .server import main

__all__ = ["main", "__version__"]
