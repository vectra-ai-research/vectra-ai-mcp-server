"""Vectra AI MCP Server package."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("vectra-ai-mcp-server")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0+unknown"

# Keep this import BELOW the __version__ assignment. vectra_client builds its
# User-Agent from `__version__`, and importing .server pulls vectra_client in —
# so if this line moves above the block, that import resolves against a module
# that has no __version__ yet and the package fails to load. Guarded by
# tests/test_user_agent.py::test_version_is_defined_before_server_import.
from .server import main

__all__ = ["main", "__version__"]
