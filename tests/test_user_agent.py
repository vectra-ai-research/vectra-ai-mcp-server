"""The User-Agent is the only signal tenant-side logging has about which server
version a customer runs, so it has to track the package version and stay that
way.

It was hardcoded `VectraMCPServer/1.0.0` in two places and never matched a
release — the package sat at 0.3.2 while the header still claimed 1.0.0, which
made version-based adoption stats impossible. These tests exist to stop it
drifting a second time.
"""

import re
from pathlib import Path

from vectra_mcp_server import __version__
from vectra_mcp_server.vectra_client import USER_AGENT

CLIENT_SRC = Path(__file__).resolve().parents[1] / "src" / "vectra_mcp_server" / "vectra_client.py"
INIT_SRC = CLIENT_SRC.parent / "__init__.py"


def test_user_agent_tracks_the_package_version():
    assert USER_AGENT == f"VectraMCPServer/{__version__}"


def test_user_agent_is_not_the_legacy_sentinel():
    """`1.0.0` now means "a build from before this changed".

    No real release ever emitted it, so tenant-side stats treat any other value
    as a post-change build. Shipping it again would silently merge the two
    populations back together.
    """
    assert USER_AGENT != "VectraMCPServer/1.0.0"
    assert not __version__.startswith("1.0.0")


def test_no_hardcoded_user_agent_remains():
    """Every call site must use the constant, not its own string literal."""
    src = CLIENT_SRC.read_text()
    literals = re.findall(r'"User-Agent":\s*(.+?),?\n', src)
    assert literals, "no User-Agent headers found — did the client move?"
    for lit in literals:
        assert lit.rstrip(",").strip() == "USER_AGENT", (
            f"hardcoded User-Agent {lit!r}: use the USER_AGENT constant so it "
            f"cannot drift from the package version"
        )


def test_version_is_defined_before_server_import():
    """Ordering in __init__.py is load-bearing, not cosmetic.

    vectra_client does `from . import __version__`, and importing .server pulls
    vectra_client in. If `from .server import main` moves above the __version__
    assignment, that resolves against a half-initialised module and the package
    fails to import at all.
    """
    lines = INIT_SRC.read_text().splitlines()
    # The assignment sits inside a try/except, so it is indented — match on the
    # stripped line. An earlier version of this test used startswith() at column
    # zero, found nothing, and raised StopIteration instead of asserting.
    version_at = next(
        i for i, l in enumerate(lines) if l.lstrip().startswith("__version__ =")
    )
    server_at = next(i for i, l in enumerate(lines) if "from .server import" in l)
    assert version_at < server_at, (
        "__init__.py assigns __version__ after importing .server — "
        "vectra_client's USER_AGENT will fail to resolve"
    )
