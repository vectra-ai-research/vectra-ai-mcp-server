"""Investigation-report rendering: case JSON in, one self-contained HTML file out.

This lives in the MCP server rather than in the skill that describes the format,
and the reason is worth recording because the alternative was tried and failed
for a whole afternoon.

The renderer began as `scripts/render_report.py` inside the
`vectra-investigation-report` skill. Three separate problems killed that:

1. **A plugin carrying a fourth file under `skills/*/scripts/` silently fails
   to install.** It appears in the plugin list with the correct skill count and
   then stays disabled, with a message blaming plugin sync. Nine bisected
   bundles established that the file's name, extension, size, content and mode
   were all irrelevant — only its presence mattered.
2. **Shipping it as a companion file needs somewhere to put it**, needs the
   operator told where that is, and needs the skill to guess the path.
3. **And none of that helps, because a plain MCP client cannot execute
   Python.** The agent could write a case file and name a renderer it had no
   way to run.

As a tool, all three vanish. The server is already a Python package, already
installed by `uvx`, already executes, and already returns file paths — see
`get_detection_pcap`, which set that pattern. The skill describes the format;
the server renders it; the tester installs nothing extra.

`renderer.py` is standard library only and imports nothing from this package,
so it still runs standalone (`python3 renderer.py case.json`) for anyone who
wants to render a stored case file by hand.
"""

from .renderer import CaseError, render, slugify, validate

__all__ = ["CaseError", "render", "slugify", "validate"]
