"""Rendering a finished investigation as one self-contained HTML report."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Annotated, Optional

from pydantic import Field

from ..report import CaseError, render, slugify, validate
from .base import READ_ONLY, BaseMCPTools

#: Fallback location. A fixed subdirectory rather than a random temp name so
#: repeat renders of the same entity overwrite instead of accumulating, and so
#: an operator can find yesterday's report without asking. Same reasoning, and
#: the same directory convention, as PCAP_DIR.
#:
#: The default is the system temp directory, which on macOS is an opaque
#: per-user path under /var/folders/<hash>/T/ — findable only because the tool
#: returns it. ``VECTRA_REPORT_DIR`` exists so an operator can point reports at
#: somewhere they would actually think to look.
REPORT_DIR = Path(tempfile.gettempdir()) / "vectra-reports"

#: Environment variable overriding :data:`REPORT_DIR`.
REPORT_DIR_ENV = "VECTRA_REPORT_DIR"


def _report_dir() -> tuple[Path, str]:
    """Resolve the output directory, and say where the choice came from.

    Resolved per call rather than at import, so a value can be set in the
    server's environment without being baked in at module load, and so tests
    can vary it.

    A relative value is resolved against the process working directory — which
    for a stdio server is wherever the MCP client happened to launch it, rarely
    what anyone means. It is resolved rather than rejected, and the absolute
    result is what gets reported, so the returned path is never ambiguous.

    Returns:
        The directory, and a short provenance string for the tool result. The
        provenance is there for the same reason ``get_active_profile`` reports
        ``configured_by``: when a file is not where someone expected, the
        useful answer names the mechanism that decided.
    """
    override = os.environ.get(REPORT_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve(), REPORT_DIR_ENV
    return REPORT_DIR, "system temp directory"


class ReportMCPTools(BaseMCPTools):
    """Turns a case file into a report. No Vectra API calls."""

    def register_tools(self):
        # READ_ONLY, matching get_detection_pcap, which also writes a file.
        # The annotation describes effects on the *tenant*: this touches
        # nothing in Vectra, reads nothing from it, and rendering the same case
        # twice produces the same document. A host that prompts for
        # confirmation on state changes should not prompt here.
        self._register_tool(self.render_investigation_report, READ_ONLY)

    async def render_investigation_report(
        self,
        case: Annotated[
            str,
            Field(description=(
                "The investigation case file as JSON text. The contract is the "
                "vectra-investigation-report skill's references/case-schema.md. "
                "Required fields: schema (1), entity.name, tenant.label, "
                "verdict.code, answer, next_action."
            ))
        ],
        filename: Annotated[
            Optional[str],
            Field(description=(
                "Optional output filename. Defaults to "
                "Investigation-Report-<entity>.html. Any directory component "
                "is ignored — reports always land in the server's report "
                "directory, whose path is returned."
            ))
        ] = None,
    ) -> str:
        """
        Render an investigation case file into one self-contained HTML report.

        Takes the case as JSON text rather than a file path, because the caller
        usually cannot write files: an MCP client has no filesystem access of
        its own, which is the whole reason this is a tool and not a script.

        Returns the path to the written file, not the HTML. A report is 25-30 KB
        of markup and re-emitting it through the conversation would cost more
        than the investigation did.

        A case file that fails validation comes back as
        `rendered: false` with the specific reason, NOT as an error — getting
        the schema slightly wrong is expected traffic, and the useful response
        is one the caller can act on. Fix the named field and call again.

        Returns:
            str: JSON with rendered, path, size_bytes, sha256, entity, verdict,
            and any warnings. On a validation failure: rendered false and error.

        Raises:
            Exception: only for failures that are not the case file's fault,
                such as the report directory being unwritable.
        """
        try:
            parsed = json.loads(case)
        except json.JSONDecodeError as exc:
            return json.dumps({
                "rendered": False,
                "error": f"the case is not valid JSON: {exc}",
                "hint": "Pass the case file as JSON text, not as prose or a path.",
            }, indent=2)

        if not isinstance(parsed, dict):
            return json.dumps({
                "rendered": False,
                "error": f"the case must be a JSON object, got {type(parsed).__name__}",
            }, indent=2)

        try:
            warnings = validate(parsed)
            page = render(parsed, warnings)
        except CaseError as exc:
            # Deliberately a value, not an exception. See the docstring.
            return json.dumps({
                "rendered": False,
                "error": str(exc),
                "hint": (
                    "See references/case-schema.md in the "
                    "vectra-investigation-report skill. Correct the field named "
                    "above and call this tool again."
                ),
            }, indent=2)

        entity = parsed.get("entity", {}).get("name", "entity")
        name = Path(filename).name if filename else (
            f"Investigation-Report-{slugify(entity)}.html"
        )
        if not name.lower().endswith((".html", ".htm")):
            name += ".html"

        target, source = _report_dir()
        data = page.encode("utf-8")
        path = target / name
        try:
            target.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as exc:
            # Same principle as a bad case file: a value, not a raise. An
            # operator with a typo in VECTRA_REPORT_DIR should be told which
            # path failed and how to get back to a working default, not handed
            # a traceback from inside a tool call.
            return json.dumps({
                "rendered": False,
                "error": f"cannot write the report to {path}: {exc}",
                "report_dir": str(target),
                "report_dir_source": source,
                "hint": (
                    f"Set {REPORT_DIR_ENV} to an absolute path the server can "
                    f"create, or unset it to fall back to the system temp "
                    f"directory ({REPORT_DIR})."
                ),
            }, indent=2)

        verdict = parsed.get("verdict")
        code = verdict.get("code") if isinstance(verdict, dict) else verdict

        return json.dumps({
            "rendered": True,
            "path": str(path),
            "report_dir_source": source,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entity": entity,
            "verdict": code,
            "tenant": parsed.get("tenant", {}).get("label"),
            "warnings": warnings,
            "note": (
                "Quote this path to the operator verbatim — it is not "
                "guessable, and on macOS the default temp directory is an "
                "opaque per-user path. The file is self-contained — no "
                "JavaScript, no external references — so it opens offline and "
                "can be attached to a ticket as-is. If this server runs in a "
                "container the path is inside it; publish a volume or run the "
                "server on the host that needs the file."
            ),
        }, indent=2)
