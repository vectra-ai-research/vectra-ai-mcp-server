"""Rendering a finished investigation as one self-contained HTML report."""

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Annotated, Optional

from pydantic import Field

from ..report import CaseError, render, slugify, validate
from .base import READ_ONLY, BaseMCPTools

#: Where reports land. A fixed subdirectory rather than a random temp name so
#: repeat renders of the same entity overwrite instead of accumulating, and so
#: an operator can find yesterday's report without asking. Same reasoning, and
#: the same directory convention, as PCAP_DIR.
REPORT_DIR = Path(tempfile.gettempdir()) / "vectra-reports"


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

        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORT_DIR / name
        data = page.encode("utf-8")
        path.write_bytes(data)

        verdict = parsed.get("verdict")
        code = verdict.get("code") if isinstance(verdict, dict) else verdict

        return json.dumps({
            "rendered": True,
            "path": str(path),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entity": entity,
            "verdict": code,
            "tenant": parsed.get("tenant", {}).get("label"),
            "warnings": warnings,
            "note": (
                "Give the operator this path. The file is self-contained — no "
                "JavaScript, no external references — so it opens offline and "
                "can be attached to a ticket as-is. If this server runs in a "
                "container the path is inside it; publish a volume or run the "
                "server on the host that needs the file."
            ),
        }, indent=2)
