"""The decision tree, and the coverage table derived from it.

Why this section exists
-----------------------
The same entity run through two reasoning layers produced the same verdict,
the same chain and the same format — but one ran a control query and verified
an operator note while the other closed a gap and named a blast-radius
question. Neither was wrong. Both looked identically authoritative, and a
reader could not tell them apart.

That is the adoption risk in one sentence: **the format's authority is uniform
and the work behind it is not.** A well-presented shallow investigation is more
dangerous than an obviously shallow one.

So the format's claim moves from "every claim carries its provenance" to
"every *judgement* carries its alternatives and its falsifier". The tests below
pin the parts of that which a validator can enforce — and deliberately not the
part it cannot, which is whether the judgements are any good.

The refusals are chosen on one principle: refuse what would make the tree
*misleading*, warn about what merely makes it *thin*.
"""

from __future__ import annotations

import json
from html.parser import HTMLParser

import pytest

from vectra_mcp_server.report import CaseError, render, validate
from vectra_mcp_server.report.renderer import (
    CONFIDENCE,
    COVERAGE_STATUS,
    RULES,
    coverage_table,
)

BASE = {
    "schema": 1,
    "entity": {"name": "marketing-collab-server0", "kind": "host"},
    "tenant": {"label": "109796245472.ew1"},
    "verdict": {"code": "TP-High"},
    "answer": "Compromised host, C2 then lateral movement.",
    "next_action": "Escalate to IR.",
}

NODE = {
    "id": "D1",
    "question": "Is the Hidden HTTPS Tunnel real C2, or a sanctioned tunnel?",
    "concluded": "Real C2",
    "confidence": "high",
    "load_bearing": True,
    "because": ["121 sessions to one external IP inside 2.5 hours"],
    "rests_on": ["19768"],
    "would_change_if": "The destination resolves into a sanctioned SaaS range",
}


def case(**kw):
    c = dict(BASE)
    c.update(kw)
    return c


def node(**kw):
    n = dict(NODE)
    n.update(kw)
    return n


def warnings_for(**kw):
    return validate(case(**kw))


# --------------------------------------------------------------- the falsifier

def test_a_judgement_without_a_falsifier_is_refused():
    """The load-bearing rule of the whole design.

    A judgement whose author cannot name what would overturn it was not a
    judgement, it was an assumption. It is also the field an agent under time
    pressure drops first, and the field a reviewing analyst needs most — which
    is why this is a refusal and not a warning.
    """
    bad = {k: v for k, v in NODE.items() if k != "would_change_if"}
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[bad]))
    assert "would_change_if" in str(exc.value)


@pytest.mark.parametrize("blank", ["", "   ", "\n"])
def test_a_whitespace_falsifier_does_not_satisfy_the_requirement(blank):
    with pytest.raises(CaseError):
        validate(case(decisions=[node(would_change_if=blank)]))


def test_the_falsifier_is_set_apart_in_the_output():
    """It must not read as one more bullet. A reviewer uses it to turn
    'I disagree' into 'go and check this specific thing'."""
    c = case(decisions=[NODE])
    out = render(c, validate(c))
    assert "Would change if" in out
    assert "dflip" in out          # its own styled block, not a list item


# ------------------------------------------------------- addressable judgements

def test_duplicate_ids_are_refused():
    """IDs are how a reviewer addresses one judgement. "D4 is wrong" has to
    mean exactly one thing in a ticket, a handover or a customer call."""
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[NODE, node(question="different")]))
    assert "unique" in str(exc.value) or "already used" in str(exc.value)


def test_node_ids_appear_in_the_rendered_output():
    c = case(decisions=[NODE, node(id="D2", depends_on=["D1"], load_bearing=False)])
    out = render(c, validate(c))
    assert "D1" in out and "D2" in out
    assert "Follows D1" in out     # the dependency is visible, not implied


# ------------------------------------------------------------------- the tree

def test_an_unknown_parent_is_refused():
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[node(depends_on=["D9"])]))
    assert "D9" in str(exc.value)


def test_self_dependency_is_refused():
    with pytest.raises(CaseError):
        validate(case(decisions=[node(depends_on=["D1"])]))


def test_a_dependency_cycle_is_refused():
    """A reviewer following depends_on must reach a starting point."""
    a = node(id="A", depends_on=["B"])
    b = node(id="B", depends_on=["A"], load_bearing=False)
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[a, b]))
    assert "cycle" in str(exc.value).lower()


def test_a_longer_cycle_is_still_found():
    ns = [node(id="A", depends_on=["C"]),
          node(id="B", depends_on=["A"], load_bearing=False),
          node(id="C", depends_on=["B"], load_bearing=False)]
    with pytest.raises(CaseError):
        validate(case(decisions=ns))


def test_depth_orders_the_output_parents_before_children():
    child = node(id="D2", depends_on=["D1"], load_bearing=False)
    c = case(decisions=[child, NODE])          # deliberately out of order
    out = render(c, validate(c))
    assert out.index(">D1<") < out.index(">D2<")


# ------------------------------------------------------------- guard vs theatre

def test_no_load_bearing_node_warns():
    """Twelve nodes of trivia burying the two that matter is worse than no
    tree. The report has to say which judgements the verdict rests on."""
    w = warnings_for(decisions=[node(load_bearing=False)])
    assert any("load_bearing" in x for x in w)


def test_too_many_load_bearing_nodes_warns():
    ns = [node(id=f"D{i}") for i in range(1, 7)]
    w = warnings_for(decisions=ns)
    assert any("load_bearing" in x and "6" in x for x in w)


def test_a_load_bearing_node_at_low_confidence_warns_loudly():
    """That combination is the report saying the verdict rests on something
    soft. It may well be correct, but it belongs in front of the reader."""
    w = warnings_for(decisions=[node(confidence="low")])
    assert any("soft" in x for x in w)


def test_a_node_without_provenance_warns():
    bare = {k: v for k, v in NODE.items() if k != "rests_on"}
    w = warnings_for(decisions=[bare])
    assert any("provenance" in x for x in w)


def test_a_case_with_no_decisions_warns_that_it_will_become_required():
    """A warning rather than a refusal, so every case file written before this
    section existed still renders — and the warning shows in the report."""
    w = warnings_for()
    assert any("decisions" in x and "required" in x for x in w)


def test_zero_coverage_warns():
    """The louder signal, and it was missing from the first cut.

    A real run produced a two-node tree whose nodes named no rules and whose
    case file had no coverage block. All seven rules rendered "Not reported"
    and nothing warned. The report understated its own investigation, which
    had populated sweep and ruled-out sections.
    """
    w = warnings_for(decisions=[node(satisfies=[])])
    assert any("no workflow rule is accounted for" in x for x in w)


def test_thin_coverage_warns_with_a_count():
    w = warnings_for(decisions=[node(satisfies=["R1"])])
    assert any("only 1 of 7" in x for x in w)


def test_adequate_coverage_does_not_warn():
    c = case(decisions=[node(satisfies=["R1", "R2"])],
             coverage={"R3": "done", "R4": "partial"})
    assert not any("accounted for" in x or "of 7" in x for x in validate(c))


def test_the_codex_shaped_case_now_warns_on_every_count():
    """Regression for the exact shape a real run produced: two verdict-level
    nodes, no provenance, nothing load-bearing, no rules named.

    Every one of those is now called out on the page rather than only the
    load_bearing one.
    """
    thin = [
        {"id": "D1", "question": "Does the evidence support a benign explanation?",
         "concluded": "No", "would_change_if": "An approved change record covered it"},
        {"id": "D2", "question": "Should the entity be escalated?",
         "concluded": "Yes — TP-High", "would_change_if": "Primary evidence is shown to be synthetic"},
    ]
    w = validate(case(decisions=thin))
    assert any("D1 cites no provenance" in x for x in w)
    assert any("D2 cites no provenance" in x for x in w)
    assert any("load_bearing" in x for x in w)
    assert any("no workflow rule is accounted for" in x for x in w)
    assert len(w) >= 4


# ------------------------------------------------------------------ vocabulary

@pytest.mark.parametrize("value", sorted(CONFIDENCE))
def test_each_confidence_value_is_accepted(value):
    validate(case(decisions=[node(confidence=value)]))


def test_an_invented_confidence_value_is_refused():
    """Three values, not a percentage: a model asked for a number will produce
    one and it will mean nothing."""
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[node(confidence="very high")]))
    assert "confidence" in str(exc.value)


def test_an_alternative_without_a_reason_is_refused():
    """A verdict listing only its confirmations reads as more certain than it
    is. An alternative with no rejection reason is decoration."""
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[node(considered=[{"alternative": "Sanctioned VPN"}])]))
    assert "rejected_because" in str(exc.value)


def test_satisfies_must_name_a_real_workflow_rule():
    with pytest.raises(CaseError) as exc:
        validate(case(decisions=[node(satisfies=["R99"])]))
    assert "R99" in str(exc.value)


@pytest.mark.parametrize("key", ["because", "rests_on", "depends_on", "satisfies"])
def test_list_fields_must_be_lists(key):
    with pytest.raises(CaseError):
        validate(case(decisions=[node(**{key: "a string"})]))


# -------------------------------------------------------------------- coverage

def test_coverage_is_derived_from_satisfies_tags():
    """Nothing for the agent to fill in twice."""
    c = case(decisions=[node(satisfies=["R1", "R2"])])
    rows = {r["rule"]: r for r in coverage_table(c)}
    assert rows["R1"]["status"] == "done"
    assert rows["R1"]["nodes"] == ["D1"]
    assert rows["R2"]["status"] == "done"


def test_an_explicit_coverage_block_covers_rules_with_no_node():
    """How a rule that was deliberately skipped gets to say so."""
    c = case(decisions=[node(satisfies=["R1"])],
             coverage={"R2": {"status": "not run", "detail": "no inbound query"}})
    rows = {r["rule"]: r for r in coverage_table(c)}
    assert rows["R2"]["status"] == "not run"
    assert "inbound" in rows["R2"]["detail"]


def _coverage_section(out: str) -> str:
    """Just the coverage table.

    Counting "Not reported" across the whole document does not work: the
    warnings quote that label back to the reader on purpose, and warnings are
    rendered into the page. Scope the count instead of weakening the message.
    """
    start = out.index("Which workflow rules were followed")
    return out[start:out.index("</table>", start)]


def test_a_rule_with_neither_renders_as_not_reported():
    """The distinction the table exists for. A skipped check becomes a visible
    row rather than an absence nobody notices — silence is otherwise
    indistinguishable from a rule that ran and found nothing.
    """
    c = case(decisions=[node(satisfies=["R1"])])
    rows = {r["rule"]: r for r in coverage_table(c)}
    assert rows["R1"]["status"] == "done"
    unreported = [r for r in RULES if rows[r]["status"] is None]
    assert len(unreported) == len(RULES) - 1

    out = render(c, validate(c))
    assert _coverage_section(out).count("Not reported") == len(RULES) - 1


def test_every_workflow_rule_appears_in_the_table():
    c = case(decisions=[NODE])
    assert [r["rule"] for r in coverage_table(c)] == list(RULES)
    out = render(c, validate(c))
    for rule in RULES:
        assert rule in out


def test_a_bare_string_coverage_value_is_accepted():
    """`{"R2": "not run"}` is what someone will write. Accept it."""
    c = case(decisions=[NODE], coverage={"R2": "not run"})
    rows = {r["rule"]: r for r in coverage_table(c)}
    assert rows["R2"]["status"] == "not run"


@pytest.mark.parametrize("status", sorted(COVERAGE_STATUS))
def test_each_coverage_status_renders_with_a_label(status):
    c = case(decisions=[NODE], coverage={"R3": {"status": status}})
    out = render(c, validate(c))
    assert COVERAGE_STATUS[status][0] in out


# ------------------------------------------------------------------- rendering

def test_the_tree_precedes_the_narrative_detail():
    """A reviewer's first question is not "what happened in what order" but
    "how did you conclude that, and where can I disagree"."""
    c = case(decisions=[NODE],
             timeline=[{"title": "C2 established", "grade": "decisive"}])
    out = render(c, validate(c))
    assert out.index("How the verdict was reached") < out.index("Sequence")


def test_coverage_sits_directly_under_the_tree():
    c = case(decisions=[NODE])
    out = render(c, validate(c))
    assert out.index("How the verdict was reached") < out.index("Which workflow rules")


class _Attrs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.handlers = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for key, value in attrs:
            if key.lower().startswith("on") or "javascript:" in str(value or "").lower():
                self.handlers.append((tag, key))


def test_hostile_decision_text_cannot_become_markup():
    """Every string is escaped and then a three-token markup is applied. The
    tree added five new string fields; this asserts they went through it.
    """
    hostile = {
        "id": "<script>x</script>",
        "question": "<img onerror=1 src=x>",
        "concluded": "a<b",
        "would_change_if": "</div><script>alert(1)</script>",
        "because": ["<svg onload=alert(1)>"],
        "rests_on": ["<b>"],
        "considered": [{"alternative": "<iframe src=javascript:1>",
                        "rejected_because": "<a onclick=1>"}],
    }
    c = case(decisions=[hostile])
    out = render(c, validate(c))

    p = _Attrs()
    p.feed(out)
    assert p.handlers == [], f"live event handlers rendered: {p.handlers}"
    for forbidden in ("img", "svg", "iframe", "script"):
        assert forbidden not in p.tags
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


class _Balance(HTMLParser):
    VOID = {"br", "img", "hr", "meta", "link", "input", "source", "path",
            "circle", "rect", "line", "polyline", "polygon", "ellipse",
            "use", "stop", "text"}

    def __init__(self):
        super().__init__()
        self.stack, self.bad = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        elif tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass
            self.bad.append(f"crossed </{tag}>")
        else:
            self.bad.append(f"stray </{tag}>")


def test_a_deep_tree_renders_balanced_html():
    """Indentation is an inline margin computed from depth, so a deep tree is
    the case most likely to produce unbalanced markup."""
    ns = [NODE]
    for i in range(2, 9):
        ns.append(node(id=f"D{i}", depends_on=[f"D{i-1}"], load_bearing=False,
                       considered=[{"alternative": "alt", "rejected_because": "why"}],
                       satisfies=["R4"]))
    c = case(decisions=ns)
    out = render(c, validate(c))
    p = _Balance()
    p.feed(out)
    assert p.bad == []
    assert p.stack == []


def test_the_real_case_renders_with_no_warnings():
    """The marketing-collab-server0 investigation with a tree attached — the
    end-to-end shape the workflow is expected to emit."""
    c = case(
        composition="Individually low-scoring; together a chain.",
        timeline=[{"title": "C2 established", "grade": "decisive", "provenance": "19768"}],
        evidence=[{"id": "19768", "what": "Hidden HTTPS Tunnel", "grade": "decisive"}],
        gaps=[{"question": "Initial access?", "outcome": "OUT OF REACH", "detail": "no EDR"}],
        decisions=[
            node(satisfies=["R2"]),
            node(id="D2", question="Is adam_admin this host's own account?",
                 concluded="No; marketing_svc is the probable owner",
                 depends_on=["D1"], satisfies=["R1", "R5"],
                 because=["account_access_history contains only marketing_svc"],
                 rests_on=["get_host_details", "19809"],
                 would_change_if="A Kerberos or NTLM event shows adam_admin authenticating here"),
            node(id="D4", question="Is endpoint telemetry available?",
                 concluded="No; edrs is empty and the operator note agrees",
                 load_bearing=False, satisfies=["R7"],
                 because=["edrs is an empty array",
                          "sensor_name is a network-sensor label, not an EDR indicator"],
                 rests_on=["get_host_details"],
                 would_change_if="The edrs array is populated, or the EDR console shows a check-in"),
        ],
        coverage={"R3": {"status": "done", "detail": "1 of 1"},
                  "R4": {"status": "partial", "detail": "3 attempted, 0 closed"},
                  "R6": {"status": "done"}},
    )
    w = validate(c)
    assert w == [], f"unexpected warnings: {w}"
    out = render(c, w)
    assert "Not reported" not in out          # all seven accounted for
    assert json.dumps(c)                       # the case stays serialisable
