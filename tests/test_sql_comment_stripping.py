"""SQL comments must be removed before newlines are collapsed.

The failure this prevents is silent, not loud. `run_investigation` normalises a
query with `" ".join(query.split())`, which joins every line into one. A recipe
containing

    WHERE timestamp > NOW() - INTERVAL '7' DAY
      -- Optional: AND LOWER(user_id) LIKE '%x%'
      AND operation = 'New-InboxRule'
    ORDER BY timestamp DESC LIMIT 100

becomes a single line where the comment swallows the remaining predicate, the
ORDER BY *and the LIMIT*. If the API tolerates `--` at all, the query then runs
unfiltered and unbounded and returns wrong results, which is worse than a 400.

Stripping is literal-aware: `--` inside a string is data. Hunting for
SQL-injection patterns in HTTP URIs legitimately searches for it.
"""

import pytest

from vectra_mcp_server.tool.investigation_tools import strip_sql_comments


def normalise(q: str) -> str:
    """What the server does, in order."""
    return " ".join(strip_sql_comments(q).split())


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------

def test_line_comment_does_not_swallow_the_rest_of_the_query():
    q = """SELECT timestamp, user_id
FROM m365.auditexchange._all
WHERE timestamp > NOW() - INTERVAL '7' DAY
  -- Optional: AND LOWER(user_id) LIKE '%adam%'
  AND operation = 'New-InboxRule'
ORDER BY timestamp DESC LIMIT 100"""
    result = normalise(q)
    assert "New-InboxRule" in result, "predicate after the comment was lost"
    assert "ORDER BY" in result
    assert "LIMIT 100" in result, "LIMIT was lost — query would run unbounded"
    assert "Optional" not in result
    assert "--" not in result


def test_order_matters_collapsing_first_would_lose_the_limit():
    """Demonstrates why strip must precede the join, not follow it."""
    q = "SELECT 1\n-- note\nFROM t LIMIT 10"
    wrong = strip_sql_comments(" ".join(q.split()))   # collapse first
    right = normalise(q)                              # strip first
    assert "LIMIT 10" not in wrong
    assert "LIMIT 10" in right


def test_block_comment_removed():
    assert "hidden" not in normalise("SELECT a /* hidden */ FROM t LIMIT 1")
    assert "FROM t LIMIT 1" in normalise("SELECT a /* hidden */ FROM t LIMIT 1")


def test_unterminated_block_comment_does_not_hang():
    assert normalise("SELECT a /* oops FROM t") == "SELECT a"


# ---------------------------------------------------------------------------
# Literal awareness — a naive regex strip would corrupt these
# ---------------------------------------------------------------------------

def test_double_dash_inside_a_literal_is_data():
    q = "SELECT uri FROM network.http._all WHERE uri LIKE '%--%' LIMIT 100"
    assert strip_sql_comments(q) == q


def test_sql_injection_hunt_survives():
    """A real recipe shape: looking for injection markers in URIs."""
    q = ("SELECT timestamp, uri FROM network.http._all "
         "WHERE uri LIKE '%1=1--%' OR uri LIKE '%/*%' LIMIT 100")
    assert strip_sql_comments(q) == q


def test_escaped_quote_inside_literal_is_handled():
    q = "SELECT a FROM t WHERE name = 'O''Brien' -- drop this\nAND x = 1 LIMIT 5"
    result = normalise(q)
    assert "O''Brien" in result
    assert "AND x = 1" in result
    assert "LIMIT 5" in result
    assert "drop this" not in result


def test_comment_marker_immediately_after_a_literal_is_still_a_comment():
    q = "SELECT a FROM t WHERE b = 'x'-- tail\nAND c = 1 LIMIT 2"
    result = normalise(q)
    assert "AND c = 1" in result
    assert "tail" not in result


# ---------------------------------------------------------------------------
# No-ops
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("q", [
    "SELECT a FROM t LIMIT 1",
    "SELECT a FROM t WHERE b = 'no comments here' LIMIT 1",
    "",
])
def test_queries_without_comments_are_unchanged(q):
    assert strip_sql_comments(q) == q
