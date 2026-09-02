"""The credential redaction filter has to actually redact.

A redaction filter that fails silently is worse than none: it buys confidence
without providing protection. Two real defects motivated these tests.

1. The filter rewrote ``record.msg`` only. Under %-style logging the secret
   lives in ``record.args``, so ``logger.info("client_secret=%s", secret)``
   passed through in the clear — and because the rewrite deleted the ``%s``
   from the format string, emitting the record then raised "not all arguments
   converted during string formatting".

2. The patterns had no boundaries. ``key=`` matched inside ``monkey=1`` and
   ``secret=`` matched inside ``client_secret=``, so unrelated lines were
   corrupted while the credential was only half hidden.

Both are the same class of bug as an unanchored ``rx="7"`` matching
``stroke-width``: a regex trusted without being made to prove itself.
"""

import logging

import pytest

from vectra_mcp_server.utils.logging import REDACTED, SensitiveDataFilter, redact

SECRET = "sup3r-s3cret-v4lue"


def record(msg, args=()):
    """A log record as logging itself would build one."""
    return logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=None,
    )


def rendered(msg, args=()):
    """Push a record through the filter and return what would be emitted."""
    rec = record(msg, args)
    assert SensitiveDataFilter().filter(rec) is True, "filter must never drop records"
    return rec.getMessage()


# ---------------------------------------------------------------- the regression

@pytest.mark.parametrize("template", [
    "client_secret=%s",
    "using client_secret=%s for auth",
    '{"client_secret": "%s"}',
    "password=%s",
    "access_token=%s",
])
def test_secrets_passed_as_args_are_redacted(template):
    """The defect that mattered: the secret was in args, not in msg."""
    out = rendered(template, (SECRET,))
    assert SECRET not in out, f"credential survived redaction: {out!r}"
    assert REDACTED in out


def test_a_record_with_args_still_renders_after_filtering():
    """The old filter deleted the %s and left the args, so getMessage() raised."""
    rec = record("client_secret=%s", (SECRET,))
    SensitiveDataFilter().filter(rec)
    rec.getMessage()  # must not raise
    assert rec.args == (), "args must be cleared once folded into the message"


def test_a_broken_format_string_does_not_lose_the_record():
    """Too few args is a bug in the caller; it must not silence the log line."""
    rec = record("two placeholders %s %s", (SECRET,))
    assert SensitiveDataFilter().filter(rec) is True


# ---------------------------------------------------------------- boundaries

def test_unrelated_words_containing_key_are_left_alone():
    assert redact("monkey=1 turkey=2 donkey=3") == "monkey=1 turkey=2 donkey=3"


def test_client_secret_is_redacted_whole_not_half():
    out = redact(f"client_secret={SECRET}")
    assert out == f"client_secret={REDACTED}"
    assert "client_" not in out.replace("client_secret", ""), out


def test_client_id_is_preserved_deliberately():
    """client_id is the username half of the pair, and the only attribution in
    a log line. Redacting it would protect nothing and destroy the audit value.
    """
    assert redact("client_id=abc123") == "client_id=abc123"


# ---------------------------------------------------------------- forms

@pytest.mark.parametrize("line", [
    f"token={SECRET}",
    f"token: {SECRET}",
    f'"token": "{SECRET}"',
    f"secret={SECRET}",
    f"api_key={SECRET}",
    f"apikey={SECRET}",
    f"Authorization: Bearer {SECRET}",
    f"Authorization: Basic {SECRET}",
    f"authorization={SECRET}",
])
def test_every_credential_form_we_emit_is_covered(line):
    assert SECRET not in redact(line), line


def test_bearer_token_without_a_header_name_is_still_caught():
    assert SECRET not in redact(f"retrying with Bearer {SECRET}")


# ---------------------------------------------------------------- shape

def test_redact_is_a_no_op_on_clean_text():
    clean = "Making GET request to https://x.vectra.ai/api/v3.4/detections"
    assert redact(clean) == clean


def test_redact_handles_empty_and_none_safely():
    assert redact("") == ""
    assert redact(None) is None


def test_filter_leaves_a_clean_record_untouched():
    rec = record("no credentials here")
    SensitiveDataFilter().filter(rec)
    assert rec.msg == "no credentials here"
