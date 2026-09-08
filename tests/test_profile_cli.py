"""The profile CLI.

The load-bearing test in here is `test_show_can_never_print_the_secret`. The
brief requires that credentials cannot appear in `profile show` output, and the
way that requirement gets broken later is someone adding a helpful line to the
display function. So the test asserts on output rather than on intent.

`_probe` is stubbed throughout: `profile add` and `profile test` make real
network calls by design, and a test suite that reaches a customer tenant is not
a test suite.
"""

from __future__ import annotations

import pytest

from vectra_mcp_server import cli
from vectra_mcp_server.profiles.credentials import Credential
from vectra_mcp_server.profiles.store import Profile, ProfileStore

SECRET = "sup3r-s3cret-v4lue"
CRED = Credential(client_id="an-id", client_secret=SECRET)


@pytest.fixture
def store(tmp_path):
    return ProfileStore(tmp_path / "profiles.yaml")


@pytest.fixture
def run(store, credentials, capsys):
    """Invoke the CLI against a temp store and an in-memory keychain."""

    def _run(*argv):
        code = cli.main(list(argv), store=store, credentials=credentials)
        captured = capsys.readouterr()
        return code, captured.out + captured.err

    return _run


@pytest.fixture
def no_network(monkeypatch):
    """Make the connection probe succeed without touching a network."""
    monkeypatch.setattr(cli, "_probe", lambda config: _ok(config))
    return monkeypatch


async def _ok(config):
    return f"OK — authenticated to {config.tenants[0].base_url}"


@pytest.fixture
def seeded(store, credentials):
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    store.add("globex", Profile(base_url="https://globex.vectra.ai"))
    store.set_active("acme")
    credentials.set("vectra-mcp/acme", CRED)
    credentials.set("vectra-mcp/globex", Credential(client_id="g-id", client_secret="g-secret"))
    return store


# ----------------------------------------------------------------- the parser

def test_bare_invocation_prints_help_rather_than_crashing(run):
    code, output = run()
    assert code == cli.EXIT_USAGE
    assert "profile" in output


def test_profile_with_no_action_prints_help(run):
    code, output = run("profile")
    assert code == cli.EXIT_USAGE


def test_there_is_no_flag_to_pass_a_secret_on_the_command_line():
    """argv is visible in ps output and shell history.

    Asserted against the parser rather than trusted to review: a helpful
    `--client-secret` is exactly the kind of thing that gets added later.
    """
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["profile", "add", "acme", "--client-secret", SECRET])


def test_the_secret_stdin_flag_documents_why_it_exists():
    parser = cli.build_parser()
    args = parser.parse_args(["profile", "add", "acme", "--secret-stdin"])
    assert args.secret_stdin is True


# -------------------------------------------------------------------- listing

def test_list_with_nothing_configured_says_how_to_start(run):
    code, output = run("profile", "list")
    assert code == cli.EXIT_OK
    assert "profile add" in output


def test_list_marks_the_active_profile(run, seeded):
    code, output = run("profile", "list")
    assert code == cli.EXIT_OK
    active_line = [l for l in output.splitlines() if "acme" in l][0]
    assert active_line.startswith("*")
    other_line = [l for l in output.splitlines() if "globex" in l][0]
    assert not other_line.startswith("*")


def test_list_shows_every_tenant_url(run, seeded):
    _, output = run("profile", "list")
    assert "https://acme.vectra.ai" in output
    assert "https://globex.vectra.ai" in output


def test_list_warns_when_nothing_is_active(run, store, seeded):
    store.remove("acme")
    _, output = run("profile", "list")
    assert "No active profile" in output


# --------------------------------------------------------------------- switch

def test_use_switches_the_active_profile(run, seeded, store):
    code, output = run("profile", "use", "globex")
    assert code == cli.EXIT_OK
    assert store.active_name() == "globex"


def test_use_says_a_running_server_keeps_its_tenant(run, seeded):
    """The single most likely support question, answered in the output."""
    _, output = run("profile", "use", "globex")
    assert "already running" in output.lower() or "restart" in output.lower()


def test_use_with_an_unknown_name_fails_and_lists_the_known_ones(run, seeded, store):
    code, output = run("profile", "use", "initech")
    assert code == cli.EXIT_ERROR
    assert "acme" in output and "globex" in output
    assert store.active_name() == "acme", "a failed switch must not change anything"


# ----------------------------------------------------------------------- show

def test_show_can_never_print_the_secret(run, seeded):
    code, output = run("profile", "show", "acme")
    assert code == cli.EXIT_OK
    assert SECRET not in output


def test_show_reports_the_secret_as_present_without_revealing_it(run, seeded):
    _, output = run("profile", "show", "acme")
    assert "keychain" in output
    assert "vectra-mcp/acme" in output


def test_show_displays_the_client_id_for_attribution(run, seeded):
    _, output = run("profile", "show", "acme")
    assert "an-id" in output


def test_show_defaults_to_the_active_profile(run, seeded):
    _, output = run("profile", "show")
    assert "acme" in output


def test_show_reports_a_missing_credential_as_a_fixable_state(run, store):
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    code, output = run("profile", "show", "acme")
    assert code == cli.EXIT_OK, "a missing credential is a state to report, not a crash"
    assert "MISSING" in output
    assert "profile add acme" in output


def test_show_with_no_argument_and_nothing_active_explains_itself(run, store):
    code, output = run("profile", "show")
    assert code == cli.EXIT_ERROR
    assert "profile list" in output


# ------------------------------------------------------------------------ add

def test_add_stores_the_profile_and_the_credential(run, store, credentials, no_network, monkeypatch):
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")
    code, output = run(
        "profile", "add", "acme",
        "--base-url", "https://acme.vectra.ai",
        "--client-id", "an-id",
        "--secret-stdin",
    )
    assert code == cli.EXIT_OK, output
    assert store.get("acme").base_url == "https://acme.vectra.ai"
    assert credentials.get("vectra-mcp/acme") == CRED


def test_add_does_not_echo_the_secret(run, store, credentials, no_network, monkeypatch):
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")
    _, output = run(
        "profile", "add", "acme",
        "--base-url", "https://acme.vectra.ai", "--client-id", "an-id", "--secret-stdin",
    )
    assert SECRET not in output


def test_add_makes_the_first_profile_active(run, store, no_network, monkeypatch):
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")
    run("profile", "add", "acme", "--base-url", "https://acme.vectra.ai",
        "--client-id", "an-id", "--secret-stdin")
    assert store.active_name() == "acme"


def test_add_refuses_to_overwrite_without_force(run, seeded, no_network, monkeypatch):
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")
    code, output = run("profile", "add", "acme", "--base-url", "https://x.vectra.ai",
                       "--client-id", "id", "--secret-stdin")
    assert code == cli.EXIT_ERROR
    assert "--force" in output


def test_add_rejects_an_invalid_profile_name(run, no_network):
    code, output = run("profile", "add", "has/slash", "--base-url", "https://x.vectra.ai",
                       "--client-id", "id", "--no-test", "--secret-stdin")
    assert code == cli.EXIT_ERROR


def test_add_requires_a_secret(run, no_network, monkeypatch):
    monkeypatch.setattr("sys.stdin.readline", lambda: "\n")
    code, output = run("profile", "add", "acme", "--base-url", "https://x.vectra.ai",
                       "--client-id", "id", "--secret-stdin")
    assert code == cli.EXIT_ERROR


def test_add_stores_nothing_when_the_probe_fails_and_the_operator_declines(
    run, store, credentials, monkeypatch
):
    """A failed test must not leave a half-made profile behind."""
    async def failing(config):
        raise cli.CliError("authentication failed against https://x.vectra.ai: 401")

    monkeypatch.setattr(cli, "_probe", failing)
    monkeypatch.setattr(cli, "_confirm", lambda *a, **k: False)
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")

    code, output = run("profile", "add", "acme", "--base-url", "https://x.vectra.ai",
                       "--client-id", "id", "--secret-stdin")
    assert code == cli.EXIT_ERROR
    assert store.names() == []
    assert credentials.entries == {}


def test_add_can_store_despite_a_failed_probe_if_confirmed(run, store, credentials, monkeypatch):
    async def failing(config):
        raise cli.CliError("tenant unreachable")

    monkeypatch.setattr(cli, "_probe", failing)
    monkeypatch.setattr(cli, "_confirm", lambda *a, **k: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")

    code, _ = run("profile", "add", "acme", "--base-url", "https://x.vectra.ai",
                  "--client-id", "id", "--secret-stdin")
    assert code == cli.EXIT_OK
    assert store.names() == ["acme"]


def test_add_with_no_test_skips_the_probe(run, store, monkeypatch):
    def must_not_run(config):
        raise AssertionError("--no-test still ran the probe")

    monkeypatch.setattr(cli, "_probe", must_not_run)
    monkeypatch.setattr("sys.stdin.readline", lambda: SECRET + "\n")
    code, _ = run("profile", "add", "acme", "--base-url", "https://x.vectra.ai",
                  "--client-id", "id", "--secret-stdin", "--no-test")
    assert code == cli.EXIT_OK
    assert store.names() == ["acme"]


# ----------------------------------------------------------------------- test

def test_test_uses_the_active_profile_by_default(run, seeded, no_network):
    code, output = run("profile", "test")
    assert code == cli.EXIT_OK
    assert "acme.vectra.ai" in output


def test_test_reports_a_failure_as_an_error_code(run, seeded, monkeypatch):
    async def failing(config):
        raise cli.CliError("authentication failed: 401")

    monkeypatch.setattr(cli, "_probe", failing)
    code, output = run("profile", "test", "acme")
    assert code == cli.EXIT_ERROR
    assert "401" in output


def test_test_on_a_profile_with_no_credential_explains_the_fix(run, store):
    store.add("acme", Profile(base_url="https://acme.vectra.ai"))
    code, output = run("profile", "test", "acme")
    assert code == cli.EXIT_ERROR
    assert "profile add acme" in output


# --------------------------------------------------------------------- remove

def test_remove_deletes_the_profile_and_the_credential(run, seeded, store, credentials):
    code, output = run("profile", "remove", "globex", "--yes")
    assert code == cli.EXIT_OK
    assert store.names() == ["acme"]
    assert credentials.get("vectra-mcp/globex") is None


def test_remove_without_yes_does_nothing_when_declined(run, seeded, store, monkeypatch):
    monkeypatch.setattr(cli, "_confirm", lambda *a, **k: False)
    code, output = run("profile", "remove", "globex")
    assert code == cli.EXIT_OK
    assert "globex" in store.names()


def test_removing_the_active_profile_warns_that_nothing_is_selected(run, seeded, store):
    code, output = run("profile", "remove", "acme", "--yes")
    assert code == cli.EXIT_OK
    assert store.active_name() is None
    assert "profile use" in output


def test_remove_of_an_unknown_profile_is_an_error(run, seeded):
    code, output = run("profile", "remove", "initech", "--yes")
    assert code == cli.EXIT_ERROR


# --------------------------------------------------------------- error shape

def test_errors_are_reported_without_a_traceback(run, seeded):
    code, output = run("profile", "use", "nope")
    assert code == cli.EXIT_ERROR
    assert "Traceback" not in output
    assert output.startswith(cli.PROG + ":") or f"\n{cli.PROG}:" in output
