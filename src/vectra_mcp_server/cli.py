"""``vectra-mcp`` — manage local tenant profiles.

    vectra-mcp profile add acme
    vectra-mcp profile list
    vectra-mcp profile use acme
    vectra-mcp profile show acme
    vectra-mcp profile test acme
    vectra-mcp profile remove acme

Why this is a second console script
-----------------------------------
``vectra-ai-mcp-server`` is what every existing MCP client configuration
launches, with no arguments or with ``--transport stdio``. Hanging subcommands
off that parser risks changing how a bare invocation behaves, and it is the one
command that must not change. ``vectra-mcp`` is also what an operator types
several times a day, so it is short on purpose.

The secret is never a command-line argument
-------------------------------------------
There is deliberately no ``--client-secret`` flag. A secret passed as an
argument lands in shell history, in ``ps`` output for every user on the
machine, and in any shell-tracing or session-recording tool. ``add`` prompts
for it without echo; scripted use pipes it on stdin. This is the one place the
tool is deliberately less convenient than it could be.

Tenant management lives here and not in the MCP tool surface, per the design:
the model must not be able to change which tenant it is acting against.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from typing import Optional, Sequence

from . import __version__
from .config import ServerConfiguration
from .profiles.credentials import (
    Credential,
    CredentialStore,
    CredentialStoreError,
    KeyringCredentialStore,
)
from .profiles.resolver import ConfigurationError
from .profiles.store import (
    Profile,
    ProfileStore,
    ProfileStoreError,
    UnknownProfile,
    validate_profile_name,
)

PROG = "vectra-mcp"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class CliError(Exception):
    """Anything the operator needs told, without a traceback."""


# --------------------------------------------------------------------- output


def out(message: str = "") -> None:
    print(message)


def err(message: str) -> None:
    print(message, file=sys.stderr)


# ------------------------------------------------------------------- plumbing


def _prompt(label: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{label}{suffix}: ").strip()
    except EOFError:
        value = ""
    return value or (default or "")


def _prompt_secret(label: str, *, stdin: bool = False) -> str:
    """Collect a secret without echoing it, or read one from stdin.

    ``stdin`` exists for scripted use — ``echo "$SECRET" | vectra-mcp profile
    add acme --secret-stdin`` — which keeps the value out of argv while still
    being automatable.
    """
    if stdin:
        value = sys.stdin.readline().rstrip("\n")
        if not value:
            raise CliError("no secret was received on stdin")
        return value
    try:
        return getpass.getpass(f"{label}: ")
    except (EOFError, KeyboardInterrupt):
        raise CliError("cancelled") from None


async def _probe(config: ServerConfiguration) -> str:
    """Authenticate and make one cheap read. Returns a one-line result.

    Two steps rather than one, because the failures mean different things: a
    token failure is bad credentials, while a token success followed by a read
    failure is a working credential with insufficient role — and telling an
    operator "check your credentials" when the real problem is an API client
    role is how an afternoon disappears.
    """
    from .vectra_client import VectraClient

    tenant = config.tenants[0]
    client = VectraClient(config.vectra_config_for_tenant(tenant))
    try:
        try:
            await client.token_manager.get_access_token()
        except Exception as exc:
            raise CliError(
                f"authentication failed against {tenant.base_url}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        try:
            response = await client.get_entities(page_size=1)
        except Exception as exc:
            raise CliError(
                f"authenticated successfully, but the first read failed: "
                f"{type(exc).__name__}: {exc}. The credential is valid — check "
                f"the API client's role in the Vectra UI."
            ) from exc

        count = response.get("count")
        seen = "" if count is None else f", {count} entities visible"
        return f"OK — authenticated to {tenant.base_url}{seen}"
    finally:
        await client.close()


def _resolve_for(name: str, store: ProfileStore, credentials: CredentialStore) -> ServerConfiguration:
    """Build a one-tenant configuration for *name* without consulting the environment."""
    from .profiles.resolver import _server_config, _tenant_from_profile

    profile = store.get(name)
    return _server_config(_tenant_from_profile(name, profile, credentials))


# ------------------------------------------------------------------- commands


def cmd_add(args, store: ProfileStore, credentials: CredentialStore) -> int:
    name = validate_profile_name(args.name)

    existing = store.load().profiles.get(name)
    if existing and not args.force:
        raise CliError(
            f"profile {name!r} already exists ({existing.base_url}). "
            f"Re-run with --force to replace it."
        )

    base_url = args.base_url or _prompt("Tenant URL (https://customer.vectra.ai)")
    if not base_url:
        raise CliError("a tenant URL is required")

    client_id = args.client_id or _prompt("API client ID")
    if not client_id:
        raise CliError("a client ID is required")

    client_secret = _prompt_secret("API client secret", stdin=args.secret_stdin)
    if not client_secret:
        raise CliError("a client secret is required")

    try:
        profile = Profile(base_url=base_url, api_version=args.api_version)
        credential = Credential(client_id=client_id, client_secret=client_secret)
    except Exception as exc:
        raise CliError(str(exc)) from exc

    ref = profile.ref_for(name)

    if args.no_test:
        out("Skipping the connection test (--no-test).")
    else:
        # Validate before storing anything. A profile that was never tested is
        # a profile that fails in the middle of an investigation instead.
        probe_config = _server_config_for(profile, credential)
        try:
            out(f"Testing {base_url} ...")
            out("  " + asyncio.run(_probe(probe_config)))
        except CliError as exc:
            err(f"  {exc}")
            if not _confirm("Store the profile anyway?", default=False):
                raise CliError("nothing was stored") from None

    try:
        credentials.set(ref, credential)
    except CredentialStoreError as exc:
        raise CliError(f"could not store the credential: {exc}") from exc

    store.add(name, profile, make_active=args.use)

    out(f"Stored profile {name!r}:")
    out(f"  tenant      {profile.base_url}")
    out(f"  client id   {credential.client_id}")
    out(f"  secret      in the OS keychain as {ref}")
    if store.active_name() == name:
        out(f"  active      yes")
        out("")
        out("Restart your MCP client, or it will keep using the tenant it started with.")
    else:
        out(f"  active      no — 'vectra-mcp profile use {name}' to switch")
    return EXIT_OK


def _server_config_for(profile: Profile, credential: Credential) -> ServerConfiguration:
    """A throwaway configuration for testing a credential not yet stored."""
    from .config import TenantConfig
    from .profiles.resolver import _server_config

    return _server_config(TenantConfig(
        name="default",
        base_url=profile.base_url,
        client_id=credential.client_id,
        client_secret=credential.client_secret,
        api_version=profile.api_version,
        oauth_token_url_override=profile.oauth_token_url_override,
        request_timeout=profile.request_timeout,
        rate_limit_requests=profile.rate_limit_requests,
        rate_limit_period=profile.rate_limit_period,
        cache_ttl=profile.cache_ttl,
    ))


def cmd_list(args, store: ProfileStore, credentials: CredentialStore) -> int:
    file = store.load()
    if not file.profiles:
        out("No profiles configured.")
        out(f"  {PROG} profile add <name>")
        return EXIT_OK

    width = max(len(n) for n in file.profiles)
    out(f"  {'NAME'.ljust(width)}  TENANT")
    for name in sorted(file.profiles):
        marker = "*" if name == file.active else " "
        out(f"{marker} {name.ljust(width)}  {file.profiles[name].base_url}")
    out("")
    if file.active:
        out(f"* = active. Change with '{PROG} profile use <name>'.")
    else:
        # Worth calling out rather than leaving as an absent asterisk: with no
        # active profile the server will refuse to start unless the legacy
        # environment variables are set.
        out(f"No active profile. Set one with '{PROG} profile use <name>'.")
    return EXIT_OK


def cmd_use(args, store: ProfileStore, credentials: CredentialStore) -> int:
    store.set_active(args.name)
    profile = store.get(args.name)
    out(f"Active profile is now {args.name!r} ({profile.base_url}).")
    out("")
    out("A server process that is already running keeps the tenant it started")
    out("with until it resolves again. Restart your MCP client to be certain.")
    return EXIT_OK


def cmd_show(args, store: ProfileStore, credentials: CredentialStore) -> int:
    """Print a profile. This function must never be able to print a secret.

    It reports only whether a credential is *present*, and the non-secret
    client id. There is no code path here that reads ``client_secret``.
    """
    name = args.name or store.active_name()
    if not name:
        raise CliError(f"no profile named and none active. Try '{PROG} profile list'.")

    profile = store.get(name)
    ref = profile.ref_for(name)

    try:
        credential = credentials.get(ref)
        if credential is None:
            secret_state = f"MISSING — run '{PROG} profile add {name}'"
            client_id = "-"
        else:
            secret_state = f"present in the OS keychain ({ref})"
            client_id = credential.client_id
    except CredentialStoreError as exc:
        secret_state = f"unreadable: {exc}"
        client_id = "-"

    out(f"profile      {name}{' (active)' if store.active_name() == name else ''}")
    out(f"tenant       {profile.base_url}")
    out(f"api version  {profile.api_version}")
    out(f"client id    {client_id}")
    out(f"secret       {secret_state}")
    out(f"config file  {store.path}")
    return EXIT_OK


def cmd_test(args, store: ProfileStore, credentials: CredentialStore) -> int:
    name = args.name or store.active_name()
    if not name:
        raise CliError(f"no profile named and none active. Try '{PROG} profile list'.")

    try:
        config = _resolve_for(name, store, credentials)
    except ConfigurationError as exc:
        raise CliError(str(exc)) from exc

    out(f"Testing profile {name!r} ...")
    out("  " + asyncio.run(_probe(config)))
    return EXIT_OK


def cmd_remove(args, store: ProfileStore, credentials: CredentialStore) -> int:
    name = args.name
    profile = store.get(name)

    if not args.yes and not _confirm(
        f"Remove profile {name!r} ({profile.base_url}) and its stored credential?",
        default=False,
    ):
        out("Nothing was removed.")
        return EXIT_OK

    was_active = store.active_name() == name
    ref = profile.ref_for(name)

    store.remove(name)
    try:
        credentials.delete(ref)
    except CredentialStoreError as exc:
        # The profile is already gone; leaving the keychain entry is untidy but
        # harmless, and failing here would strand the operator half-way.
        err(f"Removed the profile, but could not delete {ref}: {exc}")

    out(f"Removed profile {name!r}.")
    if was_active:
        out("")
        out("That was the active profile, and no other profile has been selected.")
        out(f"Choose one with '{PROG} profile use <name>' — until then the server")
        out("will only start if the legacy VECTRA_* environment variables are set.")
    return EXIT_OK


def _confirm(question: str, *, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        # Non-interactive: take the default rather than blocking forever.
        return default
    suffix = "[y/N]" if not default else "[Y/n]"
    answer = _prompt(f"{question} {suffix}").lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Manage local Vectra tenant profiles for the MCP server.",
        epilog=(
            "Credentials are kept in the OS keychain, never in the profile file "
            "and never in an MCP client's configuration."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument(
        "--config-file",
        help="Path to profiles.yaml (default: $VECTRA_MCP_CONFIG_DIR or ~/.config/vectra-mcp)",
    )

    sub = parser.add_subparsers(dest="group", metavar="<group>")
    profile = sub.add_parser("profile", help="add, list, switch and test tenant profiles")
    actions = profile.add_subparsers(dest="action", metavar="<action>")

    p_add = actions.add_parser("add", help="create a profile and store its credential")
    p_add.add_argument("name")
    p_add.add_argument("--base-url", help="tenant URL; prompted for if omitted")
    p_add.add_argument("--client-id", help="API client ID; prompted for if omitted")
    p_add.add_argument("--api-version", default="v3.4")
    p_add.add_argument(
        "--secret-stdin",
        action="store_true",
        help="read the client secret from stdin instead of prompting. There is "
             "no flag to pass the secret directly: argv is visible in ps and "
             "shell history.",
    )
    p_add.add_argument("--no-test", action="store_true", help="skip the connection test")
    p_add.add_argument("--use", action="store_true", help="also make this the active profile")
    p_add.add_argument("--force", action="store_true", help="replace an existing profile")
    p_add.set_defaults(func=cmd_add)

    p_list = actions.add_parser("list", help="list profiles and show which is active")
    p_list.set_defaults(func=cmd_list)

    p_use = actions.add_parser("use", help="make a profile active")
    p_use.add_argument("name")
    p_use.set_defaults(func=cmd_use)

    p_show = actions.add_parser("show", help="show one profile (never prints the secret)")
    p_show.add_argument("name", nargs="?")
    p_show.set_defaults(func=cmd_show)

    p_test = actions.add_parser("test", help="authenticate and make one read against the tenant")
    p_test.add_argument("name", nargs="?")
    p_test.set_defaults(func=cmd_test)

    p_remove = actions.add_parser("remove", help="delete a profile and its credential")
    p_remove.add_argument("name")
    p_remove.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    p_remove.set_defaults(func=cmd_remove)

    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    store: Optional[ProfileStore] = None,
    credentials: Optional[CredentialStore] = None,
) -> int:
    """Entry point. *store* and *credentials* are injectable for tests."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        # `vectra-mcp` or `vectra-mcp profile` with nothing further: show help
        # rather than an obscure AttributeError.
        parser.print_help()
        return EXIT_USAGE

    store = store or ProfileStore(args.config_file)
    credentials = credentials or KeyringCredentialStore()

    try:
        return args.func(args, store, credentials)
    except (CliError, ProfileStoreError, UnknownProfile, ConfigurationError, ValueError) as exc:
        err(f"{PROG}: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        err("")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
