# Named tenant profiles

Profiles solve two problems with configuring this server through an MCP
client's JSON file: the API secret sits in that file in clear text, and
switching tenants means editing it.

A profile is a named tenant. The non-secret part lives in
`~/.config/vectra-mcp/profiles.yaml`; the credential lives in the OS keychain.

```
profiles.yaml                       OS keychain
─────────────                       ───────────
name: acme                          service  "vectra-mcp"
base_url: https://acme…             username "acme"
credential_ref: vectra-mcp/acme ──▶ password {"client_id": …,
                                              "client_secret": …}
```

Both halves of the OAuth2 pair go into the keychain, so the profile file
contains no credential material at all. It is written `0600`, and the server
**refuses to load it** if a secret has been pasted in by hand — with a message
telling you to rotate the value, because by then it has been sitting in a
plaintext file.

## The commands

```bash
vectra-mcp profile add <name>      # create; prompts for URL, client id, secret
vectra-mcp profile list            # all profiles; * marks the active one
vectra-mcp profile use <name>      # change the active profile
vectra-mcp profile show [<name>]   # details; never prints the secret
vectra-mcp profile test [<name>]   # authenticate and make one read
vectra-mcp profile remove <name>   # delete the profile and its credential
```

`add` accepts `--base-url` and `--client-id` to skip those prompts, and
`--secret-stdin` to read the secret from a pipe for scripted setup.

**There is deliberately no `--client-secret` flag.** A secret passed as a
command-line argument appears in your shell history and in `ps` output for
every user on the machine. This is the one place the tool is intentionally less
convenient.

`add` authenticates before storing anything, in two steps, because the failures
mean different things: a token failure is a bad credential, while a token
success followed by a failed read is a valid credential whose API client lacks
the necessary role.

## Which tenant a run uses

Highest priority first:

| | Source |
|---|---|
| 1 | `--profile <name>` on the command line |
| 2 | `VECTRA_PROFILE` in the environment |
| 3 | the active profile in `profiles.yaml` |
| 4 | `VECTRA_BASE_URL` + `VECTRA_CLIENT_ID` + `VECTRA_CLIENT_SECRET` |
| 5 | a configuration error listing every option above |

Rules 1–3 select a profile. Rule 4 is the original mechanism and is unchanged,
so a deployment that has never heard of profiles behaves exactly as before.

Two behaviours worth knowing:

**A profile outranks environment variables**, and when both are usable the
server logs the winner and the loser by name at startup. That precedence is a
change for anyone upgrading, since environment variables were previously the
only path.

**A named profile that does not exist is an error, not a fallback.** Asking for
one tenant and silently getting another is worse than failing to start, and a
typo is the likeliest cause.

`--profile` and `--config` (multi-tenant YAML) are mutually exclusive and
refused together rather than ordered by precedence.

## Does changing the active profile affect a running server?

**No, by default.** The tenant is resolved once at startup and pinned for the
life of the process, so `profile use` takes effect the next time your MCP
client starts the server. For Claude Desktop that means quitting and reopening
the app.

This is deliberate. Under live switching, a conversation that read one tenant's
detections could write its note to another, and Vectra's audit log records the
API client rather than the analyst or the session — so nothing downstream would
catch it.

To opt in anyway:

```json
"env": { "VECTRA_PROFILE_FOLLOW_ACTIVE": "true" }
```

The active pointer is then re-read whenever the profile file changes, and the
next tool call uses the new tenant. The server logs a warning at startup and
again each time the tenant changes. Precedence still applies, so an instance
pinned with `--profile` or `VECTRA_PROFILE` keeps its tenant no matter where
the active pointer moves — which is what makes it safe to run one server per
tenant against a shared active profile.

A **changed** credential always needs a restart: clients are cached per tenant,
and the cache key is the tenant and client id, not the secret.

## Knowing which tenant you are talking to

The server exposes a read-only `get_active_profile` tool reporting the profile
name, tenant URL, API client id, and where the configuration came from. It
**reports and cannot select** — there is no matching setter, so a model can
never change which tenant it is acting against.

It matters more than it looks. Entity and detection IDs are scoped to a tenant,
and ID ranges overlap between tenants, so an identifier carried over from
another tenant's notes resolves to a *different real entity* rather than
erroring. Confirm the tenant before acting on any ID that did not come from the
current session, and prefer resolving by name.

## Multi-tenant YAML is a different feature

`--config tenants.yaml` registers **every** tenant's tools simultaneously, each
prefixed with the tenant name (`acme_get_detection`, `globex_get_detection`),
plus a `list_tenants` tool. That changes the tool contract, which is why it is
not how profiles work.

A profile **selects one** tenant and registers tools unprefixed, so the tool
names and schemas are identical whichever profile is active — which is what
lets centrally maintained skills and workflows call them without knowing
anything about tenants.

If you want two tenants available at once without prefixes, run two server
entries in your MCP client, each pinned with `VECTRA_PROFILE`. Your client
namespaces them by server name. Be aware that this puts two identically named
tool sets in front of the model, and it chooses between them — name the entries
after the tenants so a wrong choice is visible in the transcript.

`credential_ref` is also accepted on entries in `tenants.yaml`, so a
multi-tenant deployment can move its secrets into the keychain without
adopting a new file format.

## Troubleshooting

**The server will not start, and the log names every configuration option.**
Nothing resolved. Either no profile is active (`vectra-mcp profile list`) or the
environment variables are incomplete — two of the three is a mistake, not a
configuration.

**"profile 'x' has no credential stored at 'vectra-mcp/x'".** The profile file
holds no secrets by design, so this is the expected state after copying
`profiles.yaml` to a new machine. Run `vectra-mcp profile add x` there.

**A keychain prompt you cannot see.** macOS ties keychain access to the
requesting binary, so the first read from a process your MCP client launched may
raise a dialog with no visible window, and the server appears to hang. Run
`vectra-mcp profile test <name>` from a terminal first and choose **Always
Allow**.

**A headless or containerised host with no keychain.** The credential store
fails with an explanation rather than hanging, and environment variables remain
the documented path for Docker.

**`profile use` seemed to do nothing.** Expected — see the pinning section
above. `vectra-mcp profile list` shows what the next start will use;
`get_active_profile` shows what the running server is using. They diverge
exactly when you have switched and not restarted.

## Two changed defaults

Unrelated to profiles, but shipped alongside them:

**`--host` now defaults to `127.0.0.1`** instead of `0.0.0.0`. Neither HTTP
transport authenticates its callers, so the old default published an
unauthenticated proxy for your Vectra credentials to the local network. Binding
wider still works via `--host` or `VECTRA_MCP_HOST`, and now logs a warning
naming the consequence.

**`LOG_FORMAT` now takes effect.** It was previously validated and then
ignored, so `LOG_FORMAT=json` silently produced text. The declared default was
corrected from `json` to `text` to match the behaviour every release has
actually had — otherwise wiring it up would have changed the log format of every
existing deployment on upgrade.
