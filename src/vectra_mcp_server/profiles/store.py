"""The profile file: named tenants, and which one is active.

Shape on disk
-------------
``~/.config/vectra-mcp/profiles.yaml`` (override with ``VECTRA_MCP_CONFIG_DIR``)::

    version: 1
    active: acme
    profiles:
      acme:
        base_url: https://acme.vectra.ai
        api_version: v3.4
        credential_ref: vectra-mcp/acme

YAML rather than TOML or JSON because the repo already depends on ``pyyaml``
and already ships a YAML config (``tenants.yaml``) — a second serialisation
format would be a new dependency and a second thing to explain.

This file must never hold a secret
----------------------------------
That is the point of the whole exercise, so it is enforced rather than
documented: the model forbids unknown keys, and a hand-edited
``client_secret:`` is refused at load with a message pointing at
``profile add``. A silent ignore would leave the secret sitting in the file
while the operator believed it was in the keychain — worse than either
alternative.

Profiles vs. multi-tenant mode
------------------------------
These are different features and stay separate. ``tenants.yaml`` registers
*every* tenant's tools simultaneously with name prefixes, which changes the MCP
tool contract. A profile *selects one* tenant and registers unprefixed, so the
39 tools and their schemas are identical whichever profile is active — which is
what lets centrally maintained Skills call them without knowing about tenants.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..config import _validate_api_version, _validate_base_url

#: Current on-disk schema version. Present from the first release so a future
#: format change has something to branch on rather than having to guess.
FILE_VERSION = 1

CONFIG_DIR_ENV = "VECTRA_MCP_CONFIG_DIR"
DEFAULT_CONFIG_DIR = Path("~/.config/vectra-mcp")
FILE_NAME = "profiles.yaml"

#: Profile names are keychain usernames and YAML keys, so: no slashes (they
#: would split a credential_ref), no leading punctuation, no spaces. Wider than
#: the multi-tenant tenant-name rule because a profile name is never used as an
#: MCP tool prefix — it does not have to be a valid identifier fragment.
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,39}$")

#: Keys that would mean a secret had been written into the file by hand.
_CREDENTIAL_KEYS = frozenset({
    "client_secret", "secret", "password", "token", "api_token", "api_key",
})


class ProfileStoreError(Exception):
    """The profile file could not be read, written, or made sense of."""


class UnknownProfile(ProfileStoreError):
    """A profile was named that does not exist."""


def validate_profile_name(name: str) -> str:
    if not name or not _NAME_RE.match(name):
        raise ValueError(
            f"invalid profile name {name!r}: use letters, digits, '.', '_' or "
            f"'-', starting with a letter or digit, up to 40 characters"
        )
    return name


class Profile(BaseModel):
    """One named tenant. Non-secret configuration only."""

    # extra="forbid" is doing real work: it is what turns a hand-added
    # `client_secret:` into a load error instead of a field nobody reads.
    model_config = ConfigDict(extra="forbid")

    base_url: str
    api_version: str = "v3.4"
    credential_ref: Optional[str] = Field(
        default=None,
        description="Pointer into the OS keychain, e.g. 'vectra-mcp/acme'. "
                    "Defaults to 'vectra-mcp/<profile name>' when unset.",
    )
    oauth_token_url_override: Optional[str] = None
    request_timeout: int = 30
    rate_limit_requests: int = 100
    rate_limit_period: int = 60
    cache_ttl: int = 300

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, v: str) -> str:
        return _validate_base_url(v)

    @field_validator("api_version")
    @classmethod
    def _api_version(cls, v: str) -> str:
        return _validate_api_version(v)

    def ref_for(self, name: str) -> str:
        """The keychain reference for this profile."""
        return self.credential_ref or f"vectra-mcp/{name}"


class ProfileFile(BaseModel):
    """The whole file."""

    model_config = ConfigDict(extra="forbid")

    version: int = FILE_VERSION
    active: Optional[str] = None
    profiles: Dict[str, Profile] = Field(default_factory=dict)

    @field_validator("profiles")
    @classmethod
    def _names(cls, v: Dict[str, Profile]) -> Dict[str, Profile]:
        for name in v:
            validate_profile_name(name)
        return v


def config_dir() -> Path:
    """Where the profile file lives."""
    override = os.environ.get(CONFIG_DIR_ENV)
    base = Path(override) if override else DEFAULT_CONFIG_DIR
    return base.expanduser()


def config_path() -> Path:
    return config_dir() / FILE_NAME


class ProfileStore:
    """Read and write the profile file.

    Reads are cheap and uncached on purpose: the resolver may consult the
    active pointer on every tool call, and caching here would be the reason
    ``profile use`` appeared to do nothing.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else config_path()

    # ------------------------------------------------------------------ read

    def load(self) -> ProfileFile:
        """Return the file's contents, or an empty file if it does not exist.

        A missing file is not an error — it is the state every new install is
        in, and the env-var path has to keep working without one.
        """
        if not self.path.exists():
            return ProfileFile()

        try:
            raw = yaml.safe_load(self.path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ProfileStoreError(f"{self.path} is not valid YAML: {exc}") from exc
        except OSError as exc:
            raise ProfileStoreError(f"could not read {self.path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ProfileStoreError(
                f"{self.path} must contain a mapping at the top level"
            )

        self._reject_credentials_in_file(raw)

        try:
            return ProfileFile(**raw)
        except Exception as exc:
            raise ProfileStoreError(f"{self.path} is not a valid profile file: {exc}") from exc

    def _reject_credentials_in_file(self, raw: dict) -> None:
        """Refuse to load a file someone has pasted a secret into.

        ``extra="forbid"`` would already reject it, but with a pydantic message
        about an unexpected field. This one says what to do instead, and says
        it before the value has been through a validator that might quote it.
        """
        for name, body in (raw.get("profiles") or {}).items():
            if not isinstance(body, dict):
                continue
            found = sorted(_CREDENTIAL_KEYS.intersection(body))
            if found:
                raise ProfileStoreError(
                    f"profile {name!r} in {self.path} contains {', '.join(found)}. "
                    f"Credentials belong in the OS keychain, not this file — that "
                    f"is the reason it exists. Remove the key and run "
                    f"'vectra-mcp profile add {name}' to store it properly. "
                    f"Treat the value already in the file as exposed and rotate it."
                )

    def get(self, name: str) -> Profile:
        file = self.load()
        if name not in file.profiles:
            raise UnknownProfile(self._unknown_message(name, file))
        return file.profiles[name]

    def names(self) -> List[str]:
        return sorted(self.load().profiles)

    def active_name(self) -> Optional[str]:
        return self.load().active

    def _unknown_message(self, name: str, file: ProfileFile) -> str:
        known = sorted(file.profiles)
        if not known:
            return (
                f"no profile named {name!r}, and none are configured. "
                f"Run 'vectra-mcp profile add {name}' to create one."
            )
        return (
            f"no profile named {name!r}. Configured profiles: "
            f"{', '.join(known)}."
        )

    # ----------------------------------------------------------------- write

    def save(self, file: ProfileFile) -> None:
        """Write the file atomically, owner-readable only.

        Atomic because the resolver may read this file while the CLI writes it:
        a half-written YAML document would make every tool call fail until the
        write finished. Written 0600 because even without secrets it names the
        customer tenants this operator works with.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, stat.S_IRWXU)
        except OSError:
            # Best effort: an unusual umask or a shared directory should not
            # stop the write, and the file mode below is the load-bearing part.
            pass

        payload = yaml.safe_dump(
            file.model_dump(exclude_none=True, mode="json"),
            sort_keys=False,
            default_flow_style=False,
        )

        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".profiles-", suffix=".tmp")
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, self.path)

    def add(self, name: str, profile: Profile, *, make_active: bool = False) -> None:
        validate_profile_name(name)
        file = self.load()
        file.profiles[name] = profile
        if make_active or file.active is None:
            # The first profile becomes active automatically: an operator who
            # adds exactly one and then finds nothing selected has been given a
            # puzzle rather than a tool.
            file.active = name
        self.save(file)

    def remove(self, name: str) -> Profile:
        file = self.load()
        if name not in file.profiles:
            raise UnknownProfile(self._unknown_message(name, file))
        removed = file.profiles.pop(name)
        if file.active == name:
            # Never silently fall through to a different tenant. No active
            # profile is a clear error at resolve time; the wrong active
            # profile is a silent cross-tenant action.
            file.active = None
        self.save(file)
        return removed

    def set_active(self, name: str) -> None:
        file = self.load()
        if name not in file.profiles:
            raise UnknownProfile(self._unknown_message(name, file))
        file.active = name
        self.save(file)
