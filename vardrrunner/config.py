"""
Local config + credential resolution.

The backend URL (not a secret) lives in ~/.vardrmap/config.json. The API key is
resolved from, in order: the VARDRMAP_API_KEY env var, the OS keychain, then a
legacy plaintext key in the config file. `vardrrunner login` stores the key in the
keychain when one is available, falling back to the config file otherwise.
"""

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from vardrrunner import keychain, manifests

CONFIG_DIR = Path.home() / ".vardrmap"
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNS_DIR = CONFIG_DIR / "runs"
JOURNAL_FILE = CONFIG_DIR / "runner-journal.sqlite3"
# Managed tool binaries and their install receipt, and the data those tools need
# (nuclei templates). Kept beside the rest of the runner's state so an operator
# can find, audit, or delete every installed tool in one place.
TOOLS_DIR = Path(os.environ.get("VARDRRUNNER_TOOLS_DIR", str(CONFIG_DIR / "tools")))
DATA_DIR = CONFIG_DIR / "data"
# Wordlists the operator supplies, for the tools that fuzz (ffuf). A queued job
# names a wordlist; it never sends a path. The name is resolved against this one
# directory on the machine that runs the scan, so the backend cannot point the
# runner at an arbitrary file to read and replay at a target.
WORDLISTS_DIR = CONFIG_DIR / "wordlists"

# Environment overrides — useful for containers, CI, and headless hosts,
# where a config file is awkward. Env always takes precedence over the file.
ENV_API_URL = "VARDRMAP_URL"
ENV_API_KEY = "VARDRMAP_API_KEY"
ENV_ALLOW_INSECURE = "VARDRRUNNER_ALLOW_INSECURE"

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# What a tool process may inherit: finding binaries, a home and config/cache
# directories, temp space, locale, CA bundles, the operator's proxy, and the
# variables Windows programs need to start and resolve names. Everything else in
# the runner's environment, notably VARDRMAP_API_KEY and identity credentials,
# stays out of tool processes.
_TOOL_ENV_NAMES = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TERM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        # Windows
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "SYSTEMDRIVE",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "USERNAME",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    }
)
_TOOL_ENV_PREFIXES = ("LC_", "XDG_")


class InvalidApiUrl(ValueError):
    """The API URL is malformed or would send the key over plain HTTP."""


class InvalidConfigFile(ValueError):
    """The config file exists but contains invalid JSON."""


def config_dir() -> Path:
    return CONFIG_DIR


def runs_dir() -> Path:
    return RUNS_DIR


def tools_dir() -> Path:
    return TOOLS_DIR


def tool_environment() -> dict[str, str]:
    """The environment every tool subprocess receives: an allowlist of this one.

    Tools read their configuration from files under HOME / XDG directories, so
    nothing a tool needs is lost. VardrGate in particular expands ${VAR}
    references from the environment it inherits; a full copy would let a job
    name the runner's own secrets.
    """
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _TOOL_ENV_NAMES or name.upper().startswith(_TOOL_ENV_PREFIXES)
    }


def data_dir() -> Path:
    return DATA_DIR


def wordlists_dir() -> Path:
    return WORDLISTS_DIR


def journal_file() -> Path:
    return JOURNAL_FILE


def load() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with CONFIG_FILE.open() as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidConfigFile(
            f"Config file contains invalid JSON: {CONFIG_FILE}\n"
            f"  {e}\n"
            f"  Run `vardrrunner login` or delete the file to reset."
        ) from e


def save(data: dict) -> None:
    """Atomically replace config with owner-only permissions.

    This deliberately uses ``write_atomic_text`` rather than the manifest JSON helper:
    config may contain an explicitly accepted plaintext API key, which the manifest
    redactor would replace and make unusable.
    """
    text = json.dumps(data, indent=2) + "\n"
    manifests.write_atomic_text(CONFIG_FILE, text)


def get_api_url() -> str | None:
    """Resolved API URL — the VARDRMAP_URL env var takes precedence over the config file."""
    return os.environ.get(ENV_API_URL) or load().get("api_url")


def get_api_key() -> str | None:
    """Resolved API key — precedence: VARDRMAP_API_KEY env > OS keychain > config file."""
    env = os.environ.get(ENV_API_KEY)
    if env:
        return env
    url = get_api_url()
    if url:
        stored = keychain.get_key(url)
        if stored:
            return stored
    return load().get("api_key")


def credential_source() -> str | None:
    """Where the API key resolves from, without revealing it: 'environment',
    'keychain', 'config file', or None if no key is configured."""
    if os.environ.get(ENV_API_KEY):
        return "environment"
    url = get_api_url()
    if url and keychain.get_key(url):
        return "keychain"
    if load().get("api_key"):
        return "config file"
    return None


def save_url(api_url: str) -> None:
    """Persist only the API URL (no secret) — used when the key lives in the keychain.
    Drops any legacy plaintext key so it can't linger after moving to the keychain."""
    data = load()
    data["api_url"] = api_url
    data.pop("api_key", None)
    save(data)


def clear_file_key() -> bool:
    """Remove a plaintext api_key from the config file. Returns True if one was removed."""
    data = load()
    if "api_key" in data:
        data.pop("api_key")
        save(data)
        return True
    return False


def validate_api_url(url: str) -> str:
    """Return the URL unchanged, or raise InvalidApiUrl.

    Requires https:// so the bearer key is never sent in cleartext. Plain http is
    allowed only for localhost (development), or anywhere when
    VARDRRUNNER_ALLOW_INSECURE=1 is set (not recommended).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InvalidApiUrl(f"Invalid API URL {url!r} — expected https://host[:port]")
    if parsed.scheme == "https":
        return url
    if parsed.hostname in _LOCAL_HOSTS or os.environ.get(ENV_ALLOW_INSECURE) == "1":
        return url
    raise InvalidApiUrl(
        f"Refusing to send your API key over plain HTTP to {parsed.hostname!r}. "
        f"Use https://, or set {ENV_ALLOW_INSECURE}=1 to override (not recommended)."
    )


def require_auth() -> tuple[str, str]:
    """Return validated (api_url, api_key), or raise a helpful Typer error.

    Reads VARDRMAP_URL / VARDRMAP_API_KEY first, then the config file.
    """
    url = get_api_url()
    key = get_api_key()
    if not url or not key:
        import typer

        raise typer.BadParameter(
            "Not set up. Run: vardrrunner init (or set VARDRMAP_URL and VARDRMAP_API_KEY).",
            param_hint="auth",
        )
    try:
        validate_api_url(url)
    except InvalidApiUrl as e:
        import typer

        raise typer.BadParameter(str(e), param_hint="api_url") from e
    return url, key


# --------------------------------------------------------------------------- #
# Approved VardrGate credential references (ADR 0023)
# --------------------------------------------------------------------------- #
# A Gate case arrives from the backend and names where each identity's secret
# comes from: an environment variable (value_env) or an OS keychain account
# (value_keychain). The runner resolves a reference only if the operator approved
# it on this machine for that engagement and target origin. The backend cannot
# add an approval; approvals hold names, never values.
APPROVALS_KEY = "gate_credential_approvals"
CREDENTIAL_SOURCES = ("env", "keychain")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidApproval(ValueError):
    """An approval names an invalid engagement, origin or reference."""


def url_origin(url: str) -> str:
    """Normalized ``scheme://host[:port]`` of an http(s) URL; raise InvalidApproval otherwise."""
    try:
        parsed = urlparse(str(url).strip())
        port = parsed.port
    except ValueError as e:
        raise InvalidApproval(f"invalid URL {url!r}") from e
    if parsed.scheme not in _DEFAULT_PORTS or not parsed.hostname:
        raise InvalidApproval(f"{url!r} is not an absolute http(s) URL")
    if (
        parsed.username is not None
        or parsed.password is not None
        or any(marker in parsed.netloc for marker in ("{{", "}}"))
    ):
        raise InvalidApproval(
            "credential targets require a fixed authority without URL user information"
        )
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[parsed.scheme]:
        return f"{parsed.scheme}://{host}"
    return f"{parsed.scheme}://{host}:{port}"


def _approval(engagement_id: str, origin: str, source: str, name: str) -> dict[str, str]:
    engagement_id = str(engagement_id).strip()
    if not engagement_id or len(engagement_id) > 128 or any(c.isspace() for c in engagement_id):
        raise InvalidApproval("an engagement id is required")
    if source not in CREDENTIAL_SOURCES:
        raise InvalidApproval(f"source must be one of {CREDENTIAL_SOURCES}")
    name = str(name).strip()
    if source == "env" and not _ENV_NAME.fullmatch(name):
        raise InvalidApproval(f"{name!r} is not an environment variable name")
    if source == "keychain" and (not name or len(name) > 200 or any(ord(c) < 32 for c in name)):
        raise InvalidApproval("a keychain account name is required")
    return {
        "engagement_id": engagement_id,
        "origin": url_origin(origin),
        "source": source,
        "name": name,
    }


def credential_approvals() -> list[dict[str, str]]:
    """Every approved reference, in the order it was added."""
    entries = load().get(APPROVALS_KEY) or []
    if not isinstance(entries, list):
        raise InvalidConfigFile(f"{APPROVALS_KEY} in {CONFIG_FILE} must be a list")
    return [e for e in entries if isinstance(e, dict)]


def approve_credential(engagement_id: str, origin: str, source: str, name: str) -> dict[str, str]:
    """Record an approval (idempotent) and return its normalized form."""
    entry = _approval(engagement_id, origin, source, name)
    data = load()
    entries = [e for e in data.get(APPROVALS_KEY) or [] if isinstance(e, dict)]
    if entry not in entries:
        entries.append(entry)
    data[APPROVALS_KEY] = entries
    save(data)
    return entry


def revoke_credential(engagement_id: str, origin: str, source: str, name: str) -> bool:
    """Remove an approval. Returns True if one was removed."""
    entry = _approval(engagement_id, origin, source, name)
    data = load()
    entries = [e for e in data.get(APPROVALS_KEY) or [] if isinstance(e, dict)]
    if entry not in entries:
        return False
    data[APPROVALS_KEY] = [e for e in entries if e != entry]
    save(data)
    return True


def credential_approved(engagement_id: str, origin: str, source: str, name: str) -> bool:
    """True if the operator approved this reference for this engagement and origin."""
    try:
        entry = _approval(engagement_id, origin, source, name)
    except InvalidApproval:
        return False
    return entry in credential_approvals()
