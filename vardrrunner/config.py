"""
Local config + credential resolution.

The backend URL (not a secret) lives in ~/.vardrmap/config.json. The API key is
resolved from, in order: the VARDRMAP_API_KEY env var, the OS keychain, then a
legacy plaintext key in the config file. `vardrrunner login` stores the key in the
keychain when one is available, falling back to the config file otherwise.
"""

import json
import os
import stat
from pathlib import Path
from urllib.parse import urlparse

from vardrrunner import keychain

CONFIG_DIR = Path.home() / ".vardrmap"
CONFIG_FILE = CONFIG_DIR / "config.json"
RUNS_DIR = CONFIG_DIR / "runs"
JOURNAL_FILE = CONFIG_DIR / "runner-journal.sqlite3"

# Environment overrides — useful for containers, CI, and headless VPS daemons,
# where a config file is awkward. Env always takes precedence over the file.
ENV_API_URL = "VARDRMAP_URL"
ENV_API_KEY = "VARDRMAP_API_KEY"
ENV_ALLOW_INSECURE = "VARDRRUNNER_ALLOW_INSECURE"

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class InvalidApiUrl(ValueError):
    """The API URL is malformed or would send the key over plain HTTP."""


class InvalidConfigFile(ValueError):
    """The config file exists but contains invalid JSON."""


def config_dir() -> Path:
    return CONFIG_DIR


def runs_dir() -> Path:
    return RUNS_DIR


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
            f"  Run `vardrrunner login vardrmap` or delete the file to reset."
        ) from e


def save(data: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_FILE.open("w") as f:
        json.dump(data, f, indent=2)
    # Best-effort: restrict permissions on Unix so the file isn't world-readable.
    # On Windows this has no effect but raises no error.
    try:
        CONFIG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


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
            "Not logged in. Run: vardrrunner login vardrmap "
            "(or set VARDRMAP_URL and VARDRMAP_API_KEY).",
            param_hint="auth",
        )
    try:
        validate_api_url(url)
    except InvalidApiUrl as e:
        import typer

        raise typer.BadParameter(str(e), param_hint="api_url") from e
    return url, key
