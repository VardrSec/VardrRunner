"""Credential posture: where the API key lives, and how exposed it is.

Answers "how is this machine authenticated, and is that safe?" without ever
touching the secret itself. Nothing here returns, logs or formats a key — the
only facts it reports are *about* the credential, never the credential.

Separated from `config.py` because that module's job is to *resolve* a key for
use, while this one's job is to *describe* the arrangement for an operator or a
health check. `doctor`, `status` and the `credentials` command all read from
here so they cannot drift into disagreeing about the same machine.
"""

from __future__ import annotations

import platform
import stat
from dataclasses import dataclass
from pathlib import Path

from vardrrunner import config, keychain


@dataclass(frozen=True)
class CredentialStatus:
    """A snapshot of credential posture. Contains no secret material."""

    source: str | None
    """Where a key resolves from: 'environment', 'keychain', 'config file', or None."""

    keychain_available: bool
    """Whether an OS keyring backend exists on this machine."""

    plaintext_in_config: bool
    """Whether the config file currently holds a readable API key."""

    config_file: Path
    config_file_exists: bool

    config_mode: str | None
    """Octal permission string, or None on Windows / when the file is absent."""

    world_readable: bool
    """True when a config file holding a plaintext key is group- or other-readable."""

    api_url: str | None

    @property
    def is_authenticated(self) -> bool:
        return self.source is not None

    @property
    def at_rest_encrypted(self) -> bool:
        """True only when the key is held by the OS keychain.

        The environment source is *not* counted as encrypted at rest: it is not
        on disk via the runner, but an env var is readable by any process
        running as this user and often lands in a shell profile or unit file.
        It is a reasonable choice for servers; it is not encryption.
        """
        return self.source == "keychain"


def inspect() -> CredentialStatus:
    """Gather credential posture. Read-only; never raises on a corrupt config."""
    path = config.CONFIG_FILE
    exists = path.exists()

    try:
        data = config.load()
    except config.InvalidConfigFile:
        # A corrupt file cannot be read, so it holds no usable plaintext key as
        # far as anything downstream is concerned. `doctor` reports the
        # corruption separately; this must not raise from a status command.
        data = {}

    plaintext = bool(data.get("api_key"))

    mode_str: str | None = None
    world_readable = False
    if exists and platform.system() != "Windows":
        mode = stat.S_IMODE(path.stat().st_mode)
        mode_str = oct(mode)
        world_readable = plaintext and bool(mode & 0o077)

    return CredentialStatus(
        source=config.credential_source(),
        keychain_available=keychain.available(),
        plaintext_in_config=plaintext,
        config_file=path,
        config_file_exists=exists,
        config_mode=mode_str,
        world_readable=world_readable,
        api_url=config.get_api_url(),
    )


def plaintext_refusal_message(config_file: Path) -> str:
    """Why `login` refused to write a plaintext key, and the three ways forward.

    Kept here rather than inline in the command so the wording is testable and
    identical wherever the refusal is surfaced.
    """
    return (
        "No OS keychain is available on this machine, so the API key could only be "
        "stored in cleartext at\n"
        f"  {config_file}\n\n"
        "Refusing to do that silently. Choose one:\n\n"
        "  1. Use an environment variable instead (recommended for servers and "
        "containers — nothing is written to disk):\n"
        f"       {config.ENV_API_URL}=<your backend url>\n"
        f"       {config.ENV_API_KEY}=<your vmap_ key>\n\n"
        "  2. Install a keyring backend so the key can be encrypted at rest "
        "(e.g. gnome-keyring or kwallet on Linux).\n\n"
        "  3. Accept cleartext storage explicitly:\n"
        "       vardrrunner login vardrmap --allow-plaintext-credentials"
    )
