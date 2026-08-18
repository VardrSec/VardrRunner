# ADR 0004 — Credential storage (OS keychain by default)

- **Status:** Accepted
- **Date:** 2026-06-17
- **Amended by:** [ADR 0009](0009-fail-closed-credential-storage.md) — the plaintext fallback described below is no longer silent; `login` now refuses without an explicit opt-in.

## Context
The API key is the runner's only credential and grants access to a user's bug-bounty
programs. Until now the normal path stored it in plaintext at `~/.vardrmap/config.json`
(0600 on Unix). For a tool that aims to feel trustworthy and runs unattended, a long-lived
plaintext key as the *default* is the weakest link — even with restrictive permissions.

## Decision
Store the API key in the **OS keychain** by default, via the `keyring` library
(macOS Keychain, Windows Credential Locker, Linux Secret Service). The backend URL — not a
secret — stays in `config.json` so the key is resolvable without re-prompting.

Resolution order for the key becomes: **`VARDRMAP_API_KEY` env > OS keychain > config file**.

- `vardrrunner login` verifies the key, then stores it in the keychain when one is available
  (writing only the URL to the config file); if no keychain backend exists (e.g. a headless
  server), it falls back to the plaintext config file with a clear warning.
- `vardrrunner logout` removes the key from the keychain and the config file, leaving the URL
  in place (and warns if `VARDRMAP_API_KEY` is still set in the environment).
- `doctor` reports the **credential source** (`environment` / `keychain` / `config file`)
  without ever printing the secret, and only warns about config-file permissions when the
  file actually contains a plaintext key.

The keychain wrapper (`keychain.py`) degrades gracefully: every operation returns
None/False instead of raising when no backend is present, so servers/CI keep working via
env vars.

## Consequences
- Desktop/dev installs keep the key in the OS secret store — no plaintext on disk.
- CI/servers use `VARDRMAP_API_KEY`; headless boxes without a Secret Service fall back to the
  (warned) config file, so nothing breaks.
- One new runtime dependency (`keyring`). It earns its place: native secret storage is not
  something to reimplement.
- Tests mock the keyring backend (including the missing-backend fallback), so the suite never
  touches a real keychain.

## Alternatives considered
- **Encrypt the config file ourselves** — rejected; rolling our own at-rest crypto + key
  management is worse than the OS-provided secret store.
- **Keep plaintext, rely on file perms** — rejected as the default; it's the status quo this
  ADR exists to improve (still supported as the no-keychain fallback).
