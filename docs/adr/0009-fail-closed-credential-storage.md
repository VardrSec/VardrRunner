# ADR 0009 — Fail closed on plaintext credential storage

- **Status:** Accepted
- **Date:** 2026-08-17
- **Amends:** [ADR 0004](0004-credential-storage.md)

## Context

ADR 0004 chose the OS keychain as the default credential store, with a
documented fallback: *"On a headless box with no keyring backend, login falls
back to the plaintext config file with a warning, so servers keep working."*

That fallback was the wrong default, for a reason ADR 0004 did not weigh: **the
machines most likely to lack a keyring backend are exactly the machines that run
unattended**. A VPS, a container, a CI runner. The fallback optimised for "the
command succeeds" on precisely the hosts where an unencrypted long-lived
credential matters most, and the only signal was one yellow line in output
nobody reads during provisioning.

It also produced a documentation error that survived several releases. The
README claimed logging in meant "no plaintext key on disk" and `docs/cli.md`
claimed the hidden prompt meant the key was "never written to disk in
cleartext". Neither was true without a keychain. Those were corrected in
v0.30.0, but correcting the *description* of a bad default is not the same as
fixing it.

## Decision

**`login` refuses to write a cleartext key unless the operator says so.**

When no keychain is available — or a keychain is present but the write fails —
`login` verifies the key against the backend, then exits non-zero without
persisting anything, printing three routes forward:

1. `VARDRMAP_API_KEY` / `VARDRMAP_URL` environment variables (nothing written to
   disk at all) — the recommended path for servers and containers
2. install a keyring backend so the key can be encrypted at rest
3. `--allow-plaintext-credentials` to accept cleartext deliberately

A broken-but-present keyring is treated the same as an absent one. Silently
downgrading to cleartext because a keyring write failed would reintroduce the
exact behaviour being removed.

**Posture is inspectable.** `vardrrunner/credentials.py` reports where a key
resolves from, whether it is encrypted at rest, whether the config file holds
cleartext, and the file's permissions — never the key itself. `doctor`, and the
new `vardrrunner credentials` command, both read from it, so they cannot drift
into describing the same machine differently.

**The environment variable is not counted as "encrypted at rest."** It is not
written to disk by the runner, which is a real improvement, but any process
running as that user can read it and it usually ends up in a shell profile or a
systemd unit. Calling that encryption would repeat the overstatement this ADR
exists to correct.

## Consequences

- **Breaking for one path:** `vardrrunner login` on a machine with no keyring
  backend now exits 1 instead of succeeding. Automation that relied on the
  silent fallback must add `--allow-plaintext-credentials` or, better, switch to
  `VARDRMAP_API_KEY`. Every other login path is unchanged.
- Nothing is written before the refusal, so a failed login cannot leave a
  half-configured machine.
- The `--key` flag still exists, and the distinction it actually makes —
  protecting *shell history*, not storage — is now stated wherever it appears.
- `credentials` exits non-zero when unauthenticated, so it composes into
  provisioning scripts like `doctor` does.

## Alternatives considered

- **Keep the fallback, warn louder.** Rejected: v0.30.0 already established that
  the warning was accurate and still ineffective. A warning nobody reads during
  an automated provision is not a control.
- **Encrypt the config file ourselves.** Rejected — that is building a second
  secrets manager, which the roadmap explicitly rules out. Key management is the
  OS keychain's job, and a passphrase the operator must supply on every
  unattended start defeats the purpose.
- **Refuse with no escape hatch.** Rejected: some operators genuinely accept the
  risk on an isolated box, and leaving them no supported route pushes them to
  hand-edit `~/.vardrmap/config.json`, which is worse because it is invisible.
