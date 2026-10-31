# ADR 0024: Nmap outside the supported toolkit; naabu for port discovery

- **Status:** Accepted
- **Date:** 2026-10-31

## Context

The `toolkit` container image installed Debian's `nmap`, and Runner has dedicated Nmap
execution and XML parsing. Nmap's license terms (NPSL 0.95, which treats software designed
specifically to execute Nmap and parse its results as a derivative work and is not
GPL-compatible) are unresolved for the VardrSec Community Alpha distribution. Naabu is already
shipped, pinned and verified, and covers port discovery; HTTPx identifies web services.

## Decision

- The container image does not install Nmap, and no installer, manifest or default downloads
  it. libpcap stays for naabu.
- The Nmap integration (`run nmap`, the `nmap` job type, `NmapHandler`, the allowlist entry)
  stays in the code but is **off unless the operator sets `VARDRRUNNER_ENABLE_NMAP=1`** and
  supplies their own Nmap, under its own license terms. Only the literal value `1` enables
  it. Disabled, it is absent from `ALLOWED_TOOLS` and `handlers.REGISTRY`, so `doctor`,
  `tools` and `status` do not list it, and a queued `nmap` job fails as unsupported with a
  message that names naabu.
- Methodology checklists suggest naabu rather than nmap. Naabu is run with `-list`,
  `-top-ports`, `-json`, `-o` and `-silent` only; it never enables its Nmap hooks.
- All other controls are unchanged: scope and operator approval, credential-reference
  approval, the minimal tool environment and the job lifecycle.

## Consequences

- Supported workflows need no Nmap. The Nmap code remains in the repository; whether keeping
  it is itself acceptable under Nmap's terms is a licensing question, not an engineering one,
  and the isolation here (off by default, never packaged) does not answer it.
- An operator who relied on `nmap` must set the variable and keep their own installation.
- The existing suite opts in so the optional path stays covered; `tests/test_nmap_optional.py`
  checks the default in fresh interpreters.
