# ADR 0022: Minimal environment for tool processes

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

Every tool process inherited the runner's full environment. That environment can
hold `VARDRMAP_API_KEY` (the documented credential source for containers and CI),
the identity tokens an operator exports for VardrGate cases, and unrelated shell
secrets. No tool needs them. VardrGate also expands `${VAR}` references in a job
from the environment it inherits, so a case received from the backend could name
any of these variables and have its value sent to the case's target.

## Decision

Every tool subprocess, including the version probes, receives
`config.tool_environment()`: an allowlist of the runner's environment covering
`PATH`, home, user and shell names, temp directories, locale (`LANG`, `LC_*`),
`XDG_*` directories, CA bundle locations, proxy settings and the variables Windows
programs need to start. Names are matched case-insensitively. Nothing else is
passed.

Identity credentials keep reaching VardrGate only through the private job file the
runner writes after resolving each reference locally.

## Consequences

- Tools keep reading their configuration from files under home and the XDG
  directories, which is where ProjectDiscovery tools, Gau and Dalfox look.
- A tool option supplied only through an environment variable outside the allowlist
  no longer reaches the tool. Add such a variable to the allowlist deliberately,
  with a reason, rather than passing the environment through.
- Proxy variables are passed because they direct the operator's own tool traffic;
  a proxy URL with embedded credentials therefore still reaches the tools.
