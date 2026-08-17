# ADR 0003 — Distribution and release process

- **Status:** Accepted
- **Date:** 2026-06-17

## Context
VardrRunner needs a repeatable, trustworthy way to ship. As a security tool that operators
run with their API keys (often unattended on a VPS), the supply chain matters: artifacts
should be verifiable, dependencies audited, and installs should not require cloning the repo.

## Decision
Releases are **tag-driven**. Pushing a `vX.Y.Z` tag triggers `release.yml`, which:

1. Builds an sdist + wheel with `python -m build`.
2. Generates a **CycloneDX SBOM** (`cyclonedx-py environment`).
3. Attests **build provenance** (`actions/attest-build-provenance`) for the artifacts.
4. Publishes a **GitHub Release** with the wheel, sdist, and SBOM attached + auto notes.
5. Optionally publishes to **PyPI via trusted publishing** (OIDC, no stored token) — gated
   behind the `PYPI_PUBLISH` repo variable so the rest of the pipeline runs green before PyPI
   is set up.

The version is single-sourced from `vardrrunner/__init__.py` (read dynamically by
`pyproject.toml`, ADR-adjacent to the v0.18.0 packaging work). CI additionally runs
`pip-audit` and a Linux/Windows/macOS test matrix, since the daemon is OS-sensitive.

Installation paths, in order of preference:
- **pipx** (`pipx install vardrrunner`) once on PyPI — isolated, ideal for a CLI.
- **From a GitHub Release** wheel (works today, before PyPI).
- **From source** (`pip install -e ".[dev]"`) for development.

> **Amendment (2026-08-17, v0.28.0).** PyPI publishing is now live. A pending trusted
> publisher was registered for `VardrSec/VardrRunner` / `release.yml`, `PYPI_PUBLISH` was
> set to `true`, and the v0.28.0 tag published
> [`vardrrunner`](https://pypi.org/project/vardrrunner) — promoting the pending publisher
> to an ordinary one. `pipx install vardrrunner` is now the primary documented path. The
> ordering above stands as written; only its "once on PyPI" precondition is satisfied.
>
> One gap this ADR did not consider: **pipx presumes a Python installation**, which
> operators provisioning a fresh VPS or a clean Windows box may not have. The README now
> documents [uv](https://docs.astral.sh/uv/) — a single static binary that bootstraps its
> own CPython — for that case. A fully standalone executable (PyInstaller/PyApp) remains
> deferred: it would mean a per-OS build matrix, unsigned-binary warnings on Windows, and a
> weaker supply-chain story than the current wheel + SBOM + attestation.

## Consequences
- Every release has a verifiable provenance attestation and an SBOM, satisfying the
  supply-chain bar without manual steps.
- PyPI publishing is decoupled: the maintainer enables it by configuring a trusted publisher
  and setting `PYPI_PUBLISH=true`; nothing breaks in the meantime.
- A bad tag produces a bad release — the version bump + CHANGELOG roll remain a deliberate,
  reviewed PR step before the tag is pushed.

## Alternatives considered
- **Stored PyPI API token** — rejected; trusted publishing (OIDC) avoids a long-lived secret.
- **Manual `twine upload`** — rejected; not reproducible or attestable.
- **Homebrew/Scoop formulae** — deferred until there's PyPI/release demand; the GitHub Release
  wheel covers the gap.
