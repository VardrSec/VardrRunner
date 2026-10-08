# ADR 0014 — Pinned, verified tool installs in one managed directory

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

VardrRunner executes third-party binaries (httpx, nuclei, subfinder, dnsx, naabu,
nmap, VardrGate) but never installed them. Operators installed each one by hand,
from wherever they found it, into wherever it landed: `~/go/bin`, a package
manager, a downloads folder. The runner then ran whatever `PATH` resolved first.

That left three problems:

1. **No integrity.** Nothing checked that the binary on `PATH` was the one its
   author published. A tampered or corrupted tool would run with the operator's
   privileges, against authorized targets, with nobody told.
2. **No version control.** Two runners could execute different builds of the same
   tool and produce different results with no record of which ran.
3. **Scattered state.** Tools lived in several directories an operator might not
   know about, which made them hard to audit or remove.

The tools are about to multiply (katana, gau, ffuf, dalfox), so the cost of all
three grows with every addition.

## Decision

VardrRunner installs tools itself, from a pinned manifest, into one directory.

- **Pinned manifest.** `vardrrunner/tool_manifest.json` ships inside the package
  and lists, per tool, an exact version and, per platform (Windows, Linux and
  macOS on amd64/arm64), a release archive URL and its SHA-256.
- **The hash comes from the package, not the download site.** Verifying an
  archive against a checksums file fetched from the same release page would let
  anyone who can modify that page change both. Pinning the hash in the package
  means a substituted binary also requires compromising VardrRunner's own
  release, which is built and published with provenance attestation (ADR 0003).
- **One directory.** Binaries and their receipt live in `~/.vardrmap/tools`;
  tool data in `~/.vardrmap/data`; both beside the rest of the runner's state.
  `tools purge` removes everything.
- **Fail-closed install.** Download over HTTPS with a size cap → verify the
  archive's SHA-256 → extract only the one expected file, bounded in size, to a
  path VardrRunner chooses → run the binary's version flag and require the pinned
  version → move it into place in a single rename → write the receipt. Any failed
  step installs nothing and leaves no partial file.
- **Receipt and re-verification.** `tools.lock.json` records each binary's
  SHA-256. The runner re-hashes a managed binary the first time it resolves it in
  a process, and again if its size or modification time changes, and **refuses to
  execute one that no longer matches**. `doctor` and `tools verify` report the
  same.
- **PATH fallback, flagged.** A tool with no managed install still resolves from
  `PATH`, so existing setups keep working; `doctor` and `tools list` mark such
  copies *unverified*. A managed install that fails verification never falls
  back to `PATH`.
- **Not everything is managed.** nmap ships as an OS installer or package rather
  than one binary, and naabu needs libpcap/Npcap; VardrRunner does not install
  system software. `doctor` names the OS install step instead.
- **Pins change only through review.** `scripts/pin_tools.py` downloads every
  platform archive for a requested version, hashes it locally, requires that
  hash to match the tool's own published checksums file, and confirms the
  archive contains the expected binary before writing a pin. A weekly workflow
  (`tool-pins.yml`) re-downloads every pinned archive and fails on any change:
  a replaced upstream release is something to investigate, never something to
  re-pin automatically.

## Consequences

- Operators get one command (`vardrrunner tools install --all`) instead of
  per-tool installation, and one folder to audit or delete.
- Every runner on a given VardrRunner version executes byte-identical tool
  builds, recorded in the receipt.
- New tools now cost a manifest entry and a pin-script source, in addition to
  the handler (ADR 0002).
- Tool upgrades ship with VardrRunner releases rather than whenever upstream
  publishes. That is deliberate, but it means a pinned version can lag.
- Antivirus software routinely quarantines penetration-testing tools (observed:
  Malwarebytes quarantining naabu on launch). The installer detects a binary
  that disappears during its version check and tells the operator; deciding to
  exclude the tools directory remains the operator's choice.
- nuclei still manages its own template directory. Pinning templates into
  `~/.vardrmap/data` is a follow-up.

## Alternatives considered

- **One container per tool (as in larger frameworks).** Gives isolation and easy
  removal, but needs a Docker daemon on every runner, multiplies download size
  (a base image and toolchain per tool), and fights the scanners: SYN scans need
  raw sockets, which in a container means `--cap-add`/`--net=host`, undoing the
  isolation. VardrRunner's premise is a light client on the operator's own host.
- **`go install` from source.** Integrity via the Go checksum database is good,
  but it requires a Go toolchain on every runner, builds slowly, and does not
  cover tools that publish only release binaries.
- **Verify against the upstream checksums file at install time.** Same origin as
  the binary, so it defends against corruption but not against a modified release.
  It is used only when pinning, as a cross-check.
- **Managed-only (no PATH fallback).** Stricter, but breaks every existing
  installation on upgrade. Reporting PATH copies as unverified gets most of the
  benefit without the break.
