# ADR 0040 — Partial single-run portable evidence export

Status: isolated implementation candidate; unpublished and not full NM-3 acceptance.

## Requirement and smaller options

The approved NM-3 roadmap requires portable local evidence and non-destructive
record preservation, with Windows-first installed acceptance. The prior component
copy experiment proved existing formats readable, not a usable export command,
installed transition or safe authority restoration. Metadata-only audit export
already exists. A raw SQLite backup would also copy ledger/grant state and does
not supply artifact coherence; a new archive store/importer is unnecessary here.

## Decision

Add only an explicit one-run local command using existing schema-1 audit/manifest
and central redaction. It accepts a terminal, PID-free current-schema record and
a bounded JSON object artifact matching its recorded SHA-256 and size. No keys,
credentials, providers, approval/consumption changes, network, tool execution,
MCP capability or new database schema is involved.

Retain sanitized original provenance in audit.json. artifact.json is a **redacted
derivative**, never original-byte evidence; the relative-path manifest hashes
the exact serialized copy and links the original hash through an explicit warning.
Preserve source phase/status, including partial/failed outcomes. No source file
is rewritten. Redaction is the existing policy, not a secret-free guarantee or
finding reclassification. External sharing still requires operator review.

Read the journal with SQLite mode=ro and require its current schema; never create
or migrate it. Recheck through new connections before and after output writes.
Verify regular-file identity, single link, size/digest, stable descriptor metadata
and absence of symlink/reparse path components. Reject duplicate/nonfinite JSON,
unsupported roots/formats, depth above 12, source/copy above the smaller of 8 MiB
and local artifact policy, and metadata above 1 MiB per document.

On supported POSIX systems, require root/current-user ancestor ownership and no
group/other write except trusted sticky directories. Create a new mode-700 output
and write three fixed names exclusively through its pinned descriptor, mode 600.
Verify derivative bytes, output directory identity and unchanged record before
the manifest is written last. Preserve partial files on failure. Reserve the
existing free-disk floor plus all three actual serialized sizes. This is not a
global filesystem transaction, aggregate disk quota or defense against root or
the same privileged account modifying its own files.

## Windows boundary and decision still needed

POSIX-only creation **does not satisfy** the roadmap's Windows-first export exit.
The new command refuses Windows; existing metadata commands retain their behavior.
CPython's newer private-directory creation is useful but does not itself bind
later path-based writes against parent/ancestor replacement. Python's directory-FD
operations used here have no Windows equivalent in this implementation.

A bounded Windows adapter could evaluate documented CreateFileW directory handles,
reparse-point checks and sharing modes that prevent delete/rename while handles
are held, with private creation and verified file identity. Microsoft documents
these APIs; it does not establish that this entire protocol is safe or tested.
The precise next decision is whether to authorize that narrow adapter and synthetic
Windows race/ACL tests, or select another existing supported output mechanism
with equivalent guarantees. No such layer is implemented/adopted here; no host
ACL changes, privileges, new dependencies or unsafe fallback are authorized.

References: [Python directory creation](https://docs.python.org/3/library/os.html#os.mkdir),
[Microsoft CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

## Gates

New focused cases and independent source review supplement fresh exact-candidate
full regression/95% coverage on a supported host. Unit root/capacity simulations
are explicit; the no-simulation case remains unproven on this constrained runtime.
Windows creation/ACL/race acceptance, complete workspace/external signed-input
export, installed transition and restoration remain open. Unsupported Docker
managed execution and its failed watchdog-hang gate are unchanged.
