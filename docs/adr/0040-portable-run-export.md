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

## Bounded Windows candidate

The owner authorized a narrow same-contract Windows platform adaptation. API
availability was observed on Papachin Windows 25H2 (build 26200.9711, amd64);
neither creation API was invoked by that preflight. This is not native acceptance.

Use documented CreateDirectory2W (atomic new directory plus returned handle) and
CreateFile3 with no-redirect flags at every actual open/create. Both require
Windows 11 24H2+ / Server 2025+. Pin every ancestor, source, output and file handle
without write/delete sharing until completion. Check actual object type, identity,
local fixed NTFS/persistent ACLs and owner. Reject unknown owners and unsupported
paths/APIs/sharing states, without an older pathname fallback.

Path spelling is not a raw-token security boundary. Python/CLI Path conversion
can normalize dot or repeated separators before the adapter receives a value,
and output is made absolute in the shared command. Such normalization is allowed;
no-redirect API operations and retained verified handles bind the actual path.
Raw-string unit rejection cases must not be reported as end-to-end CLI rejection.

Current-user/SYSTEM/Administrators SIDs are the counterpart to current-user/root
trust. New directory/files require exact current ownership and a verified present,
protected non-null DACL granting only those principals. No inherited handles. Fixed
files use CREATE_NEW, exact readback and manifest-last publication. Retain partial
outputs and close owned handles; never remove evidence or change existing ACLs.
Shared code retains reserve, original hash, strict parser, redaction, provenance,
status and fresh journal checks; the adapter adds no authority or storage format.

The Microsoft header and syntax specify the five-argument HANDLE ABI for
CreateDirectory2W. The documentation's sample has inconsistent argument/return
examples; do not copy it. Reject null and INVALID_HANDLE_VALUE and validate the
returned handle. Native ABI, ACL/privacy, reparse/junction and ancestor/destination
races, exclusive creation and interrupted publication remain required gates.

References: [CreateDirectory2W](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectory2w),
[CreateFile3](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfile3),
[Microsoft header](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/fileapi.h).

## Gates

New focused cases and independent source review supplement fresh exact-candidate
full regression/95% coverage on a supported host. Unit root/capacity simulations
are explicit; the no-simulation case remains unproven on this constrained runtime.
Windows creation/ACL/race acceptance, complete workspace/external signed-input
export, installed transition and restoration remain open. Unsupported Docker
managed execution and its failed watchdog-hang gate are unchanged.
