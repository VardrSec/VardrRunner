# ADR 0042 — Canonical journal names and Windows replacement pins

Status: focused NM-3 correction; cross-platform and installed acceptance remain open.

## Problem

A leaf alias can cause Windows SQLite to use different WAL sidecar names and miss
committed data. Checking the journal with lstat before SQLite opens it also leaves
a replacement gap. A synthetic native test at the SQLite-open boundary accepted
a different valid database. Separately, mode=ro inspection created WAL/SHM files;
read-only SQL does not establish a non-mutating filesystem snapshot.

## Decision

Use one resolved canonical database pathname for every journal connection,
including workspace inventory and credential-grant transactions. Preserve ordinary
symlink aliases by resolving them before opening. Do not introduce another database,
VFS, runtime dependency or approval path.

On Windows, open the canonical ancestry in order from the drive root, then the
database. CreateFileW uses OPEN_REPARSE_POINT on every final component; validate
the actual returned disk handle as non-reparse and the expected file/directory
type. Retain non-inheritable handles without FILE_SHARE_DELETE until the SQLite
connection closes, including failure paths. Directory handles also omit write
sharing. Database handles allow SQLite read/write access; missing writable databases
use CREATE_NEW without truncation and refuse a raced-in file. Compare the originally
observed file identity to the canonical pathname while its actual non-reparse handle
is held, before SQLite opens. These APIs do not require a newer Windows build.
Refuse hardlinked database files because multiple names can split WAL state.

Native regression attempts replace the leaf or rename its ancestor immediately
inside sqlite3.connect, then verify the original records remain available. Further
tests check pin lifetime, cleanup after failed connections, invalid/reparse/hardlink
handles and committed WAL reads through ordinary aliases. A skipped fixture records
unavailable native permissions, not acceptance.

Retention inventory reads only the three referenced path columns, refuses more
than 10,000 records, limits each path's database-encoded bytes to 4 KiB before
Python materializes it, then separately checks the decoded path's UTF-8 bytes
against the same limit. It caps total UTF-8 path bytes at 8 MiB, including UTF-16
databases. It never silently truncates a destructive cleanup
decision or parses unrelated command/grant JSON. The caller must skip cleanup when
inventory is incomplete or unreadable.

## Limits

This protects the tested Windows database/ancestor name-replacement boundary. It
does not authenticate a database against its owner, prevent legitimate content
writes, pin WAL/SHM sidecars, bound filesystem metadata stalls or guarantee source
non-mutation. Privileged in-place object changes are not a new tamper guarantee.
POSIX retains canonical WAL names and its existing observed-file check; its
pathname replacement race remains open. No platform's strict snapshot gate closes.
Never use immutable=1 on a changing live database to hide sidecar writes: committed
WAL-only data may be omitted. A consistent, non-mutating snapshot requires its own
demonstrated design and acceptance tests.

References: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[SQLite WAL](https://www.sqlite.org/wal.html),
[SQLite URI parameters](https://www.sqlite.org/uri.html).
