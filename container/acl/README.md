# Coordinated ACL callers on Trixie

This build uses the complete Debian ACL 2.4.0-1 source and rebuilds the existing
coreutils 9.7-3 and tar 1.35+dfsg-3.1 recipes on Trixie. It does not import an
unstable runtime, upgrade glibc, remove user-management tools, or change the
application interfaces. Only libacl1, coreutils and tar binary packages enter the
runtime. Development headers, ACL command-line test tools and the preload fixture
remain in the discarded builder.

ACL's new descriptor-relative APIs are required because the old pathname API
semantics cannot be changed compatibly. See the [upstream advisory](https://www.openwall.com/lists/oss-security/2026/06/29/1)
and [Debian tracking](https://security-tracker.debian.org/tracker/CVE-2026-54369).
The library also updates `perm_copy_fd`, used by shadow's existing descriptor-based
home-directory copying, to preserve directory default ACLs through descriptors.
No shadow source change is made.

The coreutils patch keeps directory/special-file ACL destinations anchored to
cp's resolved parent descriptor, refuses replacement symlinks, checks source
identity, and uses the descriptor for both access and default ACL operations.
Explicit source dereferencing remains supported. O_PATH avoids opening devices
or blocking on FIFOs. Debian's USE_XATTR copying path follows pinned procfs aliases using bounded
xattr operations and its existing permission-attribute filter, preserving
POSIX/NFSv4 metadata without passing O_PATH descriptors to fgetxattr or
using libattr's non-following file operations on procfs symlinks. The chmod path also uses the pinned alias
when fchmod cannot operate on O_PATH. Procfs is required, as it is for
upstream libacl's compatibility implementation.

The tar patch replaces its local legacy pathname wrappers with libacl's anchored
APIs. Reads preserve explicit `--dereference` behavior; writes refuse final
symlinks. This also avoids the [new API namespace collision](https://bugs.debian.org/1141146)
without importing unrelated tar updates. Existing tar path-traversal protections
remain required; this is not a general filesystem race-proofing claim.

Builds run unprivileged with ordinary Debian packaging and retain its test logs.
Debian disables coreutils' test target, so the existing upstream cp/mv/ls/mkdir
ACL cases additionally run explicitly. The test-only preload makes a deterministic
synthetic directory-to-symlink substitution at the default-ACL boundary. Stock
cp/tar must demonstrate the vulnerable control; the exact stripped replacement
payloads must preserve the pinned cp destination or refuse tar's redirected write.
Ordinary ACL preservation and intentional source/parent symlinks are controls.
These are bounded regressions, not complete CVE coverage or an independent rebuild.

The source bundle retains the original descriptors and archives, patched Debian
source packages, patches, build environment, applied-patch ledgers, source and
binary payload hashes, and regression logs under a SHA-256 manifest. Runtime
notice collection and existing image/installation checks remain separate. No
adjudication, suppression, risk waiver or publication authorization is supplied.
