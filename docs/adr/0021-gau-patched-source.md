# ADR 0021: Recorded Gau source fixes for TLS and provider failures

Status: Accepted for development security remediation, 2026-10-27. This does not
decide alpha tool scope or authorize image publication/native archive clearance.

Gau 2.2.4 disables provider TLS verification. Its initialization/worker error paths
also warn and can exit zero with empty output, so a dependency-only rebuild does
not establish secure or conclusive execution. A controlled experiment confirms
both defects. Preserve the upstream version and change exactly four statements:
enable normal TLS verification, and make initialization/worker errors fatal.
Also keep extensionless URLs in JSON output, matching the plain writer's filter;
the real handler regression exposed that silent output loss. Valid empty provider
responses remain successful. A partial failed lookup is not
a completed inventory; Runner's existing nonzero-exit path must fail the job.

Download the fixed upstream module through Go's checksum database, verify its
recorded module/mod-file checksums and revision, then copy it into a separate
build tree. Check all four original file hashes, apply only the reviewed single
substitutions and check their resulting hashes. Retain upstream module metadata,
original/patched files, license, original/resolved module files and actual binary
build information. Dependency patches remain explicit. Do not modify the module
cache, use module replacements or describe a patched tree as an unchanged module.
Pin the original module-file and license byte hashes too; changed retained records
must fail before probing the binary.

The local main module correctly reports `(devel)` without a checksum. Permit that
shape only for this fixed Gau recipe; preserve the original module's checksum
separately in `upstream_module` and the transformations in `source_patches`.
Other tools still require their exact unmodified upstream module/version/checksum.
The reviewed Trivy report lists this modified main package without a version;
reconcile upstream Gau advisories against the separately retained original
version/commit and patch set. Zero binary findings do not establish complete
upstream-advisory coverage or all-provider safety.
Before version probing/installing Gau, verify its binary checksum and all source
records again. Runtime hash resolution remains mandatory, without fallback on
tampering. Status explicitly identifies reviewed source patches.

Real container tests run the actual managed binary through GauHandler, with a
loopback HTTPS provider and a rejecting loopback proxy that never forwards.
Untrusted/wrong-host TLS, malformed responses and initialization failures must
raise ToolError; explicitly trusted valid and valid-empty responses must work.
Synthetic CA/leaf keys are generated on the CI host with the existing dev-only
cryptography dependency, mounted read-only and never put in a product image or
artifact upload. No host trust changes, real provider traffic or API keys occur.

This is an explicitly patched development artifact, not authenticated release
provenance or proof of all provider/platform modes. Native archive pins remain
unchanged and do not acquire this fix. Preserve the nine-tool baseline, UID10001,
capability-free runtime, explicit invocation and existing backend/auth contracts.

## Addendum: native Gau is excluded

Native Gau archives still disable provider TLS verification, and a security tool should
not offer that as a supported option. `toolchain.install` now refuses Gau, `tools install
--all` skips it with the reason, and `toolchain.resolve` and `status` accept Gau only when
its receipt records the reviewed source build (`go-module-source` with source patches). There
is no PATH fallback and no opt-in. Container images are unaffected because their patched
Gau is registered by the image-build helper, not by the archive installer. Operators who
need Gau use the container toolkit.
