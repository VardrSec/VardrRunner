# ADR 0020: Patch existing container Katana through a recorded source build

Status: Accepted for development security remediation, 2026-10-27. Alpha tool
scope and image publication remain separate decisions. Keep all nine existing
tools and preserve native archive installation; introduce no engine or daemon.

The official Katana 1.8.0 binary embeds affected Go/dependency versions. A bounded
source experiment removed its two pgx critical findings and other high findings
without changing the crawler source. OS package updates cannot replace embedded
Go dependencies. Build the same upstream command with pinned Go 1.27.3 and the
reviewed pgx 5.9.2, x/net 0.60.0 and compress 1.18.7 overrides.

Use Go's checksum database and module proxy explicitly, disable implicit compiler
downloads and retain go.mod, go.sum and actual binary build information. Before
probing or installing, verify the builder's binary SHA256, expected compiler,
upstream version and required dependency versions. Reject module replacements.
Record source origin and checksums in the root-owned managed receipt, with no
invented archive hash. The existing runtime resolver/verify path remains mandatory;
source origin never permits fallback after a failed hash check.

The build-only helper refuses existing Katana data. Ordinary image runtime stays
UID 10001, capability-free and unable to modify binaries or provenance. Native
tool pins, download behavior and other tools remain unchanged. Status's detail
identifies a verified source build; its existing `managed` category means the
binary passed its local integrity receipt, not that it is an upstream archive.

This is still a development build: dependency/build records are not authenticated
published provenance, and pip/apt inputs retain their existing resolution boundary.
Do not infer all-tool clearance, all-mode acceptance or a release from this patch.
Rebuild and rescan the combined distribution before changing its source pin.
