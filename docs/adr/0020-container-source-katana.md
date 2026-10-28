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

## 2026-10-27 addendum: existing DNSx

Apply the same contract to pinned DNSx 1.3.1 with Go 1.27.3, x/net 0.60.0 and
compress 1.18.7 after its isolated source experiment passes a synthetic DNS lookup
and removes its critical/high findings. Rename the shared build-only helper and
keep an explicit two-tool allowlist with separate module/dependency assertions.
Do not expose a generic installer or new configuration. Preserve native archives,
all nine tools and the previous security/runtime boundaries. Container CI performs
one bounded .test A lookup against an in-container loopback resolver, with updates
disabled, one thread/retry and no external DNS or added capability.

## 2026-10-27 addendum: existing Naabu

Extend the fixed build allowlist to Naabu 2.6.1 with Go 1.27.3, x/net 0.60.0,
x/crypto 0.57.0 and compress 1.18.7. Use CGO with libpcap-dev confined to the
builder; keep the existing runtime libpcap package. Its isolated source experiment
passes bounded TCP-connect operation as UID 10001 with no capabilities and removes
critical/high scan findings. This grants no raw-socket privileges, VPN acceptance,
native archive clearance or release. Other tool behavior still needs security review.

## 2026-10-27 addendum: httpx, Subfinder and FFUF

Extend the fixed build allowlist to the existing httpx 1.12.0, Subfinder 2.17.0 and
FFUF 2.3.0 with Go 1.27.3, x/net 0.60.0 and (httpx, Subfinder) compress 1.18.7, using
the same recorded-source contract and mandatory runtime hash verification. Their
scan findings were fixed-version standard-library and dependency occurrences; this
changes only the container build. FFUF release builds inject their version with
linker flags, so the build sets the same two variables; an unflagged source build
reports a development version and fails the pinned-version probe. Native archives, Nuclei (separately reviewed),
VPN behavior and release scope are unaffected.

## 2026-10-27 addendum: Nuclei

Extend the allowlist to the existing Nuclei 3.11.1 with Go 1.27.3 and the fixed
versions of kin-openapi 0.149.0, go-git 5.19.2, x/crypto 0.57.0 (required by x/net 0.60.0), x/mod 0.41.0,
x/net 0.60.0, x/text 0.42.0 (required by x/net and x/crypto) and gRPC 1.83.2 named by the scanner. Templates are
still not bundled or provisioned; Nuclei's non-root XDG state handling is covered
by the existing container state test. Dependency upgrades across minor versions can
change behavior, so the container job, state probe and the distribution's real
Nuclei fixture must pass before this is pinned.

## 2026-10-27 addendum: reachable advisories newer than the frozen scan database

Go's `govulncheck`, run against locally built binaries of every source-built tool
with the same recipes, reported two reachable advisories that the frozen image-scan
database predates: GO-2026-6860 (quadratic HTML parsing in x/net, fixed in 0.62.0;
reachable in FFUF, Nuclei and the ProjectDiscovery tools) and GO-2026-5320 (goldmark
cross-site scripting, fixed in 1.7.17; reachable in httpx, Subfinder, Katana, DNSx,
Naabu and Nuclei). Raise x/net to 0.62.0 for all builds and patch goldmark 1.7.17
where the binary links it; Go's resolver then requires x/crypto 0.58.0 and x/text
0.43.0. With these, `govulncheck` reports nothing for httpx, Subfinder, Katana, DNSx,
FFUF and Gau; Nuclei retains GO-2026-5932 (the unmaintained x/crypto/openpgp
package, no fixed version), which is inherent to upstream Nuclei and remains open.
Naabu needs CGO and libpcap and was resolved but not locally scanned.


## 2026-10-28 addendum: Nuclei go-jose

Keep Nuclei 3.11.1 and rebuild with go-jose/v4 4.1.6 for
[CVE-2026-116587](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q).
The image's source installer requires the fixed module in binary build information,
so an omitted or vulnerable version is rejected before the tool is registered.
Container smoke, the distribution's real Nuclei fixture and refreshed image evidence
must verify this build. GO-2026-5932 remains unresolved; this patch does not accept it.
