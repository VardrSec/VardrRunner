# Unreleased — Nuclei go-jose remediation

The toolkit rebuilds Nuclei 3.11.1 with `github.com/go-jose/go-jose/v4` 4.1.6,
fixing CVE-2026-116587 / GHSA-mgcc-cww5-fp2q (excessive CPU parsing crafted RSA JWKs).
The source installer rejects a missing or older dependency before running or registering
the binary. The other source patches, upstream tool version, checksum verification,
non-root execution and explicit template selection remain in place.

This changes only the source-built toolkit. Native archive pins are unchanged; no
native remediation or release clearance is claimed. The distribution must pin this
Runner commit and rerun its installed workflow and raw image evidence before acceptance.

Upstream: [security advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q),
[fixed release](https://github.com/go-jose/go-jose/releases/tag/v4.1.6).
