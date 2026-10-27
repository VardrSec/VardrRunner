# Unreleased — container Gau TLS and provider failure fixes

The toolkit's existing Gau 2.2.4 verifies provider TLS certificates normally.
Provider initialization/fetch/decode errors now exit nonzero, so Runner's existing
failure path rejects them instead of reporting an empty successful lookup. Valid
empty responses still work; partial output after a provider failure is incomplete.
JSON output retains extensionless URLs, fixing the silent loss found by the real
producing-handler success case while retaining configured extension filtering.
Explicit CA trust works without an insecure fallback or host trust changes.

Build from a checksum-verified original module in a separate patched tree, with
four exact before/after file hashes, retained original license and source/build
records. Record the modified main module as `(devel)` without inventing its
checksum; keep original upstream checksum/revision and source patches separate.
Verify all records before probing and retain mandatory runtime binary hashing.
Status identifies reviewed source patches. Patch existing Go dependencies too.

Real non-root container regressions exercise managed Gau through its producing
Runner handler against loopback synthetic fixtures, including TLS, malformed,
valid-empty and initialization cases. Existing dev-only cryptography generates
disposable test material outside the product image; no real provider/API key is
used. Native archives, other tools, core image and backend/auth contracts are
unchanged. Native Gau does not acquire this fix. No release, alpha tool-scope
choice, privilege expansion or blanket suppression is introduced. See ADR 0021.
