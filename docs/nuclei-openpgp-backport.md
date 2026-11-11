# Nuclei OpenPGP backport provenance

This image-only change preserves Nuclei v3.11.1 and go-github's v30 API generation.
It replaces the deprecated `golang.org/x/crypto/openpgp` import in go-github's
commit-signing implementation with `github.com/ProtonMail/go-crypto/openpgp`
v1.5.2. A nil primary/private key is rejected before invoking signing. No
algorithm, expiry, revocation or signature verification checks are disabled.
The signing entity's Go package type changes: this is a bounded compatibility
backport, not an unchanged upstream module or general-purpose SDK release.

## Exact inputs and source delivery

- Upstream module: `github.com/google/go-github/v30@v30.1.0`
- Upstream tag commit: `371b0007be89061b4cf899dc2083dd08e3912c14`
- Module checksum: `h1:VLDx+UolQICEOKu2m4uAoMti1SxuEBAl7RSEG16L+Oo=`
- Original Go proxy ZIP SHA-256:
  `34ccb01d56786a8f7eb876e82f33dc79034c9bd2ce863e182cae6544861a2a3d`
- Reviewed unified patch SHA-256:
  `59c13a21195b6669988125c561cbefd54e17924bdca79991ebc3f2e5f47ed8c3`
- Complete patched source tar SHA-256:
  `6d24aa8e6bba4ff67130061191de4a46c10bd4fabbe3cfca389eba666b4e571a`

`container/nuclei_openpgp.py` checks the original ZIP and reviewed file changes,
then verifies every changed file's before/after SHA-256. Its deterministic tar
contains the entire module source, including the original BSD license,
unchanged go.mod/go.sum, and modified/new tests. It has canonical member order,
modes and zero timestamps and is intentionally uncompressed to avoid compressor
version differences. The original ZIP, patch, source tar and separate license
are retained under the installed Nuclei provenance directory, together with the
main build module's final go.mod/go.sum and binary build information. Source
identity is independent of filesystem timestamps.

The main module declares exactly one local replacement at
`/src/go-github-v30-patched`. The image installer accepts this replacement only
for the specified module/version and only with the pinned source/patch evidence
and a successful test report. Arbitrary replacement paths or other module
replacements remain rejected. The installed receipt explicitly records the
local source patch and source hash; it does not invent an upstream `h1` checksum
for modified code. These hashes are integrity checks, not signatures.

## Tests and limitations

The Nuclei builder executes the bounded GitService/signing tests against its
**final selected module graph**, retaining JSON test events. The historical
2019 signing fixture expired in 2021. The valid-key roundtrip therefore uses a
fresh generated key, while a separate test requires the historical expired key
to be rejected under the maintained library's default policy. The installer
requires the valid signed-commit, fresh crypto roundtrip and expired-key tests
to pass, along with a successful package result and no failing events.

A full Nuclei build is required to qualify this API-type change for this exact
consumer. This is not proof of universal compatibility, an external target scan,
a runtime Nuclei template execution test, or byte-reproducible Go binaries.
The source archive is reproducible; build-time keys and test timestamps are not.
No advisory ignore list or scanner suppression is introduced. A newly built
exact-image vulnerability scan remains necessary before release disposition.

### Broader legacy SDK suite is not green

The full old go-github package suite was also attempted and is **not** claimed
passing on the new compiler. `TestRepositoriesService_GetContents_DirectoryWithSpaces`
uses a ServeMux pattern containing spaces rejected by the current Go runtime.
A diagnostic rerun with the test-only legacy mux setting
`GODEBUG=httpmuxgo121=1` advanced to `TestNewRequest_invalidJSON`, whose expected
`UnsupportedTypeError` for a nil `map[interface{}]interface{}` field no longer
matches current `encoding/json` behavior (null encoding). An unmodified v30.1.0 source baseline against the same main dependency graph
reproduced both failures. Neither legacy test
was changed to conceal these failures. The compatibility setting is not enabled
in the image or required by the bounded signing tests. These findings limit the
qualification to the reported signing tests and successful exact-consumer build;
they are not a blanket SDK compatibility claim.
