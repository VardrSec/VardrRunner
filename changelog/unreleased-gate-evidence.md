# Unreleased: independent Gate readback identity

Gate's optional independent reader uses the same local credential reference
resolution and principal-diagnostic validation as callers. Missing/inconsistent
reader diagnostics fail the job; failed preflight evidence is retained and uploaded.
Capability gating also covers reader-only preflight configurations. Semantic
assessments/readback provenance continue through the existing raw-result upload;
no scanner conclusions are promoted to confirmed findings.

Deploy companion Map semantic-evidence handling before using the companion Gate
reader-preflight change through Runner. Existing unresolved case hashes, recovery,
private-target opt-in and foreground execution behavior remain unchanged. This
note does not assign a release version or claim deployment.
