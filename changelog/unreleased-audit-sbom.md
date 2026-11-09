# Unreleased: required release SBOM

SBOM generation now fails the release build on error or an empty/invalid CycloneDX inventory. Existing build dependencies gate attestation and publication. Agent-local secrets are ignored and pinned Gitleaks coverage is added. No release was run.
