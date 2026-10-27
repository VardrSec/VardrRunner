# Unreleased — container Naabu security remediation

Build existing Naabu 2.6.1 with Go 1.27.3, x/net 0.60.0, x/crypto 0.57.0 and
compress 1.18.7 through the recorded source-build helper. Keep compiler,
module/version/checksum checks, no replacements/overwrites, explicit source origin
and mandatory managed binary hashes.

Use CGO and libpcap-dev in the builder only. Runtime libpcap, UID 10001,
capability-free execution and bounded TCP-connect operation remain.
Native archive pins, all nine tools, the default core image and backend/auth
contracts are unchanged. No release, privilege expansion or alpha scope choice
is introduced. Remaining vulnerabilities and transport/provenance limits need review.
