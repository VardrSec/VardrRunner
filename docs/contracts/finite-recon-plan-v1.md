# Dormant finite recon plan v1

Discriminators: `schema = vardr.finite-recon-plan/1`,
`profile = finite-dns-http/1`, `runtime = unsupported`.
This is a separate compiler-enforced projection, not an instance of the
Gate-only `plan-v1.schema.json`. No standalone JSON Schema is provided for recon;
`compile_recon_plan` plus exact canonical recompilation is normative. Structural
validation alone cannot establish the following arithmetic, authority or binding.

The complete object contains exactly these compiler-produced fields:

| Fields | Constraint |
| --- | --- |
| schema, profile, runtime, platform_model | Fixed discriminator values from the compiler; Linux amd64 conditional model only |
| input | Exactly hostnames, candidates, destination_cidrs, resolvers; canonical finite lists, no duplicate entries |
| case_hash | SHA-256 of canonical encoded input |
| tools | Exactly the reviewed HTTPx and DNSx Linux ELF SHA-256 identities |
| execution | Exactly deadline, timeout_seconds (1..600), max_artifact_bytes (1..1 GiB), allow_private_targets (boolean) |
| dispatches | Exact original HTTPS/443 GET-root candidates, with no expansion |
| credential_references | Empty list |
| max_http_dispatches, max_dns_queries | Full original 4M and 2N+50M application request/question envelope |
| reservation | Whole-plan execution ordinal, no post-handoff refund |
| counting | DNS/HTTP application units; packets, bytes and connections not bounded here |
| options | Exact compiler-fixed tool, environment, resolver and destination policy projection |

All field values must equal exact recompilation; unknown or modified fields deny.
Hostnames are lowercase ASCII DNS labels (no IP literals, wildcard or trailing
dot). Input limits: 1..1000 hostnames/candidates, 1..100 destination CIDRs,
1..10 numeric IPv4 resolvers with port 1..65535. IPv4 CIDRs must be canonical,
exclude hard-denied ranges, and satisfy the signed private-target setting.
Special-range overlap checks are deliberately conservative. Resolver permission
is explicit and separate from HTTP destination CIDRs.

Human approval signs the full digest; existing common signature, authority, time,
Strict scope, HTTP/duration/evidence and ledger checks remain mandatory. The
shared recon deadline is checked both in validation and at the ledger's final
elapsed-time check for issuance/consumption. Failure rolls back reservation
changes while preserving the trusted clock high-water mark. This does not claim
an atomic real-time database commit at the deadline or enable any execution.
