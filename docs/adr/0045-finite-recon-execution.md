# 0045: Explicit finite Recon through the existing execution owner

Status: implementation; installed qualification and distribution pins remain separate.

## Decision

Keep `finite-dns-http/1` dormant and unchanged. The explicit
`finite-dns-http/2` profile binds the actual verified managed DNSx/HTTPx bytes,
the full reviewed inputs, numeric resolvers, destination CIDRs and finite bounds.
`workspace authorize --profile recon` uses the existing private issuer and signs
one execution. Gate remains the default; its consumer still rejects Recon.
Generic `workspace execute` and the explicitly selected local worker dispatch the
new profile. Normal startup, legacy commands, queue and MCP capabilities do not change.

One existing ledger ordinal covers DNS and every HTTP candidate. There is no
stage budget store, refund, new signer, service, scanner or orchestration layer.
All stages share one immutable monotonic plan ceiling and the earlier signed
deadline, authority and control limits. Discovery output is never execution authority.

DNSx asks A questions only through the signed numeric resolvers. Every returned
address must pass the signed CIDRs and existing hard/private exclusions before
any HTTP launch. Choose the lowest numeric IPv4 address per hostname. HTTPx
receives a literal HTTPS/443 address, the original Host header and TLS SNI, the
signed CIDR allowlist and HTTP/1.1-only transport. No redirects, fallback scheme,
extra probes, enumeration, screenshots, authentication or updates are enabled.
Each original candidate is processed once; the logical URL remains its original
hostname. The selected address is retained separately in evidence.

The reviewed DNSx 1.3.1/retryabledns 1.0.116 path permits one UDP question and at
most one TCP retry for truncation: `2N`. HTTPx 1.12.0/retryablehttp-go 1.3.25 can
retry a malformed response once and retry invalid gzip once: `4M`. HTTP/1.1
aliases the malformed-response client to the same policy-aware transport.
Fastdialer 0.5.19 skips DNS for literal addresses, including result metadata.
Managed hashes are rechecked at review and before each launch. Source-build
receipts must match the reviewed dependency versions; they remain development
provenance, not authenticated release provenance. Native managed releases remain
bound to the packaged manifest version and verified installation receipt.

The existing native owner stays armed for the whole attempt. A next-tool handoff
requires the identical active epoch, control and binding, previous normal return,
fresh descendant drain and an unexpired original lease/hard ceiling. Only the
three per-tool launch/drain flags reset. No native protocol, attempt sequence,
admission, privilege or physical-stop-report authority changes. A nonzero tool
exit propagates immediately; it cannot authorize the next stage or native DONE.
Native Windows uses its existing Job Objects under the same aggregate control cap.

Recon alone gets a task-local fresh owned HOME/config/cache and scrubbed tool
environment. It inherits no proxy, PDCP/API/identity credential or user tool
configuration. Tool console output is suppressed; raw JSONL files stay with the
private run. The existing bounded JSON artifact, journal hash and redacted export
retain the original plan and observed transport. Healthy completion still needs
native descendant drain/DONE before ledger and journal completion. Failure keeps
the spent/uncertain attempt and evidence; there is no automatic replay.

## Evidence and limits

The aggregate records DNS observations, original HTTP candidates and selected
addresses. A missing response does not prove absence or authorization safety.
Handoff URLs require a separately reviewed Gate case and fresh permission.
Application-question/request ceilings are source bounds, not packet, byte or
connection measurements. Artifact limits and existing resource controls remain.

Full/Mapless and Windows/Docker/Linux installed qualification are required for
the integrated cohort. C09 sleep, broader Recon pipelines, native deployment
qualification and release acceptance are separate; this decision waives none.

Reviewed primary sources:

- [DNSx client](https://raw.githubusercontent.com/projectdiscovery/dnsx/v1.3.1/libs/dnsx/dnsx.go)
- [DNS attempts and truncation](https://raw.githubusercontent.com/projectdiscovery/retryabledns/v1.0.116/client.go)
- [Literal-IP dialing](https://raw.githubusercontent.com/projectdiscovery/fastdialer/v0.5.19/fastdialer/dialer.go)
- [HTTP retry loop](https://raw.githubusercontent.com/projectdiscovery/retryablehttp-go/v1.3.25/do.go)
- [HTTPx transport](https://raw.githubusercontent.com/projectdiscovery/httpx/v1.12.0/common/httpx/httpx.go)
- [HTTPx request construction](https://raw.githubusercontent.com/projectdiscovery/httpx/v1.12.0/runner/runner.go)
