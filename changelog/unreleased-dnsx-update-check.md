# DNSx automatic version check

The existing DNSx adapter passes `-disable-update-check`, supported by the pinned
v1.3.1 tool. Target input, result handling, timeout, environment allowlist and
existing connected behavior remain unchanged. No recon profile is activated.

Argv regression and an opt-in managed parser/version smoke accompany the change.
Version mode performs no DNS queries and cannot prove actual adapter network
behavior. Broader destination, resolver, proxy and aggregate-budget enforcement
remain separate requirements; this flag alone is not an egress guarantee.
