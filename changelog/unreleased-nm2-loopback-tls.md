# Unreleased: disposable verified loopback HTTPS

Add a test-only transport using `VardrMapClient`'s existing HTTP/session layer.
Only fixture instances select a disposable CA, zero redirects/retries and bounded
timeouts. Verify named-chain failures, credential-forwarding refusal, ambiguous
claim/control responses and unchanged server lease expiry before an inert launch
callback. No runtime client default, CLI, production route, trust store, queue,
Gate execution, release pin or supported execution profile changes.

This requires the matching Map synthetic test app and explicit isolated TLS opt-in;
it establishes no deployed backend version, real enrollment, persistent trust,
fresh-host/public/VPN compatibility or distributed consume/ACK/recovery protocol.
