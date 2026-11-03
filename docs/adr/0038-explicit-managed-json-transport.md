# ADR 0038 — Explicit bounded managed JSON transport

Status: unregistered local primitive; canonical NM-2 worker exit remains open.

The managed protocol uses injected callbacks and fixture-only routes. The generic
API client follows normal requests behavior and has no strict response byte bound.
Fixture-specific redirect/retry configuration is insufficient as a runtime primitive.
Add only `VardrMapClient.managed_post`, keeping all HTTP inside `api.py`. No route,
CLI flag, signing/enrollment configuration, background worker or deployment is added.

Require a configured HTTPS root origin and simple trusted path; reject URL/path
ambiguity before sending. Encode at most 1 MiB per request and stream at most
256 KiB of response, rejecting oversized declared or actual bodies. Accept only
HTTP 200 JSON objects, strict UTF-8/duplicate-key/depth decoding and finite numbers.
Reject content compression, redirects and malformed/noncontract statuses. Fixed
errors expose neither response bodies nor credentials. Oversized evidence fails;
there is no chunking, splitting, fallback or automatic retry.

Each call creates a fresh session with retries disabled and redirects refused.
Use the configured API header explicitly, preventing requests netrc replacement.
Do not inherit cookies or arbitrary session headers. Preserve operator CA/client
certificate and proxy/trust-environment configuration; never disable verification
or bypass a configured network path. Generic API calls retain their existing
session/retry/redirect behavior. Existing protocol parsers still validate exact
job/principal/plan/contract/receipt semantics; transport success grants no permission.

Connect/read-idle timeouts must be finite, positive and at most ten seconds each.
They are not a total transfer deadline: a dripping peer may extend wall time.
Managed runtime must retain its original signed and monotonic ceilings, reject
late claims/ACKs, and stop execution when leases expire independently of refresh.
No new total-deadline assurance is claimed; no lease can be extended by this helper.

Synthetic unit and verified loopback TLS tests exercise complete result/stop
receipts, actual authentication, certificate rejection, redirects, ambiguity and
strict size/JSON negatives. The method remains unregistered and fixture-only in
this candidate. It is a bounded prerequisite, not production managed integration.

The canonical roadmap requires an approved operator-enabled Docker Desktop worker.
That is absent, and controlled execution currently supports Windows-native only,
not Linux inside the preferred images. Native Windows evidence cannot substitute
for container containment and queue acceptance. See the canonical exit status.
Independent review, Windows, hosted CI/security, migration comparison and phase
consolidation remain open. Owner backup waiver is retained. NM-3 has not begun.
