# NM-2 explicit managed transport

Add a library-only managed JSON method in api.py; existing calls remain unchanged.
Bounded one-shot requests retain proxy/CA settings and reject redirects, malformed
or oversized replies without retries. Verified TLS fixtures exercise exact result
and stop receipt flows. Production Map routes are not registered; no enrollment,
worker, migration or deployment. Reconcile phase status to the canonical roadmap,
not the earlier scoped evidence matrix. See ADR 0038 and canonical exit status.
