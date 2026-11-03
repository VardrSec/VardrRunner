# NM-2 existing API prefix compatibility

The explicit managed transport unnecessarily rejected the existing Full API base
`/backend`. Accept simple configured path segments, retain the exact configured
base in routing and permission values, and continue to reject encoded/traversal/
query/fragment ambiguity. Verified loopback TLS uses a synthetic equivalent of
Caddy handle_path and preserves signed claim/result/stop/observation receipts.
No live routing, issuer, enrollment, worker, containment or architecture changes.
