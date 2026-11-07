# Managed confirmed-stop checkpoint retention

Accept the matching Gate's private `execution_in_progress` checkpoint only through
the existing trusted native confirmed-stop path. Revalidate reviewed identities,
expected roles and pending indexes, then stage a separate cancelled copy with the
original reviewed case hash. Preserve genuine completed observations and the
original file bytes. Normal return rejects an unfinished checkpoint.

No Map dialect, execution permission, retry, grace or deadline is added. Component
tests use inert Runner I/O; installed C01 evidence remains platform-specific and
does not close from this change.
