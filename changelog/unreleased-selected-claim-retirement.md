# Selected first-claim retirement inspection

Fix offline worker-state inspection after the server committed the first claim
and the reply was lost. The original authenticated observation may prove server
sequence one while the local cursor correctly remains zero. Require that exact
single selected-only retirement, unchanged association and no local attempt or
consumption. Keep the existing equality requirement for every other path.

This changes inspection only. It sends no request, creates no acknowledgement or
attempt, changes no journal state, and adds no installed failure-path acceptance.
