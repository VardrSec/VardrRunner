# Selected first-claim retirement inspection

Fix offline worker-state inspection after the server committed the first claim
and the reply was lost. The original authenticated observation may prove server
sequence one while the local cursor correctly remains zero. Require that exact
single selected-only retirement, unchanged association and no local attempt or
consumption. Keep the existing equality requirement for every other path.

This changes inspection only. It sends no request, creates no acknowledgement or
attempt, changes no journal state, and adds no installed failure-path acceptance.

The follow-up also covers a lost next claim after healthy released history. The
original N+1 observation can retire the selection while inspection retains local
cursor N and all N released attempts; no missing acknowledgement is invented.
Closed preclaim tombstones are retained without being counted as issued attempts.
The focused two-healthy-then-third-unknown JSON CLI regression is synthetic,
separate from installed response-loss and physical-exit acceptance.
