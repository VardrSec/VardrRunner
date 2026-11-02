# Unreleased — NM-1 authorization foundations

Add an opt-in reference contract specification and prototypes with bounded reusable
human approvals, single-use signed execution contracts and fixed-request Gate plans.
Legacy CLI/queue paths, case hashes and evidence semantics remain unchanged. No
managed worker, live lease/cancellation, installer or engagement migration is added.

The standalone library acceptance adapter uses the companion unreleased Gate
`--request-guard` flag. Existing CLI/queue calls do not pass that flag. Missing
capability fails closed; managed live execution remains unsupported.

Guarded execution honors a shorter signed execution-contract expiry as well as
approval/window limits. The existing subprocess adapter checks the UTC deadline
after local credential and private-file preparation and refuses an expired launch.
Legacy calls omit this internal deadline option and preserve their existing argv.
