## Unreleased — retire branch-only Windows diagnosis

Remove the temporary workflow restricted to the old Windows-diagnosis branch.
Its journal/WAL visibility and duration-window regressions remain in the normal
cross-platform test suite and required CI. This removes a stale diagnostic entry
point without removing behavioral or security coverage.
The normal CI workflow now also supports explicit dispatch on a candidate branch,
reusing its existing platform matrix instead of adding a second test pipeline.
