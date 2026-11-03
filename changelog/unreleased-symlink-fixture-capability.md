Keep real symlink rejection tests and explicitly report the fixture unavailable
only for Windows symlink creation error 1314. A separate synthetic marker case
asserts the unchanged fail-closed guard and absence of RPCs. No OS proof is inferred
from the marker case or an unavailable real fixture; no runtime code changes.
