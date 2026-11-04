# Unreleased — preserve MCP route authority

MCP rejects malformed route identifiers before HTTP dispatch. Previously an
identifier containing URL syntax could redirect proposal or read-only preview
POSTs to a withheld approval route when the configured key had sufficient scope.
All interpolated engagement and nested object IDs now use one literal-segment
check. UUIDs and legacy ASCII unreserved opaque IDs remain supported; encoded
forms and dot/dot-dot segments are refused without echoing input.

No tool, approval permission, backend endpoint, generic API behavior or credential
fallback is added. Offline tests intercept requests and use synthetic values;
they do not call an approval endpoint or mutate production state.
