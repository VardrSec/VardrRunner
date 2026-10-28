# Unreleased — reliable Go source downloads

Independent toolkit builds repeatedly failed while fetching and verifying unchanged
modules with HTTP/2 `INTERNAL_ERROR` stream resets from `proxy.golang.org` and
`sum.golang.org`. The source builders use Go's documented `http2client=0` switch to
download over HTTPS/HTTP/1.1. This is a transport workaround, not a verification bypass:
the reviewed module proxy, public checksum database, compiler, versions, source patches,
binary provenance checks and runtime integrity checks are unchanged. Download failures
still fail the build. No setting is copied into the runtime image; container CI asserts it.

See [Go's HTTP transport documentation](https://pkg.go.dev/net/http#hdr-HTTP_2).
