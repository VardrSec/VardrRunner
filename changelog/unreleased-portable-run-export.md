# Unreleased — partial single-run evidence export

`audit export-run RUN_ID --output NEW_DIRECTORY` creates one local redacted JSON
evidence copy using existing audit/manifest schemas. Source bytes and recorded
hash/size are checked before export; original provenance is kept separately from
the copy's digest and relative manifest paths. No original tool output is changed
or regraded, no run status is promoted, and no credentials, database or authority
store is copied.

This first increment requires supported POSIX directory-FD/no-follow/private-mode
controls. Windows artifact creation is explicitly unsupported pending a reviewed
equivalent; the required Windows-first NM-3 gate remains open. Existing audit
metadata behavior is unchanged. This is neither full workspace backup/import nor
independent validation or a guarantee that redaction found all sensitive content.
