# Unreleased — control consolidation portability

Linux-hosted mypy correctly lacks the Windows-only `ctypes.get_last_error`
declaration. Annotate the three native error branches consistently with existing
Windows-only ctypes declarations; there is no runtime change or fallback. Both Linux and
Windows static targets are checked. Existing native regression tests cover the
runtime branches. This does not enable Linux controlled execution.
