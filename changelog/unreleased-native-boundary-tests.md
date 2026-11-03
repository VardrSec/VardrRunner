# Unreleased - portable native boundary regressions

Add portable fake-WinAPI tests for permission-before-creation ordering, job and
inherited-handle allowlists, pre/post-creation cleanup, confirmed versus uncertain
termination, process liveness, membership validation/races and bounded snapshot
retries. The fakes load no native DLL and launch no process. Windows kernel and ABI
containment still require the existing real Windows tests. Preserve the 95% suite
coverage floor, native runtime code and unsupported-platform refusal.
