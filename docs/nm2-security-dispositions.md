# NM-2 secret-scan false-positive disposition

Independent review classified two immutable historical gitleaks findings in
`tests/test_redaction.py` at commit `4890e31b9c783bcd631c63fc85b622c0e875047f`
as fixed synthetic inputs and negative-leak assertions in the redactor test.
They are not issued credentials and have no authentication authority.

`.gitleaksignore` records only those exact commit/path/rule/line fingerprints.
No rule, path, test directory or future commit is newly excluded. The default
scanner and inherited configuration remain unchanged. A fresh offline random
noncredential positive control is still detected as `generic-api-key`; its value
is redacted and retained only in restricted synthetic test artifacts.

This is a false-positive disposition, not a waiver for credential exposure or an
independent claim that the repository contains no secrets. Hosted CI and owner
release approval remain separate gates.
