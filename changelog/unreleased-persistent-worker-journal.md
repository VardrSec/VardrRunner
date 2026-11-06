# Persistent worker journal and original-key recovery

The inactive v3 candidate adds immutable admission and signed-64-bit attempt
metadata to the existing execution journal. Original-key observation `/4` and
retirement `/3` require the exact admission, selected job and canonical receipt;
later-job physical retirement never substitutes another job's completion.

Recovery retains unknown sends, original acknowledgments, artifacts and spent
allowances. It creates no execution handle and retries no mutation. Finite v1/v2
storage and wire formats remain supported. Matching unreleased Map v3 endpoints
are required. The reporting-lifetime decision, complete 95% suite and independent
Linux/Desktop platform/security acceptance remain open.
