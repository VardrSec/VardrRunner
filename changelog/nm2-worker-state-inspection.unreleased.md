# Unreleased — explicit existing-worker inspection

Add the offline `worker-state` fixed-JSON inspection facade for six explicit
existing-state selections. Reuse full local-hold and unfinished-row validation in
one normal read-only WAL snapshot without constructors, migrations, cleanup,
credential lookup or network. Distinguish original-key-linked `retired`, genuine
association-free `empty_unissued`, and conservative `held`; incomplete counts and
holds are null. Public output excludes identity labels and raw journal documents.

A30-second cooperative inspection budget checks SQL and history scans without a
job-count ceiling or execution/startup budget change. Read-only SQLite may change
sidecars. Old images without the new contract are unsupported/held. Component
validation does not establish physical stop or a supported next-enable flow.
