# Standalone Gate and dormant recon cohort

Combine published Gate 2eabab8 and dormant recon ef21cff above base 2c1f3a4,
retaining shared ancestors once. Preserve Gate callback ordering and recon
profile rejection before side effects. No recon execution or Docker worker is
enabled. Native combined acceptance and hosted checks remain open.

This candidate excludes c1bfc18 journal/export/inventory changes and the unavailable
1320e5a temporary credential cleanup fix. It is neither a recovery nor a claim of
source equivalence to d0d01d2. Prior branch test results do not transfer to it.
