Clarify that CLI/Python Path conversion can normalize dot and repeated-separator
input before validation. Actual absolute-path handle binding remains the Windows
security boundary. Add real Typer conversion coverage and distinguish raw adapter
tests from end-to-end CLI rejection claims. No production code or trust policy
changes; native Windows security acceptance remains open.
