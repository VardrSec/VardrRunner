## Unreleased — independent-process standalone workspace checks

Exercise the public workspace create/show/list commands in separate Python
processes with disposable profiles. Network connections and subprocess launches
are refused in each child, and the real keychain is disabled. Verify persistence
across restarts and that missing reads or invalid names do not initialize state.
These checks cover metadata independence; they do not certify recon, controlled
Gate execution, Linux containment or an installed distribution.
