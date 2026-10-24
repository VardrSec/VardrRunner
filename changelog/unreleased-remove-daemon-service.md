# Unreleased — legacy daemon and service commands removed (breaking)

No VardrMap change is required.

## Removed

| Removed | Now |
|---|---|
| `vardrrunner daemon start\|stop\|status` | `No such command 'daemon'` |
| `vardrrunner service install\|uninstall\|status` | `No such command 'service'` |
| `vardrrunner init --install-service`, `--start-service`, `--no-start-service`, `--env-file` | `No such option` (exit 2) |
| `vardrrunner engagement-list` | use `vardrrunner engagements` |

Since 0.48.0 none of these could start work (ADR 0016). They existed only to clean up
installs from 0.47.0 or earlier. `doctor` also drops its `daemon` check.

## If you still have a startup service from 0.47.0 or earlier

Upgrading does not remove it. Remove it once by hand:

| OS | Command |
|---|---|
| Windows | `schtasks /End /TN VardrRunner` then `schtasks /Delete /TN VardrRunner /F` |
| Linux | `systemctl --user disable --now vardrrunner.service`, delete `~/.config/systemd/user/vardrrunner.service`, then `systemctl --user daemon-reload` |
| macOS | `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.vardrsec.vardrrunner.plist`, then delete the plist |

The leftover files `~/.vardrrunner.pid`, `~/.vardrrunner.log` and `~/.vardrmap/daemon.jsonl`
can be deleted.

## Stop-work in `jobs run`

When stop-work refuses a claim, the run skips that engagement's remaining jobs and prints
"Skipping this engagement's remaining jobs in this run." Other engagements still run. The
old message promised a 60-second recheck, which only the removed daemon ever did. The next
`jobs run` asks the backend again.

See the [ADR 0016 amendment](../docs/adr/0016-explicit-daemon-execution.md).
