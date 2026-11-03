# Unreleased — Native control transport fault coverage

Add an explicit cross-repository fixture for real loopback control transport loss,
late responses and finalization acknowledgement ambiguity. It checks native tree
termination, retained partial files, cumulative accounting, ownership reservation
and journal reload without replay. No runtime or Map changes. This does not close
NM-2 or validate signed managed authorization, Gate execution or Linux/Docker
controlled execution. See [test bounds](../docs/nm2-native-faults.md).
