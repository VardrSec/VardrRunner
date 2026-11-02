"""Composition regressions, with actual permission callbacks and no subprocess."""

import pytest

from vardrrunner import launch_guard
from vardrrunner.execution_control import Control


@pytest.mark.parametrize("reverse", [False, True])
def test_nested_launch_revalidation_preserves_both_policies(reverse):
    checked = []
    checks = [lambda: checked.append("managed"), lambda: checked.append("grant")]
    if reverse:
        checks.reverse()
    with launch_guard.revalidation(checks[0]), launch_guard.revalidation(checks[1]):
        launch_guard.require_permission()
    assert checked == (["grant", "managed"] if reverse else ["managed", "grant"])


def test_expiring_outer_policy_is_rechecked_after_inner_preparation():
    valid = [True]

    def managed():
        if not valid[0]:
            raise ValueError("managed_permission_expired")

    with launch_guard.revalidation(managed), launch_guard.revalidation(lambda: None):
        valid[0] = False
        with pytest.raises(ValueError, match="managed_permission_expired"):
            launch_guard.require_permission()


def test_control_never_outlives_verified_absolute_cap(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("vardrrunner.execution_control.time.monotonic", lambda: clock[0])
    cap = [10.0]
    control = Control(
        lambda: {}, {}, 18, started=0, local_stop=lambda: False, lease_deadline=lambda: cap[0]
    )
    clock[0] = 11
    assert control.stop_reason() == "control_lease_expired"


@pytest.mark.parametrize("cap", [float("nan"), float("inf"), True, None])
def test_invalid_verified_cap_fails_closed(cap):
    control = Control(
        lambda: {}, {}, 10, started=0, local_stop=lambda: False, lease_deadline=lambda: cap
    )
    assert control.stop_reason() == "control_cap_unavailable"
