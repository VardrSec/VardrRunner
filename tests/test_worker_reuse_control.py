"""Refresh reuse metadata with bounded ordinary threads; no native execution."""

import threading
import time
from unittest.mock import Mock

import pytest

from vardrrunner.authorization.codec import AuthorizationError
from vardrrunner.execution_control import Control


@pytest.mark.parametrize(
    "failure",
    ["transport", "validation", "binding", "lease", "cancel", "malformed"],
)
def test_rejected_refresh_latches_reuse_without_extending_last_lease(failure):
    called = threading.Event()

    def refresh():
        called.set()
        value._close.set()
        if failure == "transport":
            raise OSError("synthetic transport failure")
        if failure == "validation":
            raise AuthorizationError("synthetic validated callback refusal")
        if failure == "malformed":
            return None
        return {
            "job_id": "other" if failure == "binding" else "one",
            "lease_seconds": True if failure == "lease" else 10,
            "action": "cancel" if failure == "cancel" else "continue",
        }

    value = Control(
        refresh, {"job_id": "one"}, 5, started=time.monotonic(), local_stop=lambda: False
    )
    before = value.deadline
    with value:
        assert called.wait(2)
        value.quiesce(time.monotonic() + 2)
    assert value.worker_quiescent() and not value.worker_reuse_safe()
    assert value.deadline == before
    assert value.stop_reason() == ("remote_stop_requested" if failure == "cancel" else "")


def test_later_valid_refresh_preserves_legacy_renewal_but_never_clears_reuse_failure():
    succeeded = threading.Event()
    calls = []

    def refresh():
        calls.append(True)
        if len(calls) == 1:
            raise OSError("synthetic transient failure")
        value._close.set()
        succeeded.set()
        return {"job_id": "one", "lease_seconds": 10, "action": "continue"}

    value = Control(
        refresh, {"job_id": "one"}, 5, started=time.monotonic(), local_stop=lambda: False
    )
    before = value.deadline
    with value:
        assert succeeded.wait(3)
        value.quiesce(time.monotonic() + 2)
    assert len(calls) == 2 and value.deadline > before and not value.stop_reason()
    assert value.worker_quiescent() and not value.worker_reuse_safe()


def test_valid_refresh_remains_reusable_after_actual_thread_join():
    called = threading.Event()

    def refresh():
        called.set()
        value._close.set()
        return {"job_id": "one", "lease_seconds": 10, "action": "continue"}

    value = Control(
        refresh, {"job_id": "one"}, 5, started=time.monotonic(), local_stop=lambda: False
    )
    with value:
        assert called.wait(2)
        value.quiesce(time.monotonic() + 2)
    assert value.worker_quiescent() and value.worker_reuse_safe()


def test_base_exception_still_escapes_refresh_after_latching_reuse_failure():
    value = Control(
        Mock(side_effect=SystemExit(7)),
        {},
        5,
        started=time.monotonic(),
        local_stop=lambda: False,
    )
    value._close = Mock()
    value._close.wait.return_value = False
    before = value.deadline
    with pytest.raises(SystemExit) as error:
        value._refresh()
    assert error.value.code == 7
    assert not value.worker_reuse_safe() and value.deadline == before
