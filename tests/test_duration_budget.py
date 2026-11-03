"""Allocation receipts and monotonic permission, with real native tree cleanup."""

import json
import os
import sys
import time
from unittest.mock import Mock, patch

import pytest

from vardrrunner import api, config, controlled_jobs, execution_control, launch_guard, runner


def owned(seconds):
    client = Mock(spec=api.VardrMapClient)
    client.base = "https://map.example.test"

    def claim(job, rid, **options):
        assert options == {"duration_seconds": seconds}
        return {
            "execution_control": {
                "job_id": job,
                "runner_id": rid,
                "origin": client.base,
                "lease_seconds": 10,
                "token": "synthetic-capability-" * 3,
                "duration_budget": {
                    "allocated_seconds": seconds,
                    "total_allocated_seconds": seconds,
                    "limit_seconds": seconds,
                },
            }
        }

    client.claim_controlled.side_effect = claim
    result = controlled_jobs.OwnedClient(client, duration_seconds=seconds)
    result.claim_job("duration-job")
    client.execution_control.side_effect = lambda *_: {
        **result.binding,
        "action": "continue",
        "lease_seconds": 10,
    }
    return result


@pytest.mark.parametrize("change", ["missing", "allocation", "boolean", "total", "limit"])
def test_mismatched_receipt_never_grants_permission(change):
    value = {"allocated_seconds": 3, "total_allocated_seconds": 3, "limit_seconds": 3}
    if change == "missing":
        value = None
    elif change == "allocation":
        value["allocated_seconds"] = 2
    elif change == "boolean":
        value["allocated_seconds"] = True
    else:
        value["total_allocated_seconds" if change == "total" else "limit_seconds"] = 1
    with patch.object(
        controlled_jobs, "_duration_matches", wraps=controlled_jobs._duration_matches
    ):
        client = Mock(spec=api.VardrMapClient)
        client.base = "https://map.example.test"
        client.claim_controlled.side_effect = lambda job, rid, **_: {
            "execution_control": {
                "job_id": job,
                "runner_id": rid,
                "origin": client.base,
                "lease_seconds": 10,
                "token": "synthetic-capability-" * 3,
                "duration_budget": value,
            }
        }
        instance = controlled_jobs.OwnedClient(client, duration_seconds=3)
        with pytest.raises(ValueError, match="no legacy fallback"):
            instance.claim_job("job")
        assert instance.control is None


@pytest.mark.parametrize("seconds", [True, 0, -1, 86401])
def test_invalid_local_allocation_never_contacts_map(seconds):
    client = Mock(spec=api.VardrMapClient)
    with pytest.raises(ValueError):
        controlled_jobs.OwnedClient(client, duration_seconds=seconds)
    client.claim_controlled.assert_not_called()


@pytest.mark.parametrize("entry", ["pending", "single"])
@pytest.mark.parametrize("seconds, controlled", [(3, False), (True, False), (0, True)])
def test_library_entry_cannot_drop_explicit_duration(entry, seconds, controlled):
    from rich.console import Console

    from vardrrunner import configs
    from vardrrunner.commands import jobs

    client = Mock(spec=api.VardrMapClient)
    with (
        patch.object(runner, "_spawn_tool") as spawn,
        pytest.raises(configs.ConfigError, match="duration budget"),
    ):
        if entry == "pending":
            jobs.execute_pending_jobs(
                client, Console(quiet=True), controlled=controlled, duration_budget=seconds
            )
        else:
            jobs._execute_one(
                client,
                Console(quiet=True),
                {},
                True,
                controlled=controlled,
                duration_budget=seconds,
            )
    assert client.mock_calls == []
    spawn.assert_not_called()


def test_monotonic_budget_signed_deadline_and_local_limit_compose(monkeypatch):
    clock, mono = [1000.0], [100.0]
    monkeypatch.setattr(launch_guard.time, "time", lambda: clock[0])
    monkeypatch.setattr(launch_guard.time, "monotonic", lambda: mono[0])
    with launch_guard.monotonic_deadline(110), launch_guard.monotonic_deadline(200):
        assert launch_guard.timeout(30) == 10
        assert launch_guard.timeout(3) == 3
        clock[0] = 9000  # No wall-clock dependency in an allocated budget.
        assert launch_guard.timeout(30) == 10
        with launch_guard.deadline(clock[0] + 5):
            assert launch_guard.timeout(30) == 5
            clock[0] -= 100
            mono[0] += 6
            with pytest.raises(launch_guard.DeadlineExpired):
                launch_guard.require_permission()
        assert launch_guard.timeout(30) == 4
    assert launch_guard.timeout(30) == 30


def test_claim_latency_cannot_renew_allocated_window(monkeypatch):
    mono = [100.0]
    monkeypatch.setattr(controlled_jobs.time, "monotonic", lambda: mono[0])
    instance = owned(3)
    mono[0] += 4
    with instance.monitor(lambda: False), patch("subprocess.Popen") as spawn:
        with pytest.raises(launch_guard.DeadlineExpired):
            launch_guard.require_permission()
        spawn.assert_not_called()


@pytest.mark.parametrize("first_success", [True, False])
def test_repeated_owned_claim_cannot_restart_clock_or_retry_unknown(monkeypatch, first_success):
    mono = [100.0]
    monkeypatch.setattr(controlled_jobs.time, "monotonic", lambda: mono[0])
    if first_success:
        instance = owned(3)
    else:
        client = Mock(spec=api.VardrMapClient)
        client.base = "https://map.example.test"
        client.claim_controlled.side_effect = OSError("synthetic lost response")
        instance = controlled_jobs.OwnedClient(client, duration_seconds=3)
        with pytest.raises(OSError):
            instance.claim_job("duration-job")
    mono[0] += 4
    with pytest.raises(ValueError, match="single-use"):
        instance.claim_job("duration-job")
    assert instance.started == 100
    assert instance.client.claim_controlled.call_count == 1
    if first_success:
        with instance.monitor(lambda: False), pytest.raises(launch_guard.DeadlineExpired):
            launch_guard.require_permission()


def test_concurrent_owned_calls_allow_one_attempt_only():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    client = Mock(spec=api.VardrMapClient)
    client.base = "https://map.example.test"
    client.claim_controlled.side_effect = lambda job, rid, **_: {
        "execution_control": {
            "job_id": job,
            "runner_id": rid,
            "origin": client.base,
            "lease_seconds": 10,
            "token": "synthetic-capability-" * 3,
            "duration_budget": {
                "allocated_seconds": 3,
                "total_allocated_seconds": 3,
                "limit_seconds": 3,
            },
        }
    }
    instance = controlled_jobs.OwnedClient(client, duration_seconds=3)
    barrier = threading.Barrier(2)

    def claim():
        barrier.wait(2)
        try:
            instance.claim_job("job")
            return "claimed"
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(lambda _: claim(), range(2))) == ["claimed", "refused"]
    assert client.claim_controlled.call_count == 1


def test_owned_monitor_requires_receipt_and_cannot_be_reentered():
    client = Mock(spec=api.VardrMapClient)
    client.base = "https://map.example.test"
    instance = controlled_jobs.OwnedClient(client, duration_seconds=3)
    with pytest.raises(ValueError, match="owned receipt"):
        with instance.monitor(lambda: False):
            raise AssertionError("monitor entered without receipt")
    instance = owned(3)
    with instance.monitor(lambda: False):
        pass
    with pytest.raises(ValueError, match="single-use"):
        with instance.monitor(lambda: False):
            raise AssertionError("monitor reentered")


def test_monitor_entry_is_reserved_before_constructor_delay(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    instance = owned(3)
    constructing, release = threading.Event(), threading.Event()
    original = execution_control.Control
    constructed = []

    def delayed(*args, **kwargs):
        constructed.append(True)
        constructing.set()
        assert release.wait(2)
        return original(*args, **kwargs)

    monkeypatch.setattr(execution_control, "Control", delayed)

    def enter():
        try:
            with instance.monitor(lambda: False):
                return "entered"
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(enter)
        try:
            assert constructing.wait(2)
            second = pool.submit(enter)
            assert second.result(timeout=1) == "refused"
        finally:
            release.set()
        assert first.result(timeout=2) == "entered"
    assert len(constructed) == 1


def test_failed_monitor_setup_cannot_restart_allocation(monkeypatch):
    instance = owned(3)
    factory = Mock(side_effect=RuntimeError("synthetic setup failure"))
    monkeypatch.setattr(execution_control, "Control", factory)
    with pytest.raises(RuntimeError):
        with instance.monitor(lambda: False):
            raise AssertionError("setup unexpectedly succeeded")
    with pytest.raises(ValueError, match="single-use"):
        with instance.monitor(lambda: False):
            raise AssertionError("failed setup restarted")
    factory.assert_called_once()


@pytest.mark.skipif(os.name != "nt", reason="native controlled runtime evidence only")
@pytest.mark.parametrize("mode", ["budget", "budget_forced", "per_job", "signed"])
def test_actual_native_tree_stops_at_strictest_window(tmp_path, monkeypatch, mode):
    from contextlib import nullcontext

    from vardrrunner.windows_job import process_running

    seconds = 1 if mode in {"budget", "budget_forced"} else 5
    instance = owned(seconds)
    created, stopping, stopped = [], [], []
    original_stop = execution_control._stop

    def measured_stop(process, grace):
        stopping.append(time.monotonic())
        confirmed = original_stop(process, grace)
        stopped.append(time.monotonic())
        return confirmed

    monkeypatch.setattr(execution_control, "_stop", measured_stop)
    parent, child, partial = tmp_path / "parent.pid", tmp_path / "child.pid", tmp_path / "partial"
    ignore = (
        "import signal;signal.signal(signal.SIGBREAK,signal.SIG_IGN);"
        if mode == "budget_forced"
        else ""
    )
    child_code = (
        ignore + f"import os,time;open({str(child)!r},'w').write(str(os.getpid()));time.sleep(15)"
    )
    code = (
        ignore
        + f"import os,time,subprocess,sys;subprocess.Popen([sys.executable,'-c',{child_code!r}]);open({str(parent)!r},'w').write(str(os.getpid()));open({str(partial)!r},'w').write('partial evidence');time.sleep(15)"
    )
    until = time.time() + 1
    started = time.monotonic()
    with (
        instance.monitor(lambda: False),
        launch_guard.deadline(until) if mode == "signed" else nullcontext(),
    ):
        with runner.observe_process(lambda _: created.append(time.monotonic())):
            with pytest.raises(execution_control.ExecutionStopped) as failure:
                runner._run_tool_status(
                    [sys.executable, "-c", code], None, "fixture", 1 if mode == "per_job" else 10
                )
    elapsed = time.monotonic() - started
    assert failure.value.confirmed
    assert str(failure.value) == ("tool_timeout" if mode == "per_job" else "authorization_deadline")
    assert parent.exists() and child.exists() and partial.read_text() == "partial evidence"
    assert not any(process_running(int(path.read_text())) for path in [parent, child])
    assert elapsed < 6  # 1s window + existing 2s grace/2s verification + scheduling margin.
    if mode == "budget_forced":
        assert stopped[0] - stopping[0] >= 1.9
    (tmp_path / "duration-observation.json").write_text(
        json.dumps(
            {
                "mode": mode,
                "allocated_seconds": seconds,
                "strictest_window_seconds": 1,
                "measured_until_verified_stop_seconds": elapsed,
                "cleanup_included": True,
                "all_processes_stopped": True,
                "partial_preserved": True,
                "measured_claim_and_preparation_seconds": created[0] - instance.started,
                "measured_process_runtime_until_stop_request_seconds": stopping[0] - created[0],
                "measured_cleanup_until_verified_stop_seconds": stopped[0] - stopping[0],
                "measured_request_start_until_verified_stop_seconds": stopped[0] - instance.started,
            }
        )
    )


@pytest.mark.skipif(os.name != "nt", reason="native controlled preparation boundary")
def test_expired_preparation_cannot_launch(tmp_path, monkeypatch):
    instance = owned(1)
    original_environment = config.tool_environment
    original_boundary = launch_guard.boundary
    entered = []
    from contextlib import contextmanager

    def slow_environment():
        time.sleep(1.15)
        return original_environment()

    @contextmanager
    def witness():
        with original_boundary():
            entered.append(True)
            yield

    monkeypatch.setattr(config, "tool_environment", slow_environment)
    monkeypatch.setattr(launch_guard, "boundary", witness)
    with instance.monitor(lambda: False), pytest.raises(runner.ToolTimeout, match="before launch"):
        runner._run_tool_status([sys.executable, "-c", "raise SystemExit(0)"], None, "fixture", 10)
    assert not entered
    (tmp_path / "duration-observation.json").write_text(
        json.dumps(
            {
                "mode": "preparation",
                "allocated_seconds": 1,
                "measured_request_and_preparation_seconds": time.monotonic() - instance.started,
                "creation_body_entries": 0,
            }
        )
    )


@pytest.mark.skipif(os.name != "nt", reason="native final permit callback")
def test_expiry_after_permit_callback_prevents_createprocess(tmp_path, monkeypatch):
    from vardrrunner import windows_job

    native_library = windows_job.ctypes.WinDLL
    creates = []

    def library(*args, **kwargs):
        library = native_library(*args, **kwargs)
        library.CreateProcessW = Mock(side_effect=AssertionError("must never create"))
        creates.append(library.CreateProcessW)
        return library

    monkeypatch.setattr(windows_job.ctypes, "WinDLL", library)
    instance = owned(1)
    with instance.monitor(lambda: False), pytest.raises(launch_guard.DeadlineExpired):
        windows_job.WindowsJob(
            [sys.executable, "-c", "raise SystemExit(0)"],
            config.tool_environment(),
            lambda: time.sleep(1.15),
        )
    assert len(creates) == 1
    creates[0].assert_not_called()
    (tmp_path / "duration-observation.json").write_text(
        json.dumps(
            {
                "mode": "permit_delay",
                "allocated_seconds": 1,
                "measured_request_and_permit_seconds": time.monotonic() - instance.started,
                "createprocess_calls": 0,
            }
        )
    )


@pytest.mark.skipif(os.name != "nt", reason="native grant lock and budget composition")
def test_grant_lock_delay_cannot_renew_duration_window(tmp_path, monkeypatch):
    import threading
    from contextlib import contextmanager

    from vardrrunner import credential_grants, handlers

    instance = owned(1)
    origin, reference = "http://127.0.0.1:19001", "DURATION_SYNTHETIC_REFERENCE"
    credential_grants.Store().approve(instance.base, "eng", origin, "env", reference, 60)
    case = {
        "request": {"method": "GET", "url": origin + "/object"},
        "identities": [{"id": "owner", "credential": {"type": "bearer", "value_env": reference}}],
    }
    held = threading.Event()
    original_boundary, entered = launch_guard.boundary, []

    def lock():
        with credential_grants.Store().transaction():
            held.set()
            time.sleep(1.15)

    @contextmanager
    def witness():
        with original_boundary():
            entered.append(True)
            yield

    monkeypatch.setattr(launch_guard, "boundary", witness)
    monkeypatch.setattr(runner, "program", lambda _: sys.executable)
    with credential_grants.required(instance.base), instance.monitor(lambda: False):
        handlers.check_gate_case(case, "eng")
        thread = threading.Thread(target=lock)
        thread.start()
        assert held.wait(2)
        try:
            with pytest.raises(runner.ToolTimeout, match="before launch"):
                runner.run_vardrgate(
                    {"config": {"test_case": case}}, tmp_path / "never-result.json"
                )
        finally:
            thread.join(3)
    assert not entered
    (tmp_path / "duration-observation.json").write_text(
        json.dumps(
            {
                "mode": "grant_lock_delay",
                "allocated_seconds": 1,
                "measured_request_and_lock_seconds": time.monotonic() - instance.started,
                "creation_body_entries": 0,
            }
        )
    )
