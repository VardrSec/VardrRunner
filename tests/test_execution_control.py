"""Real owned process fixtures; no scanner, target traffic, or retained state."""

import json
import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from vardrrunner import config, runner
from vardrrunner import execution_control as control
from vardrrunner.journal import Journal, JournalError, Phase
from vardrrunner.recovery import reconcile


def actually_alive(pid):
    if os.name == "nt":
        from vardrrunner.windows_job import process_running

        return process_running(pid)
    return runner._pid_alive(pid)


def permission(*, seconds=10, stop=lambda: False, refresh=None, grace=0.15):
    return control.Control(
        refresh or (lambda: {"job_id": "one", "action": "continue", "lease_seconds": 10}),
        {"job_id": "one"},
        seconds,
        started=time.monotonic(),
        local_stop=stop,
        grace=grace,
    )


def test_before_launch_local_stop_and_expiry():
    for value in (permission(stop=lambda: True), permission(seconds=-1)):
        with patch("subprocess.Popen") as spawn:
            with pytest.raises(control.ExecutionStopped) as exc:
                control.run(["unused"], 5, None, value)
            assert exc.value.confirmed
            spawn.assert_not_called()


@pytest.mark.parametrize(
    "response",
    [
        {"job_id": "other", "action": "continue", "lease_seconds": 10},
        {"job_id": "one", "action": "continue", "lease_seconds": True},
        {"job_id": "one", "action": "continue", "lease_seconds": 100},
    ],
)
def test_wrong_binding_or_invalid_lease_never_renews(response):
    value = permission(seconds=0.7, refresh=lambda: response)
    with value:
        time.sleep(0.8)
        assert value.stop_reason() == "control_lease_expired"


def test_delayed_response_cannot_resurrect_lease():
    release = threading.Event()
    value = permission(
        seconds=0.7,
        refresh=lambda: (
            (release.wait(3) or True)
            and {"job_id": "one", "action": "continue", "lease_seconds": 10}
        ),
    )
    with value:
        time.sleep(0.8)
        release.set()
        time.sleep(0.1)
        assert value.stop_reason() == "control_lease_expired"


def test_remote_stop_is_sticky():
    value = permission(refresh=lambda: {"job_id": "one", "action": "cancel", "lease_seconds": 10})
    with value:
        time.sleep(0.7)
        assert value.stop_reason() == "remote_stop_requested"


def test_uncertain_kill_is_not_reported_confirmed():
    process = Mock()
    process.active.return_value = True
    process.force.side_effect = OSError("denied")
    assert not control._stop(process, 0)


def test_unverified_platform_never_spawns(monkeypatch):
    monkeypatch.setattr(control, "available", lambda: False)
    with pytest.raises(control.ExecutionStopped, match="unsupported"):
        control.run(["unused"], 5, None, permission())


@pytest.mark.skipif(os.name != "nt", reason="Windows native launch preparation")
def test_lease_expiring_during_native_launch_preparation(tmp_path, monkeypatch):
    output = tmp_path / "never-started"
    original = config.tool_environment

    def preparation():
        time.sleep(0.1)
        return original()

    monkeypatch.setattr(config, "tool_environment", preparation)
    with pytest.raises(control.ExecutionStopped, match="expired") as exc:
        control.run(
            [sys.executable, "-c", f"open({str(output)!r},'w').write('bad')"],
            5,
            None,
            permission(seconds=0.05),
        )
    assert exc.value.confirmed
    assert not output.exists()


def test_gate_private_files_removed_on_prelaunch_stop(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(runner, "program", lambda _: "unused")
    with control.controlled(permission(stop=lambda: True)):
        with pytest.raises(control.ExecutionStopped):
            runner.run_vardrgate(
                {"config": {"test_case": {}}},
                tmp_path / "result.json",
                request_guard={"synthetic": True},
            )
    assert list(tmp_path.iterdir()) == []


def test_local_request_is_not_pid_kill_or_completion(tmp_path):
    store = Journal(tmp_path / "journal.db")
    record = store.begin(
        job_id="job",
        backend_url="http://localhost",
        engagement_id="eng",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
        command_profile={"controlled": True},
    )
    store.request_stop(record.run_id)
    assert store.stop_requested(record.run_id)
    assert store.get(record.run_id).phase == Phase.DISCOVERED
    client = Mock()
    assert reconcile(store, client, "http://localhost").deferred == 1
    client.complete_job.assert_not_called()
    with pytest.raises(JournalError):
        store.request_stop("other-run")


TREE = r"""
import json, os, signal, subprocess, sys, time
from pathlib import Path
root, depth, refuse, orphan = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4] == "1"
def stopped(*_):
    if not refuse:
        (root / (str(depth) + ".graceful")).write_text("stopped")
        raise SystemExit(0)
signal.signal(signal.SIGTERM, stopped)
if hasattr(signal, "SIGBREAK"): signal.signal(signal.SIGBREAK, stopped)
child = subprocess.Popen([sys.executable, __file__, str(root), str(depth-1), sys.argv[3], sys.argv[4]]) if depth else None
(root / (str(depth) + ".pid")).write_text(str(os.getpid()))
(root / (str(depth) + ".partial")).write_text("incomplete evidence")
if child:
    while not (root / (str(depth-1) + ".pid")).exists(): time.sleep(.01)
if orphan and depth == 2:
    while not (root / "0.partial").exists(): time.sleep(.01)
    raise SystemExit(0)
while True: time.sleep(.02)
"""


@pytest.mark.parametrize("mode", ["emergency", "lease", "observer", "orphan", "timeout"])
@pytest.mark.skipif(os.name != "nt", reason="controlled containment currently native Windows only")
def test_real_child_and_grandchild_termination(tmp_path, mode):
    script = tmp_path / "tree.py"
    script.write_text(TREE)

    def ready():
        return len(list(tmp_path.glob("*.partial"))) == 3

    release = threading.Event()

    def refresh():
        release.wait(15)  # Deliberately blocked network equivalent, independent of tool monitor.
        raise OSError("disconnected")

    value = permission(
        seconds=1.4 if mode == "lease" else 10,
        stop=(lambda: ready()) if mode == "emergency" else (lambda: False),
        refresh=refresh,
    )

    def observed(_):
        if mode == "observer":
            until = time.monotonic() + 5
            while not ready() and time.monotonic() < until:
                time.sleep(0.02)
            raise RuntimeError("journal refused PID")

    try:
        with value:
            expected = RuntimeError if mode == "observer" else control.ExecutionStopped
            with pytest.raises(expected) as exc:
                control.run(
                    [
                        sys.executable,
                        str(script),
                        str(tmp_path),
                        "2",
                        "1",
                        "1" if mode == "orphan" else "0",
                    ],
                    1 if mode == "timeout" else 8,
                    observed,
                    value,
                )
            if isinstance(exc.value, control.ExecutionStopped) and os.name == "nt":
                assert exc.value.confirmed
        assert ready(), "all three real processes must have written partial evidence"
        for path in tmp_path.glob("*.pid"):
            assert not actually_alive(int(path.read_text())), path.name
        assert all(path.read_text() == "incomplete evidence" for path in tmp_path.glob("*.partial"))
    finally:
        release.set()


@pytest.mark.skipif(os.name != "nt", reason="controlled containment currently native Windows only")
def test_ordinary_exit_and_temp_cleanup(tmp_path):
    output = tmp_path / "finished"
    temp = tmp_path / "targets"
    temp.write_text("synthetic")
    value = permission()
    with control.controlled(value):
        assert (
            runner._run_tool_status(
                [sys.executable, "-c", f"open({str(output)!r}, 'w').write('done')"],
                str(temp),
                "fixture",
                5,
            )
            == 0
        )
    assert output.read_text() == "done"
    assert not temp.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows kernel job boundary")
def test_windows_contains_breakaway_attempt_and_does_not_inherit_secret_environment(
    tmp_path, monkeypatch
):
    from vardrrunner.windows_job import WindowsJob

    output = tmp_path / "result.json"
    monkeypatch.setenv("VARDRMAP_API_KEY", "synthetic-not-for-child")
    code = f"""import json, os, subprocess, sys
try:
 child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'], creationflags=0x1000000)
 pid = child.pid
except OSError:
 pid = None
open({str(output)!r}, 'w').write(json.dumps([pid, os.getenv('VARDRMAP_API_KEY')]))
import time; time.sleep(5)
"""
    process = WindowsJob([sys.executable, "-c", code], config.tool_environment())
    try:
        until = time.monotonic() + 3
        while not output.exists() and time.monotonic() < until:
            time.sleep(0.02)
        pid, secret = json.loads(output.read_text())
        assert secret is None
        assert pid is None or process.contains(pid)
        assert control._stop(process, 0.1)
        assert pid is None or not actually_alive(pid)
    finally:
        process.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows console and Job Object lifecycle")
@pytest.mark.parametrize("crash", [False, True])
def test_windows_real_graceful_tree_and_owner_crash(tmp_path, crash):
    import subprocess

    tree = tmp_path / "tree.py"
    tree.write_text(TREE)
    helper = tmp_path / "owner.py"
    receipt = tmp_path / "receipt.json"
    helper.write_text(f"""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
from vardrrunner import execution_control as control
root=Path({str(tmp_path)!r})
def stop():
    ready=len(list(root.glob("*.partial"))) == 3
    if ready and {crash!r}: os._exit(7)
    return ready
permission=control.Control(lambda: {{"action":"continue","lease_seconds":10}}, {{}}, 10,
    started=time.monotonic(), local_stop=stop, grace=2)
try:
    with permission:
        control.run([sys.executable, {str(tree)!r}, str(root), "2", "0", "0"], 8, None, permission)
except control.ExecutionStopped as exc:
    Path({str(receipt)!r}).write_text(json.dumps({{"confirmed":exc.confirmed}}))
""")
    startup = subprocess.STARTUPINFO()
    startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    process = subprocess.Popen(
        [sys.executable, str(helper)],
        startupinfo=startup,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        env=config.tool_environment(),
    )
    assert process.wait(timeout=12) == (7 if crash else 0)
    until = time.monotonic() + 2
    while (
        any(actually_alive(int(p.read_text())) for p in tmp_path.glob("*.pid"))
        and time.monotonic() < until
    ):
        time.sleep(0.05)
    assert len(list(tmp_path.glob("*.pid"))) == 3
    assert all(not actually_alive(int(p.read_text())) for p in tmp_path.glob("*.pid"))
    if not crash:
        assert json.loads(receipt.read_text())["confirmed"]
        assert len(list(tmp_path.glob("*.graceful"))) == 3
