"""Portable WinAPI contract tests; no native DLL, process, or target is contacted.

These exercise failure/ownership decisions, not Windows ABI or kernel containment.
The real Windows process-tree tests remain the containment acceptance evidence.
"""

import ctypes
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vardrrunner import execution_control, launch_guard, windows_job


class Kernel:
    def __init__(self):
        self.error = 5
        self.pids = [301, 302]
        self.inside = True
        self.running = False
        self.active_count = 0
        self.events = []
        self.creation = None
        for name in (
            "CreateJobObjectW",
            "CloseHandle",
            "SetInformationJobObject",
            "QueryInformationJobObject",
            "InitializeProcThreadAttributeList",
            "UpdateProcThreadAttribute",
            "DeleteProcThreadAttributeList",
            "CreateFileW",
            "CreateProcessW",
            "GenerateConsoleCtrlEvent",
            "TerminateJobObject",
            "GetExitCodeProcess",
            "WaitForSingleObject",
            "IsProcessInJob",
            "OpenProcess",
        ):
            callback = getattr(self, "_" + name, None)
            setattr(self, name, Mock(side_effect=callback) if callback else Mock(return_value=True))
        self.CreateJobObjectW.return_value = 100
        self.CreateFileW.return_value = 103

    def _InitializeProcThreadAttributeList(self, attributes, count, flags, size):
        size._obj.value = 128
        return attributes is not None

    def _CreateProcessW(self, executable, command, *_args):
        inherit, flags, env, cwd, startup, info = _args[2:]
        self.events.append("create")
        self.creation = {
            "executable": executable,
            "command": command.value,
            "inherit": inherit,
            "flags": flags,
            "environment": ctypes.wstring_at(ctypes.addressof(env), len(env)),
            "cwd": cwd,
            "startup": startup._obj,
        }
        info._obj.process, info._obj.thread = 101, 102
        info._obj.pid = 301
        return True

    def _IsProcessInJob(self, handle, job, inside):
        inside._obj.value = self.inside
        return True

    def _WaitForSingleObject(self, handle, timeout):
        return 0x102 if self.running else 0

    def _GetExitCodeProcess(self, handle, code):
        code._obj.value = 7
        return True

    def _OpenProcess(self, access, inherit, pid):
        return pid + 1000

    def _QueryInformationJobObject(self, job, kind, buffer, size, _used):
        if kind == 1:
            buffer._obj.active = self.active_count
        else:
            ctypes.c_uint32.from_buffer(buffer).value = len(self.pids)
            ctypes.c_uint32.from_buffer(buffer, 4).value = len(self.pids)
            for index, pid in enumerate(self.pids):
                ctypes.c_size_t.from_buffer(
                    buffer, 8 + index * ctypes.sizeof(ctypes.c_size_t)
                ).value = pid
        return True


@pytest.fixture
def kernel(monkeypatch):
    api = Kernel()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: api, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: api.error, raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", lambda code: OSError(code, "synthetic API error"), raising=False
    )
    # Windows DWORD/BOOL remain 32 bits on an LP64 test host. No native ABI claim.
    types = {name: getattr(windows_job.w, name) for name in dir(windows_job.w)}
    types.update(DWORD=ctypes.c_uint32, BOOL=ctypes.c_int32)
    monkeypatch.setattr(windows_job, "w", SimpleNamespace(**types))
    monkeypatch.setattr(windows_job.shutil, "which", lambda _: "C:/fixture/tool.exe")
    return api


def create():
    return windows_job.WindowsJob(["fixture", "argument with spaces"], {"Z": "last", "A": "first"})


def closed(api):
    return [call.args[0] for call in api.CloseHandle.call_args_list]


def test_creation_binds_job_and_handle_allowlist_before_permission_and_process(kernel):
    @contextmanager
    def gate():
        kernel.events.append("enter")
        yield
        kernel.events.append("exit")

    with launch_guard.install(gate):
        job = windows_job.WindowsJob(
            ["fixture", "argument with spaces"],
            {"Z": "last", "A": "first"},
            lambda: kernel.events.append("permit"),
        )
    assert kernel.events == ["enter", "permit", "create", "exit"]
    limits = kernel.SetInformationJobObject.call_args.args[2]._obj
    assert limits.basic.flags == 0x2000  # kill-on-close; no breakaway
    attributes = kernel.UpdateProcThreadAttribute.call_args_list
    assert [(call.args[2], list(call.args[3])) for call in attributes] == [
        (0x2000D, [100]),
        (0x20002, [103]),
    ]
    assert kernel.creation["flags"] == 0x80000 | 0x400 | 0x200
    assert kernel.creation["inherit"] is True
    assert kernel.creation["command"] == 'C:/fixture/tool.exe "argument with spaces"'
    assert kernel.creation["environment"] == "A=first\0Z=last\0\0\0"
    startup = kernel.creation["startup"].startup
    assert (startup.stdin, startup.stdout, startup.stderr) == (103, 103, 103)
    assert closed(kernel) == [102, 103]
    assert kernel.DeleteProcThreadAttributeList.call_count == 1
    job.close()
    job.close()
    assert closed(kernel) == [102, 103, 100, 101]


@pytest.mark.parametrize(
    "failure", ["limits", "initialize", "job_attribute", "null", "handles", "permit", "create"]
)
def test_precreation_failure_never_leaves_owned_handles_or_starts_unpermitted_process(
    kernel, failure
):
    if failure == "limits":
        kernel.SetInformationJobObject.return_value = False
    elif failure == "initialize":
        kernel.InitializeProcThreadAttributeList.side_effect = [False, False]
    elif failure in ("job_attribute", "handles"):
        kernel.UpdateProcThreadAttribute.side_effect = (
            [False] if failure == "job_attribute" else [True, False]
        )
    elif failure == "null":
        kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
    elif failure == "create":
        kernel.CreateProcessW.side_effect = None
        kernel.CreateProcessW.return_value = False

    def permit():
        if failure == "permit":
            raise launch_guard.DeadlineExpired("synthetic expired permission")

    with pytest.raises((OSError, launch_guard.DeadlineExpired)):
        windows_job.WindowsJob(["fixture"], {}, permit)
    assert 100 in closed(kernel)
    assert 101 not in closed(kernel)
    assert kernel.CreateProcessW.call_count == (1 if failure == "create" else 0)
    assert kernel.DeleteProcThreadAttributeList.call_count == (
        0 if failure in ("limits", "initialize") else 1
    )
    assert (103 in closed(kernel)) == (failure in ("handles", "permit", "create"))


def test_job_creation_failure_never_attempts_launch(kernel):
    kernel.CreateJobObjectW.return_value = None
    with pytest.raises(OSError):
        create()
    kernel.CreateProcessW.assert_not_called()
    kernel.CloseHandle.assert_not_called()


def test_permission_revoked_after_launch_boundary_entry_never_creates_process(kernel):
    check = Mock(side_effect=[None, launch_guard.DeadlineExpired("synthetic revoked permission")])
    with launch_guard.revalidation(check):
        with pytest.raises(launch_guard.DeadlineExpired):
            create()
    assert check.call_count == 2
    kernel.CreateProcessW.assert_not_called()
    assert sorted(closed(kernel)) == [100, 103]


@pytest.mark.parametrize("stop_result", [True, False, "raises"])
def test_postcreation_containment_failure_reports_confirmed_or_uncertain_and_closes(
    kernel, monkeypatch, stop_result
):
    kernel.inside = False
    stop = Mock(return_value=stop_result)
    if stop_result == "raises":
        stop.side_effect = RuntimeError("synthetic observer failure")
    monkeypatch.setattr(execution_control, "_stop", stop)
    with pytest.raises(execution_control.ExecutionStopped) as exc:
        create()
    assert exc.value.pid == 301
    assert exc.value.confirmed is (stop_result is True)
    assert str(exc.value) == "post_creation_permission_failure"
    stop.assert_called_once()
    assert sorted(closed(kernel)) == [100, 101, 102, 103]


@pytest.mark.parametrize("status,expected", [(0, False), (0x102, True)])
def test_process_liveness_uses_wait_status_and_always_closes_handle(kernel, status, expected):
    kernel.WaitForSingleObject.side_effect = None
    kernel.WaitForSingleObject.return_value = status
    assert windows_job.process_running(301) is expected
    assert closed(kernel) == [1301]


@pytest.mark.parametrize("error", [87, 5])
def test_process_liveness_distinguishes_missing_pid_from_access_failure(kernel, error):
    kernel.error = error
    kernel.OpenProcess.side_effect = None
    kernel.OpenProcess.return_value = None
    if error == 87:
        assert windows_job.process_running(301) is False
    else:
        with pytest.raises(OSError):
            windows_job.process_running(301)
    kernel.WaitForSingleObject.assert_not_called()


def test_process_wait_failure_closes_handle_and_does_not_claim_exit(kernel):
    kernel.WaitForSingleObject.side_effect = None
    kernel.WaitForSingleObject.return_value = 0xFFFFFFFF
    with pytest.raises(OSError):
        windows_job.process_running(301)
    assert closed(kernel) == [1301]


def test_poll_and_active_preserve_running_parent_or_retained_descendant(kernel):
    job = create()
    assert job.poll() == 7
    assert job.active() is False
    kernel.running = True
    assert job.poll() is None
    assert job.active() is True
    kernel.running = False
    kernel.active_count = 1
    assert job.active() is True
    kernel.active_count = 0
    job.members = {302: 1302}
    kernel.WaitForSingleObject.side_effect = lambda handle, _: 0x102 if handle == 1302 else 0
    assert job.active() is True
    job.close()
    assert closed(kernel)[-1] == 1302


@pytest.mark.parametrize(
    "method", ["WaitForSingleObject", "GetExitCodeProcess", "QueryInformationJobObject"]
)
def test_polling_api_failure_cannot_report_confirmed_exit(kernel, method):
    job = create()
    function = getattr(kernel, method)
    function.side_effect = None
    function.return_value = 0xFFFFFFFF if method == "WaitForSingleObject" else False
    with pytest.raises(OSError):
        job.active() if method == "QueryInformationJobObject" else job.poll()
    job.close()


def test_members_are_retained_once_and_only_after_job_membership_verification(kernel):
    job = create()
    job.capture_members()
    job.capture_members()
    assert job.members == {301: 1301, 302: 1302}
    assert kernel.OpenProcess.call_count == 2
    kernel.inside = False
    kernel.pids = [303]
    job.capture_members()
    assert 303 not in job.members
    assert 1303 in closed(kernel)
    job.close()


@pytest.mark.parametrize("error", [87, 5])
def test_member_open_race_is_distinct_from_access_denial(kernel, error):
    job = create()
    kernel.error = error
    kernel.OpenProcess.side_effect = None
    kernel.OpenProcess.return_value = None
    if error == 87:
        job.capture_members()
        assert not job.members
    else:
        with pytest.raises(OSError):
            job.capture_members()
    job.close()


def test_failed_membership_query_closes_unverified_handle(kernel):
    job = create()
    kernel.IsProcessInJob.side_effect = None
    kernel.IsProcessInJob.return_value = False
    with pytest.raises(OSError):
        job.capture_members()
    assert job.members == {}
    assert 1301 in closed(kernel)
    job.close()


@pytest.mark.parametrize("mode", ["resize", "denied", "oversized", "unstable"])
def test_member_snapshot_resize_is_bounded_and_fails_closed(kernel, mode):
    job = create()
    query = kernel.QueryInformationJobObject.side_effect
    attempts = []

    def snapshot(handle, kind, buffer, size, used):
        attempts.append(size)
        if mode == "resize" and len(attempts) == 2:
            return query(handle, kind, buffer, size, used)
        kernel.error = 5 if mode == "denied" else 234
        ctypes.c_uint32.from_buffer(buffer).value = 100001 if mode == "oversized" else 70
        return False

    kernel.QueryInformationJobObject.side_effect = snapshot
    if mode == "resize":
        job.capture_members()
        assert len(attempts) == 2 and attempts[1] > attempts[0]
        assert len(job.members) == 2
    else:
        with pytest.raises(OSError):
            job.capture_members()
        assert len(attempts) == (3 if mode == "unstable" else 1)
        assert not job.members
    job.close()


def test_graceful_capture_precedes_signal_and_force_still_terminates_when_capture_fails(kernel):
    job = create()
    job.graceful()
    assert job.members
    kernel.GenerateConsoleCtrlEvent.assert_called_once_with(1, 301)
    kernel.QueryInformationJobObject.side_effect = None
    kernel.QueryInformationJobObject.return_value = False
    kernel.error = 5
    with pytest.raises(OSError):
        job.force()
    kernel.TerminateJobObject.assert_called_once_with(100, 1)
    job.close()


@pytest.mark.parametrize("inside", [True, False, "error"])
def test_contains_always_closes_temporary_handle(kernel, inside):
    job = create()
    kernel.inside = inside
    if inside == "error":
        kernel.IsProcessInJob.side_effect = None
        kernel.IsProcessInJob.return_value = False
        with pytest.raises(OSError):
            job.contains(303)
    else:
        assert job.contains(303) is inside
    assert closed(kernel)[-1] == 1303
    job.close()
