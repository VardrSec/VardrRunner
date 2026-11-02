"""Windows 10+ process containment for explicitly controlled executions only.

CreateProcess assigns the job atomically through JOB_LIST before user code runs.
No breakaway flags, inherited job handle, shell, or third-party dependency.
"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
from collections.abc import Callable
from ctypes import wintypes as w

from vardrrunner import launch_guard


class Startup(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD),
        ("reserved", w.LPWSTR),
        ("desktop", w.LPWSTR),
        ("title", w.LPWSTR),
        ("x", w.DWORD),
        ("y", w.DWORD),
        ("xsize", w.DWORD),
        ("ysize", w.DWORD),
        ("xchars", w.DWORD),
        ("ychars", w.DWORD),
        ("fill", w.DWORD),
        ("flags", w.DWORD),
        ("show", w.WORD),
        ("reserved_size", w.WORD),
        ("reserved_data", w.LPBYTE),
        ("stdin", w.HANDLE),
        ("stdout", w.HANDLE),
        ("stderr", w.HANDLE),
    ]


class StartupEx(ctypes.Structure):
    _fields_ = [("startup", Startup), ("attributes", ctypes.c_void_p)]


class ProcessInfo(ctypes.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class Security(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]


class Limits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong),
        ("job_time", ctypes.c_longlong),
        ("flags", w.DWORD),
        ("min_working_set", ctypes.c_size_t),
        ("max_working_set", ctypes.c_size_t),
        ("active", w.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", w.DWORD),
        ("scheduling", w.DWORD),
    ]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", Limits),
        ("io", ctypes.c_ulonglong * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class Accounting(ctypes.Structure):
    _fields_ = [
        ("times", ctypes.c_longlong * 4),
        ("faults", w.DWORD),
        ("total", w.DWORD),
        ("active", w.DWORD),
        ("terminated", w.DWORD),
    ]


def process_running(pid: int) -> bool:
    """Distinguish an exited process object from a still-running process."""
    api = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    api.OpenProcess.argtypes, api.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
    api.WaitForSingleObject.argtypes, api.WaitForSingleObject.restype = [w.HANDLE, w.DWORD], w.DWORD
    api.CloseHandle.argtypes, api.CloseHandle.restype = [w.HANDLE], w.BOOL
    handle = api.OpenProcess(0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return False
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    try:
        result = api.WaitForSingleObject(handle, 0)
        if result not in (0, 0x102):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        return result == 0x102
    finally:
        api.CloseHandle(handle)


class WindowsJob:
    """Minimal owned process/job handles; callers must close in a finally block."""

    def __init__(
        self, cmd: list[str], environment: dict[str, str], permit: Callable[[], None] | None = None
    ):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "QueryInformationJobObject": (
                [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p],
                w.BOOL,
            ),
            "InitializeProcThreadAttributeList": (
                [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)],
                w.BOOL,
            ),
            "UpdateProcThreadAttribute": (
                [
                    ctypes.c_void_p,
                    w.DWORD,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
                w.BOOL,
            ),
            "DeleteProcThreadAttributeList": ([ctypes.c_void_p], None),
            "CreateFileW": (
                [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(Security), w.DWORD, w.DWORD, w.HANDLE],
                w.HANDLE,
            ),
            "CreateProcessW": (
                [
                    w.LPCWSTR,
                    w.LPWSTR,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    w.BOOL,
                    w.DWORD,
                    ctypes.c_void_p,
                    w.LPCWSTR,
                    ctypes.POINTER(StartupEx),
                    ctypes.POINTER(ProcessInfo),
                ],
                w.BOOL,
            ),
            "GenerateConsoleCtrlEvent": ([w.DWORD, w.DWORD], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "GetExitCodeProcess": ([w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
            "IsProcessInJob": ([w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
            "OpenProcess": ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.job = self.api.CreateJobObjectW(None, None)
        self.process = None
        self.members: dict[int, int] = {}
        self._check(self.job)
        attributes = None
        initialized = False
        null = None
        try:
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway permitted
            self._check(
                self.api.SetInformationJobObject(
                    self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
                )
            )
            size = ctypes.c_size_t()
            self.api.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            attributes = ctypes.create_string_buffer(size.value)
            self._check(
                self.api.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size))
            )
            initialized = True
            jobs = (w.HANDLE * 1)(self.job)
            self._check(
                self.api.UpdateProcThreadAttribute(
                    attributes, 0, 0x2000D, jobs, ctypes.sizeof(jobs), None, None
                )
            )
            security = Security(ctypes.sizeof(Security), None, True)
            null = self.api.CreateFileW("NUL", 0xC0000000, 3, ctypes.byref(security), 3, 0, None)
            if null == ctypes.c_void_p(-1).value:
                null = None
                self._check(False)
            handles = (w.HANDLE * 1)(null)
            self._check(
                self.api.UpdateProcThreadAttribute(
                    attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None
                )
            )
            startup = StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
            startup.startup.stdin = startup.startup.stdout = startup.startup.stderr = null
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            information = ProcessInfo()
            executable = shutil.which(cmd[0]) or cmd[0]
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline([executable, *cmd[1:]]))
            env = ctypes.create_unicode_buffer(
                "\0".join(f"{k}={v}" for k, v in sorted(environment.items())) + "\0\0"
            )
            with launch_guard.boundary():
                if permit:
                    permit()
                launch_guard.require_deadline()
                self._check(
                    self.api.CreateProcessW(
                        executable,
                        command,
                        None,
                        None,
                        True,
                        0x80000 | 0x400 | 0x200,
                        env,
                        None,
                        ctypes.byref(startup),
                        ctypes.byref(information),
                    )
                )
                self.process, self.pid = information.process, information.pid
                self.api.CloseHandle(information.thread)
            inside = w.BOOL()
            self._check(self.api.IsProcessInJob(self.process, self.job, ctypes.byref(inside)))
            self._check(inside.value)
        except BaseException:
            if self.process is not None:
                from vardrrunner.execution_control import ExecutionStopped, _stop

                try:
                    stopped = _stop(self, 0)
                except BaseException:
                    stopped = False
                finally:
                    self.close()
                raise ExecutionStopped(
                    "post_creation_permission_failure", stopped, pid=self.pid
                ) from None
            self.close()
            raise
        finally:
            if initialized:
                self.api.DeleteProcThreadAttributeList(attributes)
            if null:
                self.api.CloseHandle(null)

    @staticmethod
    def _check(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]

    def poll(self) -> int | None:
        status = self.api.WaitForSingleObject(self.process, 0)
        if status == 0x102:
            return None
        self._check(status == 0)
        code = w.DWORD()
        self._check(self.api.GetExitCodeProcess(self.process, ctypes.byref(code)))
        return code.value

    def active(self) -> bool:
        accounting = Accounting()
        self._check(
            self.api.QueryInformationJobObject(
                self.job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
            )
        )
        return (
            accounting.active != 0
            or self.poll() is None
            or any(self.api.WaitForSingleObject(handle, 0) != 0 for handle in self.members.values())
        )

    def capture_members(self) -> None:
        """Hold stable handles through termination; PID existence is not liveness."""
        count = 64
        for _ in range(3):
            buffer = ctypes.create_string_buffer(8 + count * ctypes.sizeof(ctypes.c_size_t))
            if self.api.QueryInformationJobObject(self.job, 3, buffer, len(buffer), None):
                length = w.DWORD.from_buffer(buffer, 4).value
                for index in range(length):
                    pid = ctypes.c_size_t.from_buffer(
                        buffer, 8 + index * ctypes.sizeof(ctypes.c_size_t)
                    ).value
                    if pid in self.members:
                        continue
                    handle = self.api.OpenProcess(0x101000, False, pid)
                    if not handle:
                        if ctypes.get_last_error() == 87:
                            continue
                        self._check(False)
                    inside = w.BOOL()
                    if not self.api.IsProcessInJob(handle, self.job, ctypes.byref(inside)):
                        self.api.CloseHandle(handle)
                        self._check(False)
                    if inside.value:
                        self.members[pid] = handle
                    else:
                        self.api.CloseHandle(handle)
                return
            if ctypes.get_last_error() != 234:
                self._check(False)
            count = w.DWORD.from_buffer(buffer).value + 64
            if count > 100000:
                break
        raise OSError("could not capture stable execution process handles")

    def graceful(self) -> None:
        self.capture_members()
        # An unattached console may refuse this; the caller still escalates.
        self.api.GenerateConsoleCtrlEvent(1, self.pid)

    def contains(self, pid: int) -> bool:
        handle = self.api.OpenProcess(0x1000, False, pid)
        self._check(handle)
        try:
            inside = w.BOOL()
            self._check(self.api.IsProcessInJob(handle, self.job, ctypes.byref(inside)))
            return bool(inside.value)
        finally:
            self.api.CloseHandle(handle)

    def force(self) -> None:
        try:
            self.capture_members()
        finally:
            self._check(self.api.TerminateJobObject(self.job, 1))

    def close(self) -> None:
        if self.job:
            self.api.CloseHandle(self.job)
            self.job = None
        if self.process:
            self.api.CloseHandle(self.process)
            self.process = None
        for handle in self.members.values():
            self.api.CloseHandle(handle)
        self.members.clear()
