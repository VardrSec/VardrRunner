"""Keep a canonical Windows journal and its ancestors from being replaced.

This pins names while SQLite uses its ordinary pathname API. It does not make
SQLite reads non-mutating or prevent authorized writers changing database data.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes as w
from os import stat_result
from pathlib import Path

from vardrrunner.windows_export import FileInfo


class WindowsJournalError(RuntimeError):
    """Fixed journal-handle failures, without path or operating-system details."""


class WindowsJournalPin:
    """Retain non-inheritable, no-delete-sharing handles until SQLite closes."""

    def __init__(self, path: Path, *, create: bool, observed: stat_result | None = None):
        self.path = path
        self.create = create
        self.observed = observed
        self.handles: list[int] = []
        self.kernel = ctypes.WinDLL(  # type: ignore[attr-defined]
            "kernel32.dll", use_last_error=True, winmode=0x800
        )
        signatures = {
            "CreateFileW": (
                [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE],
                w.HANDLE,
            ),
            "GetFileType": ([w.HANDLE], w.DWORD),
            "GetFileInformationByHandle": ([w.HANDLE, ctypes.POINTER(FileInfo)], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = arguments, result

    def _open(self, path: Path, *, directory: bool = False) -> None:
        # Open every final component itself, rather than following a substituted
        # reparse point. Previously opened ancestors cannot be renamed/deleted.
        flags = 0x00200000 | (0x02000000 if directory else 0)
        create = self.create and self.observed is None and not directory
        handle = self.kernel.CreateFileW(
            str(path),
            0x80 | (0x40000000 if create else 0),  # attributes; write only for creation
            1 if directory else 3,  # read; database also shares legitimate writes
            None,
            1 if create else 3,  # CREATE_NEW / OPEN_EXISTING, never adopt a raced-in file
            flags,
            None,
        )
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            raise WindowsJournalError("journal_handle_unavailable")
        self.handles.append(int(handle))
        info = FileInfo()
        if (
            self.kernel.GetFileType(handle) != 1
            or not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
            or info.attributes & 0x400
            or bool(info.attributes & 0x10) != directory
            or not (info.index_high or info.index_low)
            or (not directory and info.links != 1)
        ):
            raise WindowsJournalError("journal_handle_unsupported")
        if not directory and self.observed is not None:
            actual = path.stat()
            if (actual.st_dev, actual.st_ino) != (self.observed.st_dev, self.observed.st_ino):
                raise WindowsJournalError("journal_identity_changed")

    def __enter__(self) -> WindowsJournalPin:
        try:
            for ancestor in reversed(self.path.parents):
                self._open(ancestor, directory=True)
            self._open(self.path)
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        okay = True
        for handle in reversed(self.handles):
            okay = bool(self.kernel.CloseHandle(handle)) and okay
        self.handles.clear()
        if not okay:
            raise WindowsJournalError("journal_handle_close_failed")

    def __exit__(self, kind, value, trace) -> None:
        self.close()
