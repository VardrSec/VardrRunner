"""Single-purpose Windows 11 24H2+ evidence export I/O; no pathname fallback.

This adapter is an unaccepted candidate until native ACL and race tests pass.
It creates only the three export files; policy and serialization stay in audit.
"""

from __future__ import annotations

import ctypes
import re
from ctypes import wintypes as w
from pathlib import Path, PureWindowsPath


class WindowsExportError(RuntimeError):
    """Fixed safe codes only, never Win32/path/descriptor exception text."""


def _need(condition: object, code: str) -> None:
    if not condition:
        raise WindowsExportError(code)


def _path(value: Path | str) -> PureWindowsPath:
    raw = str(value).replace("/", "\\")
    _need(len(raw) < 240 and re.match(r"^[A-Za-z]:\\", raw), "windows_path_unsupported")
    components = raw[3:].split("\\") if raw[3:] else []
    for name in components:
        _need(
            name not in {"", ".", ".."}
            and not name.endswith((".", " "))
            and not re.search(r'[<>:"|?*\x00-\x1f]', name)
            and not re.fullmatch(
                r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", name, re.I
            ),
            "windows_path_unsupported",
        )
    return PureWindowsPath(raw)


class Security(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]


class Extended(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("attributes", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("qos", ctypes.c_uint32),
        ("security", ctypes.POINTER(Security)),
        ("template", w.HANDLE),
    ]


class FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class FileInfo(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("created", FileTime),
        ("accessed", FileTime),
        ("modified", FileTime),
        ("volume", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32),
        ("index_low", ctypes.c_uint32),
    ]


class Acl(ctypes.Structure):
    _fields_ = [
        ("revision", w.BYTE),
        ("reserved", w.BYTE),
        ("size", w.WORD),
        ("count", w.WORD),
        ("reserved2", w.WORD),
    ]


class Ace(ctypes.Structure):
    _fields_ = [("kind", w.BYTE), ("flags", w.BYTE), ("size", w.WORD), ("mask", ctypes.c_uint32)]


class WindowsExport:
    """Owned handles remain pinned until context exit; partial outputs are retained."""

    def __init__(self) -> None:
        self.handles: list[int] = []
        self.descriptor = ctypes.c_void_p()
        self.kernel = ctypes.WinDLL(  # type: ignore[attr-defined]
            "kernel32.dll", use_last_error=True, winmode=0x800
        )
        self.security = ctypes.WinDLL(  # type: ignore[attr-defined]
            "advapi32.dll", use_last_error=True, winmode=0x800
        )
        pointer = ctypes.c_void_p
        pp = ctypes.POINTER(pointer)
        signatures = {
            "CreateDirectory2W": (
                [
                    w.LPCWSTR,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.POINTER(Security),
                ],
                w.HANDLE,
            ),
            "CreateFile3": (
                [
                    w.LPCWSTR,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.POINTER(Extended),
                ],
                w.HANDLE,
            ),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "LocalFree": ([pointer], pointer),
            "GetCurrentProcess": ([], w.HANDLE),
            "GetFileType": ([w.HANDLE], ctypes.c_uint32),
            "GetDriveTypeW": ([w.LPCWSTR], w.UINT),
            "GetFileInformationByHandle": ([w.HANDLE, ctypes.POINTER(FileInfo)], w.BOOL),
            "GetVolumeInformationByHandleW": (
                [
                    w.HANDLE,
                    w.LPWSTR,
                    ctypes.c_uint32,
                    pointer,
                    pointer,
                    ctypes.POINTER(ctypes.c_uint32),
                    w.LPWSTR,
                    ctypes.c_uint32,
                ],
                w.BOOL,
            ),
            "ReadFile": (
                [w.HANDLE, pointer, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), pointer],
                w.BOOL,
            ),
            "WriteFile": (
                [w.HANDLE, pointer, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), pointer],
                w.BOOL,
            ),
            "FlushFileBuffers": ([w.HANDLE], w.BOOL),
            "SetFilePointerEx": ([w.HANDLE, ctypes.c_longlong, pointer, ctypes.c_uint32], w.BOOL),
        }
        security_signatures = {
            "OpenProcessToken": ([w.HANDLE, ctypes.c_uint32, ctypes.POINTER(w.HANDLE)], w.BOOL),
            "GetTokenInformation": (
                [w.HANDLE, ctypes.c_int, pointer, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)],
                w.BOOL,
            ),
            "ConvertSidToStringSidW": ([pointer, ctypes.POINTER(w.LPWSTR)], w.BOOL),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW": (
                [w.LPCWSTR, ctypes.c_uint32, pp, pointer],
                w.BOOL,
            ),
            "GetSecurityInfo": (
                [w.HANDLE, ctypes.c_int, ctypes.c_uint32, pp, pp, pp, pp, pp],
                ctypes.c_uint32,
            ),
            "GetSecurityDescriptorControl": (
                [pointer, ctypes.POINTER(w.WORD), ctypes.POINTER(ctypes.c_uint32)],
                w.BOOL,
            ),
            "GetAce": ([pointer, ctypes.c_uint32, pp], w.BOOL),
        }
        try:
            for library, specs in ((self.kernel, signatures), (self.security, security_signatures)):
                for name, (arguments, result) in specs.items():
                    function = getattr(library, name)
                    function.argtypes, function.restype = arguments, result
            token = w.HANDLE()
            _need(
                self.security.OpenProcessToken(
                    self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)
                ),
                "windows_token_unavailable",
            )
            self._retain(token.value)
            required = ctypes.c_uint32()
            self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
            _need(0 < required.value <= 65536, "windows_token_unavailable")
            buffer = ctypes.create_string_buffer(required.value)
            _need(
                self.security.GetTokenInformation(
                    token, 1, buffer, required, ctypes.byref(required)
                ),
                "windows_token_unavailable",
            )
            sid = ctypes.cast(buffer, pp).contents
            self.owner = self._sid(sid)
            self.trusted = {self.owner, "S-1-5-18", "S-1-5-32-544"}
            sddl = (
                "O:" + self.owner + "D:P" + "".join(f"(A;;FA;;;{s})" for s in sorted(self.trusted))
            )
            _need(
                self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, 1, ctypes.byref(self.descriptor), None
                ),
                "windows_security_unavailable",
            )
        except Exception:
            self.close()
            raise WindowsExportError("windows_api_or_security_unsupported") from None

    def __enter__(self) -> WindowsExport:
        return self

    def __exit__(self, kind, value, trace) -> None:
        self.close()

    def close(self) -> None:
        okay = True
        for handle in reversed(self.handles):
            okay = bool(self.kernel.CloseHandle(handle)) and okay
        self.handles.clear()
        if self.descriptor.value:
            okay = not self.kernel.LocalFree(self.descriptor) and okay
            self.descriptor = ctypes.c_void_p()
        _need(okay, "windows_handle_close_failed")

    def _retain(self, handle) -> int:
        _need(handle not in (None, 0, ctypes.c_void_p(-1).value), "windows_open_refused")
        self.handles.append(int(handle))
        return int(handle)

    def _sid(self, pointer) -> str:
        text = w.LPWSTR()
        _need(
            pointer and self.security.ConvertSidToStringSidW(pointer, ctypes.byref(text)),
            "windows_owner_unavailable",
        )
        try:
            return str(text.value)
        finally:
            self.kernel.LocalFree(text)

    def _permissions(self, handle: int, *, private: bool = False) -> None:
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        try:
            _need(
                self.security.GetSecurityInfo(
                    handle,
                    1,
                    5,
                    ctypes.byref(owner),
                    None,
                    ctypes.byref(dacl),
                    None,
                    ctypes.byref(descriptor),
                )
                == 0,
                "windows_security_unavailable",
            )
            owner_sid = self._sid(owner)
            _need(owner_sid in self.trusted, "windows_owner_unsupported")
            if not private:
                return
            control, revision = w.WORD(), ctypes.c_uint32()
            _need(owner_sid == self.owner and dacl.value, "windows_private_acl_unavailable")
            _need(
                self.security.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)
                ),
                "windows_private_acl_unavailable",
            )
            _need(control.value & 0x1004 == 0x1004, "windows_private_acl_unavailable")
            acl = ctypes.cast(dacl, ctypes.POINTER(Acl)).contents
            _need(acl.count == len(self.trusted), "windows_private_acl_unavailable")
            actual = set()
            for index in range(acl.count):
                ace = ctypes.c_void_p()
                _need(
                    self.security.GetAce(dacl, index, ctypes.byref(ace)),
                    "windows_private_acl_unavailable",
                )
                entry = ctypes.cast(ace, ctypes.POINTER(Ace)).contents
                _need(
                    entry.kind == 0
                    and entry.flags == 0
                    and entry.mask == 0x1F01FF
                    and entry.size >= 20,
                    "windows_private_acl_unavailable",
                )
                actual.add(self._sid(ctypes.c_void_p(int(ace.value or 0) + 8)))
            _need(actual == self.trusted, "windows_private_acl_unavailable")
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)

    def _info(self, handle: int, *, directory: bool = False) -> FileInfo:
        info = FileInfo()
        _need(
            self.kernel.GetFileType(handle) == 1
            and self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)),
            "windows_file_unsupported",
        )
        _need(
            not info.attributes & 0x400
            and bool(info.attributes & 0x10) == directory
            and (info.index_high or info.index_low),
            "windows_file_unsupported",
        )
        return info

    def _open(self, path: PureWindowsPath, *, directory: bool = False, create: bool = False) -> int:
        security = Security(ctypes.sizeof(Security), self.descriptor, False)
        flags = 0x10000 | 0x200000 | (0x2000000 if directory else 0)
        parameters = Extended(
            ctypes.sizeof(Extended), 0, flags, 0, ctypes.pointer(security) if create else None, None
        )
        handle = self._retain(
            self.kernel.CreateFile3(
                str(path),
                0x20080 if directory else 0x80020000 | (0x40000000 if create else 0),
                1,
                1 if create else 3,
                ctypes.byref(parameters),
            )
        )
        self._info(handle, directory=directory)
        self._permissions(handle, private=create)
        return handle

    def _parents(self, path: PureWindowsPath) -> None:
        _need(self.kernel.GetDriveTypeW(path.anchor) == 3, "windows_volume_unsupported")
        for ancestor in reversed((path, *path.parents)):
            handle = self._open(ancestor, directory=True)
            filesystem, flags = ctypes.create_unicode_buffer(32), ctypes.c_uint32()
            _need(
                self.kernel.GetVolumeInformationByHandleW(
                    handle, None, 0, None, None, ctypes.byref(flags), filesystem, len(filesystem)
                ),
                "windows_volume_unsupported",
            )
            _need(filesystem.value == "NTFS" and flags.value & 8, "windows_volume_unsupported")

    def _read(self, handle: int, maximum: int) -> bytes:
        data = bytearray()
        while len(data) <= maximum:
            buffer = ctypes.create_string_buffer(min(65536, maximum + 1 - len(data)))
            count = ctypes.c_uint32()
            _need(
                self.kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None),
                "windows_read_failed",
            )
            if not count.value:
                break
            data.extend(buffer.raw[: count.value])
        _need(len(data) <= maximum, "artifact_size_unsupported")
        return bytes(data)

    def read_source(self, root: Path, source: Path, maximum: int) -> bytes:
        root_path, source_path = _path(root), _path(source)
        _need(
            source_path.parent == root_path and source_path.suffix.lower() == ".json",
            "artifact_path_unsupported",
        )
        self._parents(root_path)
        handle = self._open(source_path)
        before = self._info(handle)
        _need(
            before.links == 1 and 0 < (before.size_high << 32 | before.size_low) <= maximum,
            "artifact_file_unsupported",
        )
        raw = self._read(handle, maximum)
        after = self._info(handle)
        # Access time is allowed to change during the read.
        fields = ("volume", "index_high", "index_low", "links", "size_high", "size_low")
        _need(
            all(getattr(before, key) == getattr(after, key) for key in fields)
            and bytes(before.modified) == bytes(after.modified),
            "artifact_changed",
        )
        return raw

    def publish(self, output: Path, payloads: tuple[bytes, bytes, bytes], fresh) -> None:
        target = _path(output)
        self._parents(target.parent)
        fresh()
        security = Security(ctypes.sizeof(Security), self.descriptor, False)
        directory = self._retain(
            self.kernel.CreateDirectory2W(str(target), 0x20081, 1, 1, ctypes.byref(security))
        )
        self._info(directory, directory=True)
        self._permissions(directory, private=True)
        for name, payload in zip(
            ("artifact.json", "audit.json", "manifest.json"), payloads, strict=True
        ):
            if name == "manifest.json":
                fresh()
                self._info(directory, directory=True)
                self._permissions(directory, private=True)
            handle = self._open(target / name, create=True)
            buffer, count = ctypes.create_string_buffer(payload), ctypes.c_uint32()
            _need(
                self.kernel.WriteFile(handle, buffer, len(payload), ctypes.byref(count), None)
                and count.value == len(payload),
                "windows_write_failed",
            )
            _need(self.kernel.FlushFileBuffers(handle), "windows_flush_failed")
            _need(self.kernel.SetFilePointerEx(handle, 0, None, 0), "windows_readback_failed")
            _need(self._read(handle, len(payload)) == payload, "export_integrity_mismatch")
