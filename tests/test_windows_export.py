"""Protocol tests are mocks, not native path/ACL security acceptance."""

import ctypes
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from vardrrunner import windows_export as mod


@pytest.mark.parametrize(
    "path",
    [
        r"relative\file",
        r"C:relative",
        r"\\server\share\file",
        r"\\?\C:\x",
        r"C:\a\..\b",
        r"C:\a\.\b",
        r"C:\x.",
        "C:\\x ",
        r"C:\a:b",
        r"C:\NUL.json",
        r"C:\COM1",
        r"C:\LPT².txt",
        "C:\\a\x00b",
        r"C:\a?b",
    ],
)
def test_unsupported_names(path):
    with pytest.raises(mod.WindowsExportError, match="windows_path_unsupported"):
        mod._path(path)


def test_path_and_native_layout():
    assert mod._path(r"C:\safe\run.json") == PureWindowsPath(r"C:\safe\run.json")
    assert mod._path("C:\\") == PureWindowsPath("C:\\")
    assert ctypes.sizeof(mod.FileInfo) == 52
    assert ctypes.sizeof(mod.Ace) == 8


@pytest.fixture
def adapter():
    io = object.__new__(mod.WindowsExport)
    io.handles = []
    io.descriptor = ctypes.c_void_p()
    io.owner = "S-1-5-21-100"
    io.trusted = {io.owner, "S-1-5-18", "S-1-5-32-544"}
    io.kernel = SimpleNamespace(CloseHandle=lambda h: True, LocalFree=lambda p: None)
    return io


@pytest.mark.parametrize("handle", [None, 0, ctypes.c_void_p(-1).value])
def test_invalid_handle(adapter, handle):
    with pytest.raises(mod.WindowsExportError, match="windows_open_refused"):
        adapter._retain(handle)
    assert not adapter.handles


def test_open_protocol(adapter, monkeypatch):
    calls = []

    def create(path, access, sharing, disposition, parameters):
        p = parameters._obj
        calls.append((path, access, sharing, disposition, p.flags, bool(p.security)))
        if p.security:
            assert not p.security.contents.inherit
        return 7

    adapter.kernel.CreateFile3 = create
    monkeypatch.setattr(adapter, "_info", lambda *a, **k: None)
    monkeypatch.setattr(adapter, "_permissions", lambda *a, **k: None)
    adapter._open(PureWindowsPath(r"C:\safe"), directory=True)
    adapter._open(PureWindowsPath(r"C:\safe\artifact.json"), create=True)
    assert calls[0][2:] == (1, 3, 0x2210000, False)
    assert calls[1][2:] == (1, 1, 0x210000, True)
    assert adapter.handles == [7, 7]


@pytest.mark.parametrize(
    "attributes,index,kind", [(0x400, 1, 1), (0x10, 1, 1), (0, 0, 1), (0, 1, 2)]
)
def test_file_kind_refusal(adapter, attributes, index, kind):
    adapter.kernel.GetFileType = lambda h: kind

    def info(h, target):
        target._obj.attributes = attributes
        target._obj.index_low = index
        return True

    adapter.kernel.GetFileInformationByHandle = info
    with pytest.raises(mod.WindowsExportError, match="windows_file_unsupported"):
        adapter._info(7)


def test_close_reverse_and_failure(adapter):
    calls = []
    adapter.handles = [1, 2]
    adapter.descriptor = ctypes.c_void_p(3)
    adapter.kernel.CloseHandle = lambda h: calls.append(h) or h == 1
    adapter.kernel.LocalFree = lambda p: calls.append(p.value)
    with pytest.raises(mod.WindowsExportError, match="windows_handle_close_failed"):
        adapter.close()
    assert calls == [2, 1, 3]
    assert not adapter.handles and not adapter.descriptor.value


def test_read_bound(adapter):
    def read(h, buffer, length, count, overlapped):
        buffer[0] = b"x"
        count._obj.value = 1
        return True

    adapter.kernel.ReadFile = read
    with pytest.raises(mod.WindowsExportError, match="artifact_size_unsupported"):
        adapter._read(1, 2)
    adapter.kernel.ReadFile = lambda h, b, length, c, o: True
    assert adapter._read(1, 2) == b""


def test_parent_protocol(adapter, monkeypatch):
    calls = []
    adapter.kernel.GetDriveTypeW = lambda anchor: 3

    def volume(h, name, n, serial, maximum, flags, filesystem, size):
        flags._obj.value = 8
        filesystem.value = "NTFS"
        return True

    adapter.kernel.GetVolumeInformationByHandleW = volume
    monkeypatch.setattr(adapter, "_open", lambda path, **k: calls.append(path) or 1)
    adapter._parents(PureWindowsPath(r"C:\one\two"))
    assert calls == [
        PureWindowsPath("C:\\"),
        PureWindowsPath(r"C:\one"),
        PureWindowsPath(r"C:\one\two"),
    ]
    adapter.kernel.GetDriveTypeW = lambda anchor: 4
    with pytest.raises(mod.WindowsExportError, match="windows_volume_unsupported"):
        adapter._parents(PureWindowsPath("C:\\"))


def test_source_protocol(adapter, monkeypatch):
    info = mod.FileInfo()
    info.links, info.index_low, info.size_low = 1, 1, 2
    monkeypatch.setattr(adapter, "_parents", lambda p: None)
    monkeypatch.setattr(adapter, "_open", lambda p: 1)
    monkeypatch.setattr(adapter, "_info", lambda h: info)
    monkeypatch.setattr(adapter, "_read", lambda h, n: b"{}")
    assert adapter.read_source(r"C:\safe", r"C:\safe\x.json", 8) == b"{}"
    info.links = 2
    with pytest.raises(mod.WindowsExportError, match="artifact_file_unsupported"):
        adapter.read_source(r"C:\safe", r"C:\safe\x.json", 8)


@pytest.mark.parametrize("failure", [None, "fresh", "write", "flush", "readback"])
def test_publication_protocol(adapter, monkeypatch, failure):
    events, reads = [], []
    monkeypatch.setattr(adapter, "_parents", lambda p: events.append("parents"))
    monkeypatch.setattr(adapter, "_info", lambda *a, **k: None)
    monkeypatch.setattr(adapter, "_permissions", lambda *a, **k: None)

    def directory(path, access, share, flags, security):
        assert share == 1 and flags == 1 and not security._obj.inherit
        events.append("directory")
        return 5

    adapter.kernel.CreateDirectory2W = directory
    monkeypatch.setattr(adapter, "_open", lambda p, **k: events.append(p.name) or 6)

    def write(h, b, n, c, o):
        c._obj.value = n
        reads.append(b.raw[:n])
        return failure != "write"

    adapter.kernel.WriteFile = write
    adapter.kernel.FlushFileBuffers = lambda h: failure != "flush"
    adapter.kernel.SetFilePointerEx = lambda *a: True
    monkeypatch.setattr(
        adapter, "_read", lambda h, n: b"bad" if failure == "readback" else reads[-1]
    )

    def fresh():
        events.append("fresh")
        if failure == "fresh" and events.count("fresh") == 2:
            raise mod.WindowsExportError("record_changed")

    if failure:
        with pytest.raises(mod.WindowsExportError):
            adapter.publish(r"C:\out", (b"artifact", b"audit", b"manifest"), fresh)
        assert "manifest.json" not in events
    else:
        adapter.publish(r"C:\out", (b"artifact", b"audit", b"manifest"), fresh)
        assert events == [
            "parents",
            "fresh",
            "directory",
            "artifact.json",
            "audit.json",
            "fresh",
            "manifest.json",
        ]


@pytest.mark.parametrize(
    "private,owner,control,mask,expected",
    [
        (False, "S-1-5-21-100", 0x1004, 0x1F01FF, True),
        (False, "S-1-5-21-999", 0x1004, 0x1F01FF, False),
        (True, "S-1-5-21-100", 0x1004, 0x1F01FF, True),
        (True, "S-1-5-18", 0x1004, 0x1F01FF, False),
        (True, "S-1-5-21-100", 4, 0x1F01FF, False),
        (True, "S-1-5-21-100", 0x1004, 1, False),
    ],
)
def test_permissions(adapter, monkeypatch, private, owner, control, mask, expected):
    acl = mod.Acl()
    acl.count = 3
    entries = [mod.Ace(0, 0, 20, mask) for _ in range(3)]
    sids = {
        1: owner,
        **{
            ctypes.addressof(e) + 8: sid
            for e, sid in zip(entries, sorted(adapter.trusted), strict=True)
        },
    }

    def security(h, kind, flags, own, group, dacl, sacl, sd):
        own._obj.value = 1
        dacl._obj.value = ctypes.addressof(acl)
        sd._obj.value = 2
        return 0

    def get_control(sd, ctrl, rev):
        ctrl._obj.value = control
        return True

    def get_ace(p, index, target):
        target._obj.value = ctypes.addressof(entries[index])
        return True

    adapter.security = SimpleNamespace(
        GetSecurityInfo=security, GetSecurityDescriptorControl=get_control, GetAce=get_ace
    )
    monkeypatch.setattr(adapter, "_sid", lambda p: sids[p.value])
    if expected:
        adapter._permissions(7, private=private)
    else:
        with pytest.raises(mod.WindowsExportError):
            adapter._permissions(7, private=private)


@pytest.mark.parametrize(
    "failure", [None, "missing", "token", "size", "token_read", "sid", "descriptor"]
)
def test_initialization_ownership_and_cleanup(monkeypatch, failure):
    calls = []

    class Function:
        def __init__(self, name):
            self.name = name

        def __call__(self, *args):
            calls.append((self.name, args))
            if self.name == "GetCurrentProcess":
                return -1
            if self.name == "OpenProcessToken":
                args[2]._obj.value = 11
                return failure != "token"
            if self.name == "GetTokenInformation":
                args[4]._obj.value = 0 if failure == "size" else 16
                if args[2] is not None:
                    ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p)).contents.value = 1
                    return failure != "token_read"
                return False
            if self.name == "ConvertSidToStringSidW":
                args[1]._obj.value = "S-1-5-21-100"
                return failure != "sid"
            if self.name == "ConvertStringSecurityDescriptorToSecurityDescriptorW":
                assert args[0].startswith("O:S-1-5-21-100D:P")
                args[2]._obj.value = 99
                return failure != "descriptor"
            if self.name == "LocalFree":
                return None
            return True

    class Library:
        def __init__(self):
            self.functions = {}

        def __getattr__(self, name):
            if failure == "missing" and name == "CreateFile3":
                raise AttributeError(name)
            if name not in self.functions:
                self.functions[name] = Function(name)
            return self.functions[name]

    libraries = []

    def load(name, **kwargs):
        assert kwargs == {"use_last_error": True, "winmode": 0x800}
        library = Library()
        libraries.append(library)
        return library

    monkeypatch.setattr(mod.ctypes, "WinDLL", load, raising=False)
    if failure:
        with pytest.raises(mod.WindowsExportError, match="windows_api_or_security_unsupported"):
            mod.WindowsExport()
    else:
        with mod.WindowsExport() as io:
            assert io.owner == "S-1-5-21-100"
            assert len(libraries[0].functions["CreateDirectory2W"].argtypes) == 5
            assert libraries[0].functions["CreateDirectory2W"].restype is mod.w.HANDLE
            assert io.handles == [11]
        assert not io.handles and not io.descriptor.value
    assert not any(name in {"CreateDirectory2W", "CreateFile3"} for name, _ in calls)


@pytest.mark.skipif(__import__("os").name != "nt", reason="requires native Windows")
def test_native_windows_export_requires_explicit_opt_in(tmp_path):
    import os

    if os.environ.get("VARDRRUNNER_WINDOWS_EXPORT_ACCEPTANCE") != "1":
        pytest.skip("set explicit synthetic native acceptance opt-in")
    source = tmp_path / "source"
    source.mkdir()
    artifact = source / "input.json"
    artifact.write_bytes(b'{"synthetic": true}')
    output = tmp_path / "export"
    with mod.WindowsExport() as io:
        assert io.read_source(source, artifact, 1024) == artifact.read_bytes()
        io.publish(output, (b"artifact", b"audit", b"manifest"), lambda: None)
        # Actual owner/DACL, volume, reparse/type checks have run, not mocks.
        assert (output / "manifest.json").read_bytes() == b"manifest"
        with pytest.raises(OSError):
            artifact.rename(source / "moved.json")
        with pytest.raises(OSError):
            (output / "artifact.json").write_bytes(b"changed")
    assert artifact.exists() and (output / "manifest.json").exists()
