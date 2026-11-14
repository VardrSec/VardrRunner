"""Exact, offline local backport; no configurable replacement or crypto policy."""

import hashlib
import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MODULE = "github.com/google/go-github/v30"
VERSION = "v30.1.0"
REPLACEMENT = "/src/go-github-v30-patched"
ZIP_SHA256 = "34ccb01d56786a8f7eb876e82f33dc79034c9bd2ce863e182cae6544861a2a3d"
CHANGES_SHA256 = "1c70ed7ade3226b7287ed5840ced1c9ba9b1678e5589d9560cc9b679e10cce48"
PATCH_SHA256 = "59c13a21195b6669988125c561cbefd54e17924bdca79991ebc3f2e5f47ed8c3"
SOURCE_SHA256 = "6d24aa8e6bba4ff67130061191de4a46c10bd4fabbe3cfca389eba666b4e571a"
FILES = ("openpgp-source.tar", "openpgp-backport.patch", "openpgp-upstream.zip", "openpgp-LICENSE")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(archive, changes_dir, destination, evidence):
    if digest(archive) != ZIP_SHA256:
        raise ValueError("Unexpected go-github upstream archive")
    if (
        digest(changes_dir / "changes.json") != CHANGES_SHA256
        or digest(changes_dir / "backport.patch") != PATCH_SHA256
    ):
        raise ValueError("Unexpected reviewed backport")
    destination.mkdir(parents=True, exist_ok=False)
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = MODULE + "@" + VERSION + "/"
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            if not member.filename.startswith(prefix):
                raise ValueError("Unexpected source archive prefix")
            name = member.filename[len(prefix) :]
            p = PurePosixPath(name)
            if not name or p.is_absolute() or ".." in p.parts or "\\" in name:
                raise ValueError("Unsafe source member")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(member))
    for name, change in json.loads((changes_dir / "changes.json").read_text()).items():
        target = destination / name
        original = target.read_bytes() if target.exists() else b""
        # Byte ranges apply only to the exact pinned original, preserving all
        # unchanged upstream test fixtures without copying their bytes here.
        cursor = 0
        pieces = []
        for edit in change["edits"]:
            start, end = edit["start"], edit["end"]
            if (
                type(start) is not int
                or type(end) is not int
                or not cursor <= start <= end <= len(original)
            ):
                raise ValueError("Invalid reviewed source edit range")
            pieces.extend((original[cursor:start], edit["replacement"].encode()))
            cursor = end
        pieces.append(original[cursor:])
        content = b"".join(pieces)
        if (
            hashlib.sha256(original).hexdigest() != change["before_sha256"]
            or hashlib.sha256(content).hexdigest() != change["after_sha256"]
        ):
            raise ValueError("Unexpected source change")
        target.write_bytes(content)
    with (evidence / FILES[0]).open("xb") as out:
        with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in sorted(destination.rglob("*")):
                if path.is_file():
                    content = path.read_bytes()
                    entry = tarfile.TarInfo(path.relative_to(destination).as_posix())
                    entry.size = len(content)
                    entry.mode = 0o644
                    tar.addfile(entry, io.BytesIO(content))
    shutil.copyfile(changes_dir / "backport.patch", evidence / FILES[1])
    shutil.copyfile(archive, evidence / FILES[2])
    shutil.copyfile(destination / "LICENSE", evidence / FILES[3])
    verify(evidence)


def verify(evidence):
    for name, expected in zip(FILES[:3], (SOURCE_SHA256, PATCH_SHA256, ZIP_SHA256), strict=True):
        path = evidence / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError("OpenPGP source provenance differs from reviewed backport")
    with tarfile.open(evidence / FILES[0], "r:") as tar:
        license_bytes = tar.extractfile("LICENSE").read()
    if (evidence / FILES[3]).is_symlink() or (evidence / FILES[3]).read_bytes() != license_bytes:
        raise ValueError("OpenPGP license differs from reviewed source")
    return {
        "module": MODULE,
        "version": VERSION,
        "upstream_tag_commit": "371b0007be89061b4cf899dc2083dd08e3912c14",
        "upstream_module_sum": "h1:VLDx+UolQICEOKu2m4uAoMti1SxuEBAl7RSEG16L+Oo=",
        "replacement": REPLACEMENT,
        "upstream_zip_sha256": ZIP_SHA256,
        "patched_source_sha256": SOURCE_SHA256,
        "patch_sha256": PATCH_SHA256,
        "crypto_module": "github.com/ProtonMail/go-crypto",
        "crypto_version": "v1.5.2",
    }


if __name__ == "__main__":
    import sys

    prepare(*(Path(p) for p in sys.argv[1:]))


def verify_tests(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size < 2 * 1024 * 1024:
        raise ValueError("Missing or oversized OpenPGP test evidence")
    events = [json.loads(line) for line in path.read_text().splitlines()]
    required = {
        "TestGitService_CreateSignedCommitWithKey",
        "TestExpiredLegacySigningKeyRejected",
        "TestCryptoCompatibilityAudit",
    }
    passed = {e.get("Test") for e in events if e.get("Action") == "pass"}
    if (
        not required <= passed
        or any(e.get("Action") == "fail" for e in events)
        or not events
        or events[-1].get("Action") != "pass"
        or events[-1].get("Test")
        or events[-1].get("Package") != MODULE + "/github"
    ):
        raise ValueError("OpenPGP compatibility checks did not complete successfully")
