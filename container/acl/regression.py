"""Exercise exact stripped cp/tar payloads; no target or network traffic."""

import argparse
import os
import subprocess
import tempfile
from pathlib import Path


def run(*args, env=None, allowed=(0,)):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
    if result.returncode not in allowed:
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr}")
    return result.stdout


def check(cp, tar, preload, vulnerable):
    with tempfile.TemporaryDirectory(prefix="vardr-acl-") as directory:
        root = Path(directory)
        source, outside_src, outside_dst = [root / n for n in ("src", "outside-src", "outside-dst")]
        for path, uid in ((source, 10001), (outside_src, 10002), (outside_dst, 10003)):
            path.mkdir()
            run("setfacl", "-m", f"d:u:{uid}:r-x", str(path))
        (source / "ordinary.txt").write_text("synthetic control\n")
        baseline = run("getfacl", "-cp", str(outside_dst))
        expected = run("getfacl", "-cp", str(source))
        dest = root / "copy"
        # Ordinary ACL preservation, intentional source links and destination-parent
        # links remain supported. GNU's existing tests cover additional semantics.
        run(str(cp), "-a", str(source), str(dest))
        assert run("getfacl", "-cp", str(dest)) == expected
        (root / "source-link").symlink_to(source, target_is_directory=True)
        (root / "parent-link").symlink_to(root, target_is_directory=True)
        run(str(cp), "-aL", str(root / "source-link"), str(root / "parent-link/link-copy"))
        dereference_preserved = run("getfacl", "-cp", str(root / "link-copy")) == expected
        if vulnerable:
            # Stock is a race-negative comparator, not the fixed functionality
            # contract. Report its pre-existing dereference behavior separately;
            # it must still reach and demonstrate both attack witnesses below.
            print(f"stock-source-link-acl-preservation: {dereference_preserved}", flush=True)
        else:
            assert dereference_preserved, "fixed cp must preserve explicitly dereferenced ACLs"
        # A FIFO must retain access ACLs without opening it or blocking.
        fifo, fifo_copy = root / "fifo", root / "fifo-copy"
        os.mkfifo(fifo)
        run("setfacl", "-m", "u:10001:r--", str(fifo))
        run(str(cp), "-a", str(fifo), str(fifo_copy))
        assert run("getfacl", "-cp", str(fifo_copy)) == run("getfacl", "-cp", str(fifo))
        marker = root / "copy-swap"
        env = dict(
            os.environ,
            LD_PRELOAD=str(preload),
            VARDR_ACL_SWAP_MODE="read",
            VARDR_ACL_SWAP_SRC=str(source),
            VARDR_ACL_SWAP_DST=str(dest),
            VARDR_ACL_OUTSIDE_SRC=str(outside_src),
            VARDR_ACL_OUTSIDE_DST=str(outside_dst),
            VARDR_ACL_SWAP_MARKER=str(marker),
        )
        run(str(cp), "-a", str(source) + "/.", str(dest), env=env, allowed=(0, 1))
        assert marker.is_file(), "cp did not reach deterministic default-ACL swap"
        unchanged = run("getfacl", "-cp", str(outside_dst)) == baseline
        copied = run("getfacl", "-cp", str(root / "copy.saved")) == expected
        assert (unchanged and copied) != vulnerable, "cp negative/fixed control mismatch"
        print(
            f"cp-path-substitution: {'EXPECTED_VULNERABLE' if vulnerable else 'PASS'}", flush=True
        )
        # Archive ordinary ACLs, then replace an extraction directory with a link
        # at the default-ACL write boundary. Fixed tar must refuse that write.
        archive, restored = root / "control.tar", root / "restore"
        restored.mkdir()
        run(str(tar), "--acls", "-cf", str(archive), "-C", str(root), "src.saved")
        run(str(tar), "--acls", "-xf", str(archive), "-C", str(restored))
        assert run("getfacl", "-cp", str(restored / "src.saved")) == expected
        marker = root / "tar-swap"
        env = dict(
            os.environ,
            LD_PRELOAD=str(preload),
            VARDR_ACL_SWAP_MODE="write",
            VARDR_ACL_SWAP_DST=str(restored / "src.saved"),
            VARDR_ACL_OUTSIDE_DST=str(outside_dst),
            VARDR_ACL_SWAP_MARKER=str(marker),
        )
        before = run("getfacl", "-cp", str(outside_dst))
        run(
            str(tar), "--acls", "-xf", str(archive), "-C", str(restored), env=env, allowed=(0, 1, 2)
        )
        assert marker.is_file(), "tar did not reach deterministic default-ACL swap"
        unchanged = run("getfacl", "-cp", str(outside_dst)) == before
        assert unchanged != vulnerable, "tar negative/fixed control mismatch"
        print(
            f"tar-path-substitution: {'EXPECTED_VULNERABLE' if vulnerable else 'PASS'}", flush=True
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cp", type=Path, required=True)
    parser.add_argument("--tar", type=Path, required=True)
    parser.add_argument("--preload", type=Path, required=True)
    parser.add_argument("--expect-vulnerable", action="store_true")
    args = parser.parse_args()
    check(args.cp, args.tar, args.preload, args.expect_vulnerable)
