"""Explicit file interfaces cannot approve unattended or start target traffic."""

import copy
import json
from pathlib import Path

import pytest

from vardrrunner.authorization.__main__ import main
from vardrrunner.authorization.codec import decoded, digest, encoded

VECTORS = Path(__file__).parent / "fixtures" / "authorization"


@pytest.fixture
def files(tmp_path):
    for source in VECTORS.glob("*.json"):
        (tmp_path / source.name).write_bytes(source.read_bytes())
    (tmp_path / "key").write_bytes(bytes(range(32)))
    return tmp_path


def args(root, command):
    result = [command]
    for name in ("approval", "plan", "case", "execution", "trust", "context"):
        filename = "runtime" if name == "context" else name
        result += ["--" + name, str(root / (filename + ".json"))]
    return result


def test_static_vectors_validate_and_plan_bytes_are_bound(files, capsys):
    command = args(files, "validate") + ["--contract", str(files / "contract.json")]
    assert main(command) == 0
    assert "no target execution" in capsys.readouterr().out
    (files / "plan.json").write_bytes((files / "plan.json").read_bytes() + b"\n")
    assert main(command) == 1


def test_approve_requires_actual_interactive_channel(files, monkeypatch):
    receipt = decoded((files / "approval.json").read_bytes())
    from vardrrunner.authorization.codec import unb64

    context = decoded(unb64(receipt["payload"]))["context"]
    (files / "approval-context.json").write_bytes(encoded(context))
    command = [
        "approve",
        "--context",
        str(files / "approval-context.json"),
        "--issuer",
        "issuer-1",
        "--key-id",
        "key-1",
        "--key-file",
        str(files / "key"),
        "--origin",
        "standalone",
        "--approver",
        "operator-1",
        "--approval-id",
        "new-approval",
        "--at",
        "2026-11-01T17:59:00Z",
        "--out",
        str(files / "new-approval.json"),
    ]
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(command) == 1
    assert not (files / "new-approval.json").exists()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "DECLINE")
    assert main(command) == 1
    monkeypatch.setattr("builtins.input", lambda _: "APPROVE")
    assert main(command) == 0
    assert main(command) == 1  # approval output is never overwritten


def test_explicit_state_issue_and_single_consumption(files):
    journal = files / "state.sqlite3"
    state = [
        "state",
        "--journal",
        str(journal),
        "--issuer",
        "issuer-1",
        "--engagement",
        "eng-1",
        "--revision",
        "1",
        "--authority-sha256",
        "b" * 64,
    ]
    assert main(state) == 0
    command = args(files, "issue") + [
        "--issuer",
        "issuer-1",
        "--key-id",
        "key-1",
        "--key-file",
        str(files / "key"),
        "--journal",
        str(journal),
        "--contract-id",
        "contract-1",
        "--out",
        str(files / "issued.json"),
    ]
    assert main(command) == 0
    validate = args(files, "validate") + [
        "--contract",
        str(files / "issued.json"),
        "--consume-journal",
        str(journal),
    ]
    assert main(validate) == 0
    assert main(validate) == 1
    assert main(state + ["--stopped"]) == 1  # changing control requires a newer revision
    state[state.index("--revision") + 1] = "2"
    assert main(state + ["--stopped"]) == 0
    assert main(validate) == 1


def test_plan_command_binds_actual_binary_and_options(files):
    binary = files / "synthetic-binary"
    binary.write_bytes(b"fixture-only-not-executable")
    command = [
        "plan",
        "--case",
        str(files / "case.json"),
        "--execution",
        str(files / "execution.json"),
        "--tool",
        str(binary),
        "--out",
        str(files / "generated-plan.json"),
    ]
    assert main(command) == 0
    assert decoded((files / "generated-plan.json").read_bytes())["tool_sha256"] == digest(
        binary.read_bytes()
    )


def test_file_cli_cannot_assert_verified_managed_control(files):
    context = json.loads((files / "runtime.json").read_text())
    context["managed_status_verified"] = True
    (files / "runtime.json").write_bytes(encoded(context))
    assert main(args(files, "validate") + ["--contract", str(files / "contract.json")]) == 1


@pytest.mark.parametrize("kind", ["trust", "context", "signature", "missing_file"])
def test_file_errors_are_fixed_and_do_not_echo_input(files, kind, capsys):
    if kind == "trust":
        (files / "trust.json").write_text("[]")
    elif kind == "context":
        context = copy.deepcopy(json.loads((files / "runtime.json").read_text()))
        context["unknown-secret-value"] = "should-never-be-printed"
        (files / "runtime.json").write_bytes(encoded(context))
    elif kind == "signature":
        contract = json.loads((files / "contract.json").read_text())
        contract["signature"] = "bad"
        (files / "contract.json").write_bytes(encoded(contract))
    else:
        (files / "contract.json").unlink()
    assert main(args(files, "validate") + ["--contract", str(files / "contract.json")]) == 1
    assert capsys.readouterr().err.strip() == "authorization_prototype_refused"
