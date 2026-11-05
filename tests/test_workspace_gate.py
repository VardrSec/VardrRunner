"""Synthetic native-consumer wiring; no real Gate, Windows containment or target proof."""

import copy
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vardrrunner import (
    api,
    config,
    credential_grants,
    execution_control,
    identity,
    launch_guard,
    runner,
)
from vardrrunner.authorization import runtime
from vardrrunner.authorization.codec import b64, decoded, digest, encoded, sign, unb64
from vardrrunner.authorization.contracts import ValidationContext, approve
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import PROFILE, compile_gate_plan, origin
from vardrrunner.commands import audit, jobs
from vardrrunner.commands import workspace_gate as gate
from vardrrunner.journal import Journal, JournalError, Phase
from vardrrunner.recovery import reconcile
from vardrrunner.workspaces import Workspaces

VECTORS = Path(__file__).parent / "fixtures/authorization"
REAL_GATE_EXECUTE = runtime.handlers.VardrGateHandler.execute
SEED = bytes(range(32))  # Public fixture only, never a real enrolled issuer.


@pytest.fixture
def journey(tmp_path, monkeypatch, request):
    journal = Journal(config.journal_file())
    workspace = Workspaces(journal).create("Synthetic standalone")
    who = identity.load_or_create()
    binary = tmp_path / "synthetic-gate-not-executable"
    binary.write_bytes(b"synthetic fixture, not a Gate binary")
    monkeypatch.setattr(runner, "program", lambda _: str(binary))
    monkeypatch.setattr(runner, "cleanup_sensitive_temp_dirs", lambda: None)
    monkeypatch.setattr(execution_control, "available", lambda: True)
    monkeypatch.setattr(gate, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    monkeypatch.setattr(gate.typer, "confirm", lambda *a, **kw: True)
    # Finite test observation only; production guard/default512MiB is unchanged.
    monkeypatch.setattr(
        gate.resources,
        "shutil",
        SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=2 * 1024**3)),
    )
    monkeypatch.delenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("Map, network and real process activity are forbidden")

    monkeypatch.setattr(api, "VardrMapClient", forbidden)
    monkeypatch.setattr(config, "get_api_key", forbidden)
    monkeypatch.setattr(config, "require_auth", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    case = decoded((VECTORS / "case.json").read_bytes())
    execution = {}
    plan = compile_gate_plan(case, execution, tool_sha256=digest(binary.read_bytes()))
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def stamp(t):
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    permission = decoded(unb64(decoded((VECTORS / "approval.json").read_bytes())["payload"]))[
        "context"
    ]
    permission.update(
        runner_id=who.runner_id,
        engagement_id=workspace.workspace_id,
        plan_sha256=digest(encoded(plan)),
        not_before=stamp(now - timedelta(seconds=1)),
        testing_start=stamp(now - timedelta(seconds=1)),
        testing_end=stamp(now + timedelta(minutes=5)),
        expires_at=stamp(now + timedelta(minutes=5)),
    )
    for grant in permission["credential_grants"]:
        grant["expires_at"] = permission["expires_at"]
    issuer = {"id": "fixture-issuer", "key_id": "fixture-public-key"}
    public = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw()
    from vardrrunner.authorization.codec import TrustAnchor

    anchor = TrustAnchor(
        issuer["id"],
        issuer["key_id"],
        public,
        frozenset({"approval", "contract"}),
        frozenset({"standalone"}),
    )
    receipt = approve(
        permission, issuer, "standalone", "synthetic-operator", "fixture-approval", stamp(now), SEED
    )
    context = ValidationContext(
        who.runner_id,
        workspace.workspace_id,
        permission["job_id"],
        "fixture-attempt",
        1,
        "standalone",
        now,
        1,
        plan["tool_sha256"],
        permission["authority_sha256"],
    )
    # The consumer imports a signed contract; it never receives this fixture key.
    signer = AuthorizationLedger(Journal(tmp_path / "fixture-signer.sqlite3"))
    signer.set_state(issuer["id"], workspace.workspace_id, 1, False, permission["authority_sha256"])
    envelope = signer.issue(
        receipt,
        (anchor,),
        issuer,
        SEED,
        "fixture-contract",
        context.attempt_id,
        context,
        plan,
        case,
        execution,
    )
    ledger = AuthorizationLedger(journal)
    if getattr(request, "param", None) != "missing_state":
        ledger.set_state(
            issuer["id"], workspace.workspace_id, 1, False, permission["authority_sha256"]
        )
    grant_store = credential_grants.Store()
    for ref in plan["credential_references"]:
        for site in {origin(d["request"]["url"]) for d in plan["dispatches"]}:
            grant_store.approve("standalone", workspace.workspace_id, site, "env", ref["name"], 300)
    values = {
        "approval": receipt,
        "contract": envelope,
        "plan": plan,
        "case": case,
        "execution": execution,
        "trust": [
            {
                "issuer_id": issuer["id"],
                "key_id": issuer["key_id"],
                "public_key": b64(public),
                "purposes": ["approval", "contract"],
                "origins": ["standalone"],
                "revoked": False,
            }
        ],
    }
    paths = {}
    for name, value in values.items():
        paths[name] = tmp_path / (name + ".json")
        paths[name].write_bytes(encoded(value))
    calls = []

    def execute(self, targets, directory, config, **kwargs):
        control = execution_control.current()
        assert control is not None and not control.stop_reason()
        callback = runner._PROCESS_OBSERVER.get()
        assert callback is not None
        callback(900001)  # Synthetic PID metadata, never signaled or created.
        calls.append(kwargs)
        output = directory / "vardrgate_result.json"
        output.write_text('{"findings":[],"executions":[]}')
        return output

    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", execute)
    return SimpleNamespace(
        journal=journal,
        workspace=workspace,
        identity=who,
        context=context,
        ledger=ledger,
        permission=permission,
        issuer=issuer,
        values=values,
        paths=paths,
        calls=calls,
        grant_store=grant_store,
        output=tmp_path / "evidence",
        tmp=tmp_path,
    )


def invoke(f, **changes):
    return gate.run(f.workspace.workspace_id, **{**f.paths, "output": f.output, **changes})


def consumed(f):
    with f.journal._connection() as con:
        row = con.execute("SELECT consumed FROM authorization_contracts").fetchone()
    return row[0] if row else 0


def test_standalone_uses_shared_runtime_journal_export_and_refuses_replay(journey, capsys):
    f = journey
    invoke(f)
    record = f.journal.list()[0]
    assert record.phase == Phase.DONE and record.pid is None
    assert record.backend_url == "" and record.upload_state == "not_applicable"
    assert record.command_profile["controlled"] is True
    assert f.calls[0]["request_guard"] == f.values["plan"]
    assert consumed(f) == 2
    assert (
        json.loads(Path(record.manifest_path).read_text())["artifact_sha256"]
        == record.artifact_sha256
    )
    audit.export_runs(f.tmp / "audit.json")
    exported = json.loads((f.tmp / "audit.json").read_text())
    assert exported["runs"][0]["engagement_id"] == f.workspace.workspace_id
    assert "api.example.test" not in json.dumps(exported)
    assert "synthetic-gate-not-executable" not in capsys.readouterr().out
    with pytest.raises(typer.Exit):
        invoke(f, output=f.tmp / "replay")
    assert len(f.calls) == 1 and consumed(f) == 2


def test_additive_cli_reaches_the_standalone_consumer_without_map(journey):
    from typer.testing import CliRunner

    from vardrrunner.cli import app

    f = journey
    args = ["workspace", "gate", f.workspace.workspace_id]
    for name, path in {**f.paths, "output": f.output}.items():
        args.extend(["--" + name, str(path)])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert f.journal.list()[0].phase == Phase.DONE
    assert len(f.calls) == 1 and consumed(f) == 2


@pytest.mark.parametrize(
    "kind",
    [
        "noninteractive",
        "unsupported_platform",
        "declined",
        "wrong_workspace",
        "wrong_runner",
        "tampered_plan",
        "tampered_case",
        "revoked_grant",
    ],
)
def test_refusal_boundaries_have_zero_dispatch(journey, monkeypatch, kind):
    f = journey
    changes = {}
    if kind == "noninteractive":
        monkeypatch.setattr(gate.sys.stdin, "isatty", lambda: False)
    elif kind == "unsupported_platform":
        monkeypatch.setattr(execution_control, "available", lambda: False)
    elif kind == "declined":
        monkeypatch.setattr(gate.typer, "confirm", lambda *a, **kw: False)
    elif kind == "wrong_workspace":
        f.workspace = Workspaces(f.journal).create("Other")
    elif kind == "wrong_runner":
        monkeypatch.setattr(
            identity, "load_or_create", lambda: replace(f.identity, runner_id="foreign")
        )
    elif kind == "tampered_plan":
        f.paths["plan"].write_bytes(f.paths["plan"].read_bytes() + b"\n")
    elif kind == "tampered_case":
        case = copy.deepcopy(f.values["case"])
        case["request"]["url"] += "/changed"
        f.paths["case"].write_bytes(encoded(case))
    else:
        f.grant_store.revoke(
            "standalone", f.workspace.workspace_id, "https://api.example.test", "env", "NM1_OWNER"
        )
    with pytest.raises(typer.Exit):
        invoke(f, **changes)
    assert not f.calls and consumed(f) == 0


@pytest.mark.parametrize("journey", ["missing_state"], indirect=True)
def test_missing_authority_is_not_bootstrapped(journey):
    with pytest.raises(typer.Exit):
        invoke(journey)
    with journey.journal._connection() as con:
        assert con.execute("SELECT COUNT(*) FROM authorization_state").fetchone()[0] == 0
    assert not journey.calls and consumed(journey) == 0


def test_post_consume_journal_failure_spends_permission_without_launch(journey, monkeypatch):
    f = journey
    original = Journal.transition

    def transition(self, run_id, phase, **fields):
        if phase == Phase.CLAIMED:
            raise JournalError("private-fixture-error")
        return original(self, run_id, phase, **fields)

    monkeypatch.setattr(Journal, "transition", transition)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert consumed(f) == 1 and not f.calls
    with pytest.raises(typer.Exit):
        invoke(f, output=f.tmp / "retry")
    assert consumed(f) == 1 and not f.calls


def test_existing_stop_and_authority_revocation_are_polled_without_writer_deadlock(journey):
    f = journey
    record = f.journal.begin(
        job_id="local-stop-fixture",
        backend_url="",
        engagement_id=f.workspace.workspace_id,
        job_type="vardrgate_api_test",
        tool="vardrgate_api_test",
        target_source="explicit",
        command_profile={"standalone_profile": PROFILE, "controlled": True},
    )
    until = datetime.now(timezone.utc) + timedelta(seconds=30)
    control = gate._local_control(
        f.ledger, f.context, f.issuer["id"], f.permission, record.run_id, until
    )
    # Another writer represents the existing grant launch transaction. Reads must not reacquire it.
    with f.journal._connection() as writer:
        writer.execute("BEGIN IMMEDIATE")
        assert control.stop_reason() == ""
    jobs.stop_job(record.run_id)
    assert control.stop_reason() == "local_emergency_stop"
    other = gate._local_control(
        f.ledger, f.context, f.issuer["id"], f.permission, "other-run", until
    )
    f.ledger.set_state(
        f.issuer["id"], f.workspace.workspace_id, 2, True, f.permission["authority_sha256"]
    )
    assert other.stop_reason() == "local_emergency_stop"


def test_crashed_standalone_intent_never_enters_map_recovery(journey):
    f = journey
    record = f.journal.begin(
        job_id="crash-fixture",
        backend_url="",
        engagement_id=f.workspace.workspace_id,
        job_type="vardrgate_api_test",
        tool="vardrgate_api_test",
        target_source="explicit",
        command_profile={"standalone_profile": PROFILE},
    )
    client = MagicMock()
    result = reconcile(f.journal, client, "")
    assert result.deferred == 1 and not client.mock_calls
    assert f.journal.get(record.run_id).phase == Phase.DISCOVERED


@pytest.mark.parametrize("kind", ["map_origin", "expired", "revoked_issuer"])
def test_signed_but_unusable_permission_is_not_authority(journey, kind):
    f = journey
    receipt = decoded(unb64(f.values["approval"]["payload"]))
    contract = decoded(unb64(f.values["contract"]["payload"]))
    if kind == "map_origin":
        receipt["origin"] = contract["origin"] = "map"
        receipt["context"]["control"] = "managed_online"
        f.values["trust"][0]["origins"].append("map")
    elif kind == "expired":
        before = datetime.now(timezone.utc) - timedelta(days=1)
        for name in ("not_before", "testing_start"):
            receipt["context"][name] = (before - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for name in ("expires_at", "testing_end"):
            receipt["context"][name] = before.strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt["approved_at"] = receipt["context"]["not_before"]
        contract["issued_at"] = receipt["approved_at"]
        contract["expires_at"] = receipt["context"]["expires_at"]
    else:
        f.values["trust"][0]["revoked"] = True
    approval = sign(receipt, SEED, "approval")
    contract["approval_sha256"] = digest(encoded(approval))
    for name, value in (
        ("approval", approval),
        ("contract", sign(contract, SEED, "contract")),
        ("trust", f.values["trust"]),
    ):
        f.paths[name].write_bytes(encoded(value))
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.calls and consumed(f) == 0 and not f.output.exists()


@pytest.mark.parametrize("confirmed", [False, True, 1])
def test_constructor_stop_pid_is_retained_until_literal_confirmed_termination(
    journey, monkeypatch, confirmed
):
    f = journey

    def stopped(*args, **kwargs):
        raise execution_control.ExecutionStopped("fixture-stop", confirmed, pid=900002)

    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", stopped)
    with pytest.raises(typer.Exit):
        invoke(f)
    record = f.journal.list()[0]
    assert record.pid == (None if confirmed is True else 900002)
    assert record.phase == (Phase.STOP_WORK if confirmed is True else Phase.FAILED)
    assert consumed(f) == 1 and not f.calls


def test_partial_output_is_preserved_and_not_reported_complete(journey, monkeypatch, capsys):
    f = journey

    def partial(*args, **kwargs):
        runner._PROCESS_OBSERVER.get()(900001)
        (f.output / "vardrgate_result.json").write_text("partial synthetic evidence")
        raise RuntimeError("private-fixture-error")

    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", partial)
    with pytest.raises(typer.Exit):
        invoke(f)
    record = f.journal.list()[0]
    assert record.phase == Phase.FAILED and record.pid == 900001
    assert record.artifact_sha256 is None and consumed(f) == 1
    assert (f.output / "vardrgate_result.json").read_text() == "partial synthetic evidence"
    assert "private-fixture-error" not in capsys.readouterr().out


def test_duration_cap_is_rechecked_after_blocking_local_stop_read(journey, monkeypatch):
    f = journey
    clock = [100.0]
    monkeypatch.setattr(gate.time, "monotonic", lambda: clock[0])
    read = AuthorizationLedger.check_state

    def delayed(self, context, issuer):
        read(self, context, issuer)
        clock[0] += 70

    monkeypatch.setattr(AuthorizationLedger, "check_state", delayed)
    started = []

    def create(*args, **kwargs):
        # The permission check can return before noticing time spent in its read.
        assert execution_control.current().stop_reason() == ""
        launch_guard.require_permission()  # Existing final creation boundary.
        started.append(True)

    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", create)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not started and consumed(f) == 1


def test_deadline_is_computed_again_after_reservation_callback(journey, monkeypatch):
    f = journey
    now = [datetime.now(timezone.utc)]

    class Clock:
        @staticmethod
        def now(_):
            return now[0]

    monkeypatch.setattr(runtime, "datetime", Clock)
    transition = Journal.transition

    def delayed(self, run_id, phase, **fields):
        result = transition(self, run_id, phase, **fields)
        if phase == Phase.CLAIMED:
            now[0] += timedelta(hours=1)
        return result

    monkeypatch.setattr(Journal, "transition", delayed)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert consumed(f) == 1 and not f.calls


def test_launch_setup_failure_cleans_resolved_secret_and_keeps_standalone_reservation(
    journey, monkeypatch, capsys, caplog
):
    f = journey
    secret = "synthetic-standalone-launch-secret"
    monkeypatch.setenv("NM1_OWNER", secret)
    scratch = f.tmp / "private-launch"
    scratch.mkdir()
    monkeypatch.setattr(runner.tempfile, "tempdir", str(scratch))
    monkeypatch.setattr(runtime.handlers.VardrGateHandler, "execute", REAL_GATE_EXECUTE)
    original_write = runner._write_private_job
    original_program = runner.program
    written = []

    def write(payload):
        path, directory = original_write(payload)
        assert secret in path.read_text()
        written.append((path, directory))
        return path, directory

    def program(name):
        if written:
            raise runner.ToolError("synthetic launch preparation refusal")
        return original_program(name)

    monkeypatch.setattr(runner, "_write_private_job", write)
    monkeypatch.setattr(runner, "program", program)
    spawn = MagicMock(side_effect=AssertionError("No process may launch"))
    monkeypatch.setattr(runner, "_spawn_tool", spawn)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert len(written) == 1 and list(scratch.iterdir()) == []
    assert consumed(f) == 1 and not f.calls
    record = f.journal.list()[0]
    assert record.phase == Phase.FAILED and record.pid is None
    assert record.artifact_sha256 is None
    assert not (f.output / "vardrgate_result.json").exists()
    with pytest.raises(typer.Exit):
        invoke(f, output=f.tmp / "retry-cleanup")
    assert consumed(f) == 1 and len(written) == 1
    spawn.assert_not_called()
    output = capsys.readouterr()
    assert secret not in output.out + output.err + caplog.text


def test_standalone_run_exports_without_changing_consumption_or_grants(journey, monkeypatch):
    from tests.test_portable_export import root_owner_observation
    from vardrrunner import manifests, resources

    if not audit._private_directories_supported():
        pytest.skip("POSIX descriptor integration; native Windows export remains separate")
    # Reuse the export fixture's bounded capacity/root-owner observations only.
    root_owner_observation(monkeypatch, 0)
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda _: SimpleNamespace(free=2 * 1024**3))
    f = journey
    invoke(f)
    record = f.journal.list(engagement_id=f.workspace.workspace_id)[0]
    assert record.phase == Phase.DONE and record.pid is None
    assert Workspaces.list_existing(f.journal.path) == [f.workspace]
    original = Path(record.artifact_path).read_bytes()

    def control_rows():
        with f.journal._connection() as con:
            return {
                table: [tuple(row) for row in con.execute("SELECT * FROM " + table)]
                for table in ("authorization_contracts", "credential_grant_state")
            }

    before = control_rows()
    exported = f.tmp / "portable-standalone"
    audit.export_run(record.run_id, exported)
    assert control_rows() == before and consumed(f) == 2
    assert Path(record.artifact_path).read_bytes() == original
    assert {p.name for p in exported.iterdir()} == {"artifact.json", "audit.json", "manifest.json"}
    provenance = json.loads((exported / "audit.json").read_text())["runs"][0]
    derivative = json.loads((exported / "manifest.json").read_text())
    assert provenance["artifact_sha256"] == record.artifact_sha256
    assert derivative["artifact_sha256"] == manifests.artifact_digest(exported / "artifact.json")[0]
    assert derivative["artifact_path"] == "artifact.json"
    assert any(w["code"] == "redacted_export" for w in derivative["warnings"])
    with pytest.raises(typer.Exit):
        invoke(f, output=f.tmp / "export-does-not-rearm")
    assert consumed(f) == 2 and len(f.calls) == 1
