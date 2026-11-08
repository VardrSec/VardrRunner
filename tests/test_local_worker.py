"""Local worker composition with inert IO; no native owner, target or Map execution."""

import json
import socket
import struct
import uuid
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_worker_lifecycle_sequence import owner  # noqa: F401
from tests.test_workspace_gate import SEED, consumed, journey  # noqa: F401
from vardrrunner import local_worker as local
from vardrrunner import worker_lifecycle as life
from vardrrunner.authorization.codec import (
    AuthorizationError,
    decoded,
    digest,
    encoded,
    sign,
    unb64,
)
from vardrrunner.authorization.contracts import timestamp
from vardrrunner.authorization.local_admission import LocalAdmission
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.journal import Phase


@pytest.fixture
def local_case(request, monkeypatch):
    f = request.getfixturevalue("journey")
    payload = decoded(unb64(f.values["contract"]["payload"]))
    payload.update(
        contract_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()), authority_revision=2
    )
    metadata = {
        "schema": "vardr.workspace-authority/1",
        "workspace_id": f.workspace.workspace_id,
        "runner_id": f.identity.runner_id,
        "issuer": f.issuer,
        "public_key": f.values["trust"][0]["public_key"],
        "authority_revision": 2,
    }
    f.permission["authority_revision"] = 2
    f.permission["authority_sha256"] = digest(encoded(metadata))
    approval = decoded(unb64(f.values["approval"]["payload"]))
    approval["context"] = f.permission
    f.values["approval"] = sign(approval, SEED, "approval")
    payload["approval_sha256"] = digest(encoded(f.values["approval"]))
    f.ledger.set_state(
        f.issuer["id"], f.workspace.workspace_id, 2, False, f.permission["authority_sha256"]
    )
    f.values["contract"] = sign(payload, SEED, "contract")
    bundle = f.tmp / "public-bundle"
    bundle.mkdir()
    for name, value in f.values.items():
        (bundle / (name + ".json")).write_bytes(encoded(value))
    monkeypatch.setattr(local, "BUNDLE", bundle)
    monkeypatch.setattr(local, "EXPORT", f.tmp / "exports")
    monkeypatch.setattr(local.os, "ST_RDONLY", 1, raising=False)
    monkeypatch.setattr(
        local.os,
        "statvfs",
        lambda path: SimpleNamespace(f_flag=1 if path == bundle else 0),
        raising=False,
    )
    epoch = Mock()
    epoch.finished.return_value = "ab" * 32
    native = life.SequentialWorkerOwner.__new__(life.SequentialWorkerOwner)
    native.begin_attempt = Mock(return_value=epoch)

    @contextmanager
    def connect(admission):
        assert isinstance(admission, LocalAdmission) and admission.max_attempts == 1
        yield native

    monkeypatch.setattr(life, "connect", connect)
    return f, epoch


def test_local_admission_caps_work_and_preserves_map_origin_boundary(local_case):
    f, _ = local_case
    *_, context, payload, permission = local._inputs()
    plan = f.values["plan"]
    admission = LocalAdmission.verified(payload, permission, plan, now=context.now)
    expected = min(
        timestamp(payload["expires_at"]),
        timestamp(permission["testing_end"]),
        *(timestamp(g["expires_at"]) for g in permission["credential_grants"]),
    )
    assert admission.expires_at == expected + timedelta(seconds=life.REPORT_RUNWAY_SECONDS)
    assert admission.origin == "standalone" and admission.max_attempts == 1
    assert len(admission.runtime_sha256) == 64
    with pytest.raises(AuthorizationError):
        LocalAdmission.verified({**payload, "origin": "map"}, permission, plan, now=context.now)
    with pytest.raises(AuthorizationError, match="local_control_required"):
        LocalAdmission.verified(
            payload, {**permission, "control": "managed_online"}, plan, now=context.now
        )
    # A local authority object never enters or relaxes Map's closed admission parser.
    with pytest.raises(AuthorizationError):
        Admission.parse({"schema": "vardr.local-worker-admission/1"}, now=context.now)


@pytest.mark.parametrize("mutation", ["extra", "writable", "signature"])
def test_local_bundle_rejects_changed_custody_or_authority(local_case, monkeypatch, mutation):
    if mutation == "extra":
        (local.BUNDLE / "issuer.key").write_bytes(b"synthetic-never-a-key")
    elif mutation == "writable":
        monkeypatch.setattr(local.os, "statvfs", lambda _: SimpleNamespace(f_flag=0))
    else:
        path = local.BUNDLE / "contract.json"
        value = decoded(path.read_bytes())
        value["signature"] = "AAAA"
        path.write_bytes(encoded(value))
    with pytest.raises(AuthorizationError):
        local.run()


def test_local_ready_nonce_comes_from_credentialed_native_peer(request, monkeypatch):
    native_owner = request.getfixturevalue("owner")
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size, raising=False)
    nonce = b"n" * 32
    native_owner._channel.recvmsg.return_value = (
        life._PACKET_V2.pack(life._MAGIC_V2, life._READY, 0, 0, 0, nonce),
        [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("=iii", 1, 10000, 10000))],
        0,
        None,
    )
    native_owner._handshake_local()
    assert native_owner._exchange_v2.call_args.args == (
        life._HELLO,
        0,
        native_owner._work_end,
        native_owner._grant_end,
        nonce,
    )
    native_owner._channel.recvmsg.return_value[1][0] = (
        socket.SOL_SOCKET,
        socket.SCM_CREDENTIALS,
        struct.pack("=iii", 1, 10001, 10001),
    )
    with pytest.raises(life.LifecycleUnavailable):
        native_owner._handshake_local()


def test_local_native_done_precedes_completion_export_and_replay_refusal(local_case, monkeypatch):
    f, epoch = local_case
    local.EXPORT.mkdir()
    exported = []

    def finished():
        assert consumed(f) == 1
        assert f.journal.list()[0].phase == Phase.EXECUTING
        return "ab" * 32

    def export(run_id, output):
        assert consumed(f) == 2
        assert f.journal.get(run_id).phase == Phase.DONE
        exported.append(output)

    epoch.finished.side_effect = finished
    monkeypatch.setattr(local, "export_run", export)
    result = local.run()
    record = f.journal.get(result["run_id"])
    assert record.phase == Phase.DONE and record.pid is None
    assert record.last_event == "native_done_ack:" + "ab" * 32
    assert exported == [local.EXPORT / "result"]
    assert len(f.calls) == 1
    assert epoch.verified_lease.call_args.args[0]["origin"] == "standalone"
    # The outer owner/report ceiling never becomes extra tool authority.
    lease, hard = epoch.verified_lease.call_args.args[1:]
    assert (
        lease <= hard <= local.time.monotonic() + f.values["plan"]["execution"]["timeout_seconds"]
    )
    assert result["artifact_sha256"] == record.artifact_sha256
    assert result["export_status"] == "completed"
    with pytest.raises(AuthorizationError, match="replayed"):
        local.run()
    assert len(f.calls) == 1


def test_local_done_uncertainty_keeps_consumption_and_evidence(local_case):
    f, epoch = local_case
    epoch.finished.side_effect = life.LifecycleUnavailable("fixed-synthetic-refusal")
    with pytest.raises(life.LifecycleUnavailable):
        local.run()
    assert consumed(f) == 1
    record = f.journal.list()[0]
    assert record.phase == Phase.FAILED and record.status == "failed_or_uncertain"
    assert (local.config.runs_dir() / record.run_dir / "vardrgate_result.json").is_file()


def test_local_revoked_authority_refuses_before_consumption(local_case):
    f, epoch = local_case
    f.ledger.set_state(
        f.issuer["id"], f.workspace.workspace_id, 3, True, f.permission["authority_sha256"]
    )
    with pytest.raises(AuthorizationError, match="authority_state"):
        local.run()
    assert consumed(f) == 0 and not f.calls
    epoch.verified_lease.assert_not_called()


def test_local_entrypoint_refuses_arguments_and_sanitizes_failure(monkeypatch, capsys):
    operation = Mock(side_effect=ValueError("synthetic-private-path-must-not-print"))
    monkeypatch.setattr(local, "run", operation)
    assert local.main(["--arbitrary"]) == 1
    operation.assert_not_called()
    assert local.main([]) == 1
    assert "synthetic-private-path" not in capsys.readouterr().out
    operation.side_effect = None
    operation.return_value = {"status": "done"}
    assert local.main([]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "done"}
