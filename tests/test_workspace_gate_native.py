"""Explicit real Windows/Gate loopback acceptance; ordinary suites keep it unrun."""

import importlib.util
import io
import json
import os
import re
import tempfile
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich.console import Console

from vardrrunner import api, config, credential_grants, execution_control, identity, runner
from vardrrunner.authorization.codec import TrustAnchor, b64, digest, encoded
from vardrrunner.authorization.contracts import ValidationContext, approve
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.plan import compile_gate_plan, origin
from vardrrunner.commands import audit, workspace_gate
from vardrrunner.journal import Journal, Phase
from vardrrunner.workspaces import Workspaces


@pytest.mark.skipif(
    os.environ.get("NM3_NATIVE_GATE_ACCEPTANCE") != "1",
    reason="explicit real Windows/Gate fixture opt-in",
)
def test_native_standalone_workspace_gate_five_phases_and_no_replay(tmp_path, monkeypatch):
    assert execution_control.available(), "Native Windows containment is required; no fallback"
    binary = Path(os.environ["NM3_GATE_BINARY"]).resolve()
    expected = os.environ["NM3_GATE_SHA256"]
    assert re.fullmatch(r"[0-9a-f]{64}", expected)
    assert digest(binary.read_bytes()) == expected
    fixture = Path(os.environ["NM3_DISTRIBUTION_SOURCE"]) / "tests/nm1_guarded_execution.py"
    # Reuse the existing independent synthetic target, not a new Gate/oracle implementation.
    assert (
        digest(fixture.read_bytes())
        == "ea017a95e708fc5a7574ee5d0a0e8034ec69604ff9987c4dbeae80c69d73ac63"
    )
    spec = importlib.util.spec_from_file_location("nm3_existing_nm1_target", fixture)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class ObservedTarget(module.Target):
        calls = value = 0
        observed = []

        def respond(self, status, body):
            # Record only fixed synthetic routing/identity labels, never headers/body.
            type(self).observed.append((self.command, self.path, self.actor()))
            super().respond(status, body)

    target = ObservedTarget
    server = ThreadingHTTPServer(("127.0.0.1", 0), target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    base = "http://127.0.0.1:" + str(server.server_port)
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(private_temp))
    monkeypatch.setattr(runner, "program", lambda _: str(binary))
    monkeypatch.setattr(
        workspace_gate, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True))
    )
    monkeypatch.setattr(typer, "confirm", lambda *a, **kw: True)
    monkeypatch.setattr(workspace_gate, "console", Console(file=io.StringIO()))

    def no_map(*a, **kw):
        raise AssertionError("Map is unavailable for this standalone fixture")

    monkeypatch.setattr(api, "VardrMapClient", no_map)
    monkeypatch.setattr(config, "require_auth", no_map)
    monkeypatch.setattr(config, "get_api_key", no_map)
    monkeypatch.setenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", "1")
    for name in ("owner", "peer", "reader"):
        monkeypatch.setenv("NM1_" + name.upper(), "synthetic-" + name)

    def person(name):
        return {
            "id": name,
            "credential": {"type": "bearer", "value_env": "NM1_" + name.upper()},
            "preflight": {"url": base + "/me", "expected_status": 200, "json_fields": {"id": name}},
        }

    case = {
        "id": "standalone-native-fixture",
        "mutating": True,
        "identities": [person("owner"), person("peer")],
        "setup": [{"name": "prepare", "request": {"method": "POST", "url": base + "/prepare"}}],
        "request": {"method": "PATCH", "url": base + "/object", "body": {"value": 1}},
        "expected_access": [
            {"identity_id": "owner", "decision": "allow"},
            {"identity_id": "peer", "decision": "deny"},
        ],
        "write_verification": {
            "strategy": "changed",
            "environment": "synchronous_isolated",
            "identity": person("reader"),
            "request": {"method": "GET", "url": base + "/object"},
            "json_pointer": "/value",
            "changed_to": 1,
            "reset": {"as": "owner", "request": {"method": "POST", "url": base + "/reset"}},
        },
    }
    execution = {"allow_private_targets": True}
    plan = compile_gate_plan(case, execution, tool_sha256=expected)
    journal = Journal(config.journal_file())
    workspace = Workspaces(journal).create("Synthetic native acceptance")
    who = identity.load_or_create()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def stamp(t):
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    seed = bytes(range(32))  # Public fixture only; no production keys/enrollment.
    issuer = {"id": "fixture-only", "key_id": "public-test-key"}
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    anchor = TrustAnchor(
        issuer["id"],
        issuer["key_id"],
        public,
        frozenset({"approval", "contract"}),
        frozenset({"standalone"}),
    )
    permission = {
        "runner_id": who.runner_id,
        "engagement_id": workspace.workspace_id,
        "job_id": "fixture-only-job",
        "authority_revision": 1,
        "authority_sha256": "b" * 64,
        "plan_sha256": digest(encoded(plan)),
        "mode": "strict",
        "exceptions": [],
        "scope": [
            {
                "origin": origin(d["request"]["url"]),
                "path": urlsplit(d["request"]["url"]).path,
                "method": d["request"]["method"],
                "excluded": False,
                "reason": "",
            }
            for d in plan["dispatches"]
        ],
        "not_before": stamp(now),
        "expires_at": stamp(now + timedelta(minutes=5)),
        "testing_start": stamp(now),
        "testing_end": stamp(now + timedelta(minutes=5)),
        "max_executions": 1,
        "max_duration_seconds": 30,
        "max_http_dispatches": 14,
        "max_artifact_bytes": 1000000,
        "control": "local_offline",
        "credential_grants": [
            {
                "identity_id": name,
                "source": "value_env",
                "name": "NM1_" + name.upper(),
                "revision": 1,
                "expires_at": stamp(now + timedelta(minutes=5)),
            }
            for name in ("owner", "peer", "reader")
        ],
    }
    receipt = approve(
        permission, issuer, "standalone", "synthetic-operator", "fixture-approval", stamp(now), seed
    )
    ledger = AuthorizationLedger(journal)
    ledger.set_state(issuer["id"], workspace.workspace_id, 1, False, permission["authority_sha256"])
    context = ValidationContext(
        who.runner_id,
        workspace.workspace_id,
        permission["job_id"],
        "fixture-attempt",
        1,
        "standalone",
        now,
        1,
        expected,
        permission["authority_sha256"],
    )
    contract = ledger.issue(
        receipt,
        (anchor,),
        issuer,
        seed,
        "fixture-contract",
        context.attempt_id,
        context,
        plan,
        case,
        execution,
    )
    for grant in permission["credential_grants"]:
        credential_grants.Store().approve(
            "standalone", workspace.workspace_id, base, "env", grant["name"], 300
        )
    values = {
        "approval": receipt,
        "contract": contract,
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
    thread.start()
    try:
        workspace_gate.run(workspace.workspace_id, **paths, output=tmp_path / "result")
        record = journal.list()[0]
        assert record.phase == Phase.DONE and record.pid is None
        result = json.loads(Path(record.artifact_path).read_text())
        assert result["case_hash"] == plan["case_hash"] and target.calls == 14
        assert len(result["assessments"]) == 2
        assert {a["identity_id"]: a["decision"] for a in result["assessments"]} == {
            "owner": "allowed",
            "peer": "denied",
        }
        assert target.value == 0  # The actual final reset reached the loopback target.
        expected_requests = Counter()
        for dispatch in plan["dispatches"]:
            actor = dispatch["identity_id"]
            if actor.startswith("setup:"):
                actor = ""
            expected_requests[
                (dispatch["request"]["method"], urlsplit(dispatch["request"]["url"]).path, actor)
            ] += dispatch["max_dispatches"]
        assert Counter(target.observed) == expected_requests
        verified_phases = sorted({d["phase"] for d in plan["dispatches"]})
        assert verified_phases == ["preflight", "reset", "resource", "setup", "verification"]
        with pytest.raises(typer.Exit):
            workspace_gate.run(workspace.workspace_id, **paths, output=tmp_path / "replay")
        assert target.calls == 14
        audit.export_runs(tmp_path / "audit.json")
        assert record.artifact_sha256 == digest(Path(record.artifact_path).read_bytes())
        assert all(
            "synthetic-" + name not in Path(record.artifact_path).read_text()
            for name in ("owner", "peer", "reader")
        )
        (tmp_path / "native-summary.json").write_text(
            json.dumps(
                {
                    "status": "passed",
                    "tool_sha256": expected,
                    "phases": verified_phases,
                    "observed_request_multiset_matches_plan": True,
                    "owner_allowed_peer_denied": True,
                    "final_reset_value_zero": True,
                    "dispatches": 14,
                    "replay_additional_dispatches": 0,
                    "case_hash_preserved": True,
                    "artifact_sha256": record.artifact_sha256,
                    "map_used": False,
                    "native_containment": True,
                    "trust": "public synthetic fixture only",
                    "active_cancellation_tested": False,
                },
                indent=2,
            )
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
