"""Opt-in Map HTTP/proxy/native tree faults; no scanner or managed signer.

Run with Map's test Python, --map-source PATH --out NEW_DIRECTORY. Reuse only
the existing Runner test dependencies; do not install into retained environments.
All identities, grants, data and authentication are disposable fixture material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

TREE = """import os, signal, subprocess, sys, time
from pathlib import Path
root, depth = Path(sys.argv[1]), int(sys.argv[2])
signal.signal(signal.SIGTERM, lambda *_: None)
if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, lambda *_: None)
if depth: subprocess.Popen([sys.executable, __file__, str(root), str(depth-1)])
(root/(str(depth)+'.pid')).write_text(str(os.getpid()))
(root/(str(depth)+'.partial')).write_text('synthetic partial evidence')
while True: time.sleep(.05)
"""


def wait_for(predicate, seconds=15):
    until = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < until, "bounded fixture wait expired"
        time.sleep(0.02)


class Fault:
    def __init__(self):
        self.mode = ""
        self.armed = threading.Event()
        self.release = threading.Event()
        self.waiting = threading.Event()
        self.returned = threading.Event()
        self.counts = {}
        self.control_ok = 0
        self.finish_commits = 0
        self.dropped = 0
        self.delayed_action = None
        self.payload = None  # Capability stays in memory; never serialize this object.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--map-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.name == "nt", "native Windows only; no Linux support claim"
    root = args.out.resolve()
    root.mkdir(exist_ok=False)
    os.environ.update(
        DATABASE_URL="sqlite:///" + (root / "fixture.db").as_posix(),
        BACKEND_JWT_SECRET="public-disposable-nm2-fault-fixture-only-0123456789",
        ENV="test",
        ALLOWED_ORIGINS="http://localhost:3000",
        VARDRRUNNER_ALLOW_PRIVATE_TARGETS="1",
        NM2_FAULT_REFERENCE="public-disposable-fixture-value",
    )
    sys.path[:0] = [str(args.map_source.resolve() / "backend"), str(Path(__file__).parents[1])]
    sys.path.append(str(Path(__file__).parents[1] / ".venv" / "Lib" / "site-packages"))
    import jwt
    import requests
    import uvicorn
    from db import Base, engine
    from main import app
    from models import ApiKey, Engagement, JobExecution, User
    from rich.console import Console
    from sqlalchemy.orm import Session

    from vardrrunner import (
        api,
        config,
        credential_grants,
        errors,
        execution_control,
        handlers,
        identity,
        recovery,
        runner,
        windows_job,
    )
    from vardrrunner.commands import jobs
    from vardrrunner.journal import Journal, Phase

    Base.metadata.create_all(engine)
    # Public test material, not a retained credential or owner approval.
    key = "vmap_nm2_native_fault_disposable_fixture_only"
    with Session(engine) as db:
        db.add(User(github_id="fault-fixture", username="fixture"))
        db.commit()
        db.add(
            ApiKey(
                github_id="fault-fixture",
                key_hash=hashlib.sha256(key.encode()).hexdigest(),
                scope="runner",
            )
        )
        db.commit()
    token = jwt.encode(
        {
            "sub": "fault-fixture",
            "aud": "vardrmap-backend",
            "iss": "vardrmap-frontend",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=20),
        },
        os.environ["BACKEND_JWT_SECRET"],
        algorithm="HS256",
    )
    headers = {"Authorization": "Bearer " + token}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    upstream = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    wait_for(lambda: server.started)
    fault = Fault()

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.forward()

        def do_GET(self):
            self.forward()

        def forward(self):
            path = self.path
            fault.counts[path] = fault.counts.get(path, 0) + 1
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            control = path.endswith("/control")
            finish = path.endswith("/execution-finish")
            if control:
                fault.payload = json.loads(body)
            armed = fault.armed.is_set()
            if armed and (
                (control and fault.mode == "control_drop")
                or (finish and fault.mode != "finish_after_commit")
            ):
                fault.dropped += 1
                self.close_connection = True
                return
            response = requests.request(
                self.command,
                upstream + path,
                data=body,
                headers={
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in {"host", "content-length", "connection"}
                },
                timeout=4,
                allow_redirects=False,
            )
            if finish and armed:
                assert response.status_code == 200
                fault.finish_commits += 1
                fault.dropped += 1
                self.close_connection = True
                return
            if control and armed and fault.mode == "control_delay":
                fault.delayed_action = response.json()["action"]
                fault.waiting.set()
                assert fault.release.wait(20), "delayed response not released"
            elif control and response.ok:
                fault.control_ok += 1
            try:
                self.send_response(response.status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            finally:
                if control and armed and fault.mode == "control_delay":
                    fault.returned.set()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    url = f"http://127.0.0.1:{proxy.server_port}"

    def request(method, path, payload=None):
        response = requests.request(
            method, upstream + path, json=payload, headers=headers, timeout=4
        )
        assert response.ok, (response.status_code, path)
        return response.json()

    receipts = []
    try:

        def scenario(mode):
            nonlocal fault
            fault = Fault()
            fault.mode = mode
            trial = root / mode
            trial.mkdir()
            fixture = trial / "tree.py"
            fixture.write_text(TREE)
            engagement = request("POST", "/engagements", {"name": "Disposable native fault"})["id"]
            for policy, payload in (
                ("concurrency", {"limit": 1}),
                ("target", {"limit": 1}),
                ("duration", {"limit_seconds": 120}),
            ):
                request("PUT", f"/engagements/{engagement}/{policy}-policy", payload)
            target = "http://127.0.0.1:9"  # Descriptive binding only; never contacted.
            spec = {
                "id": "native-fault",
                "request": {"method": "GET", "url": target + "/fixture"},
                "identities": [
                    {
                        "id": "fixture",
                        "credential": {"type": "bearer", "value_env": "NM2_FAULT_REFERENCE"},
                    }
                ],
                "expected_access": [{"identity_id": "fixture", "decision": "allow"}],
            }
            case_id = request(
                "POST", f"/engagements/{engagement}/test-cases", {"name": "Synthetic", "spec": spec}
            )["id"]
            job_id = request(
                "POST",
                f"/engagements/{engagement}/jobs",
                {
                    "tool_type": "vardrgate_api_test",
                    "target_source": "scope",
                    "config": {"test_case_id": case_id},
                },
            )["id"]
            measurements = {}
            controls = []
            executions = []
            trigger_errors = []
            original_control_init = execution_control.Control.__init__
            original_graceful = windows_job.WindowsJob.graceful

            def observe_control(instance, *a, **kw):
                original_control_init(instance, *a, **kw)
                controls.append(instance)

            def observe_stop(instance):
                measurements["stop_requested"] = time.monotonic()
                return original_graceful(instance)

            class Fixture(handlers.VardrGateHandler):
                def execute(self, targets, run_dir, cfg, **kw):
                    assert kw.get("request_guard"), "exercise existing target binding preparation"
                    handlers._resolve_identity_secrets(cfg.test_case, cfg.engagement_id)
                    executions.append(time.monotonic())
                    runner._run_tool(
                        [sys.executable, str(fixture), str(trial), "2"], None, "fixture", 90
                    )
                    raise AssertionError("fixture must stop, never finish normally")

                def upload(self, *a, **kw):
                    raise AssertionError("partial fixture output must never upload")

            with (
                patch.object(config, "DATA_DIR", trial),
                patch.object(config, "CONFIG_DIR", trial),
                patch.object(config, "CONFIG_FILE", trial / "config.json"),
                patch.object(config, "JOURNAL_FILE", trial / "jobs.sqlite3"),
                patch.object(identity, "identity_file", lambda: trial / "identity.json"),
                patch.dict(handlers.REGISTRY, {"vardrgate_api_test": Fixture()}),
                patch.object(runner, "program", lambda _: sys.executable),
                patch.object(runner, "tool_available", lambda _: True),
                patch.object(jobs, "_make_run_dir", lambda: trial),
                patch.object(execution_control.Control, "__init__", observe_control),
                patch.object(windows_job.WindowsJob, "graceful", observe_stop),
            ):
                credential_grants.Store().approve(
                    url, engagement, target, "env", "NM2_FAULT_REFERENCE", 300
                )
                client = api.VardrMapClient(url, key, retries=0)
                # Only this injected transport waits for a genuinely late HTTP response.
                # Production API timeout remains (1,1), unchanged and separately used
                # by all other cases. No Control callback is replaced.
                if mode == "control_delay":
                    original_post = client.session.post

                    def slow_transport(address, **kw):
                        if address.endswith("/control"):
                            kw["timeout"] = (1, 15)
                        return original_post(address, **kw)

                    client.session.post = slow_transport
                job = next(j for j in client.pending_jobs() if j["id"] == job_id)
                journal_path = trial / "jobs.sqlite3"
                journal = Journal(journal_path)

                def trigger():
                    try:
                        wait_for(
                            lambda: (
                                len(list(trial.glob("*.partial"))) == 3 and fault.control_ok >= 2
                            )
                        )
                        control = controls[0]
                        measurements["fault_armed"] = time.monotonic()
                        fault.armed.set()
                        # Let any previously accepted refresh settle before sampling;
                        # the single refresh thread is then dropped or held in HTTP.
                        if mode == "control_drop":
                            wait_for(lambda: fault.dropped > 0)
                        elif mode == "control_delay":
                            wait_for(fault.waiting.is_set)
                        with control._lock:
                            measurements["last_verified_deadline"] = control.deadline
                        if mode.startswith("finish_"):
                            jobs.stop_job(journal.list()[0].run_id)
                        elif mode == "control_delay":
                            wait_for(
                                lambda: (
                                    time.monotonic() >= measurements["last_verified_deadline"] + 0.3
                                )
                            )
                            measurements["late_response_released"] = time.monotonic()
                            fault.release.set()
                    except BaseException as exc:
                        trigger_errors.append(type(exc).__name__)
                        fault.release.set()
                        journal.request_stop(journal.list()[0].run_id)

                trigger_thread = threading.Thread(target=trigger, daemon=True)
                trigger_thread.start()
                started = time.monotonic()
                jobs._execute_one(
                    client,
                    Console(quiet=True),
                    job,
                    True,
                    journal_store=journal,
                    backend_url=url,
                    controlled=True,
                    concurrency_budget=True,
                    target_budget=True,
                    duration_budget=120,
                    expiring_grants=True,
                )
                trigger_thread.join(20)
                assert not trigger_thread.is_alive() and not trigger_errors, trigger_errors
                pids = [int(p.read_text()) for p in trial.glob("*.pid")]
                assert len(pids) == 3 and not any(windows_job.process_running(p) for p in pids)
                measurements["terminated"] = time.monotonic()
                record = journal.list()[0]
                assert record.phase == Phase.EXECUTING and record.status == "cancelled", (
                    record.phase,
                    record.status,
                )
                expected_reason = (
                    "local_emergency_stop"
                    if mode.startswith("finish_")
                    else "control_lease_expired"
                )
                assert record.failure_reason == expected_reason, record.failure_reason
                assert fault.counts[f"/jobs/{job_id}/claim"] == 1
                assert fault.counts[f"/jobs/{job_id}/execution-finish"] == 1
                assert fault.finish_commits == (1 if mode == "finish_after_commit" else 0)
                assert len(executions) == 1 and len(list(trial.glob("*.partial"))) == 3
                assert measurements["terminated"] - started < 40  # Well below 90/120/300s limits.
                if mode.startswith("control_"):
                    assert measurements["stop_requested"] >= measurements["last_verified_deadline"]
                    assert (
                        measurements["stop_requested"] - measurements["last_verified_deadline"] < 1
                    )
                if mode == "control_delay":
                    wait_for(fault.returned.is_set)
                    wait_for(lambda: not controls[0]._thread.is_alive())
                    assert fault.delayed_action == "continue"
                    assert controls[0].stop_reason() == "control_lease_expired"
                    assert controls[0].deadline == measurements["last_verified_deadline"]
                fault.armed.clear()  # Restore actual transport, not the permission.
                # Wait for the actual persisted server lease; never manipulate its clock.
                with Session(engine) as db:
                    expiry = db.get(JobExecution, job_id).expires_at.replace(tzinfo=timezone.utc)
                wait_for(lambda: datetime.now(timezone.utc) > expiry + timedelta(milliseconds=100))
                late = client.execution_control(job_id, fault.payload)
                assert late["action"] == "cancel"
                assert controls[0].stop_reason() == expected_reason
                state = request("GET", f"/jobs/{job_id}/execution")
                expected_state = "cancelled" if mode == "finish_after_commit" else "uncertain"
                assert state["state"] == expected_state
                with Session(engine) as db:
                    row = db.get(JobExecution, job_id)
                    owner_digest = row.token_hash
                    assert row.capacity_reserved is (mode != "finish_after_commit")
                    eng = db.get(Engagement, engagement)
                    assert (eng.targets_spent, eng.duration_allocated) == (1, 120)
                before_recovery = dict(fault.counts)
                reloaded = Journal(journal_path)
                recovered = recovery.reconcile(reloaded, client, url)
                assert asdict(recovered) == {
                    "examined": 1,
                    "recovered": 0,
                    "failed": 0,
                    "deferred": 1,
                    "foreign_backend": 0,
                }
                assert fault.counts == before_recovery, "recovery made a transport call"
                try:
                    jobs._execute_one(
                        client,
                        Console(quiet=True),
                        job,
                        True,
                        journal_store=reloaded,
                        backend_url=url,
                        controlled=True,
                    )
                except errors.RunnerError:
                    pass
                else:
                    raise AssertionError("unfinished same attempt must not execute again")
                assert fault.counts == before_recovery and len(executions) == 1
                with Session(engine) as db:
                    assert db.get(JobExecution, job_id).token_hash == owner_digest
                    eng = db.get(Engagement, engagement)
                    assert (eng.targets_spent, eng.duration_allocated) == (1, 120)
                partials = [
                    {"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in sorted(trial.glob("*.partial"))
                ]
                receipts.append(
                    {
                        "case": mode,
                        "processes_stopped": 3,
                        "partial_files": partials,
                        "fixture_tree_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                        "elapsed_seconds": round(measurements["terminated"] - started, 4),
                        "stop_after_last_lease_deadline_seconds": round(
                            measurements["stop_requested"] - measurements["last_verified_deadline"],
                            4,
                        ),
                        "stop_to_verified_termination_seconds": round(
                            measurements["terminated"] - measurements["stop_requested"], 4
                        ),
                        "last_permission_anchor_to_stop_seconds": round(
                            measurements["stop_requested"]
                            - measurements["last_verified_deadline"]
                            + 10,
                            4,
                        ),
                        "last_permission_anchor_to_verified_termination_seconds": round(
                            measurements["terminated"]
                            - measurements["last_verified_deadline"]
                            + 10,
                            4,
                        ),
                        "late_response_after_deadline_seconds": round(
                            measurements["late_response_released"]
                            - measurements["last_verified_deadline"],
                            4,
                        )
                        if mode == "control_delay"
                        else None,
                        "stop_reason": expected_reason,
                        "late_http_continue_rejected": mode == "control_delay",
                        "finish_server_commits": fault.finish_commits,
                        "finish_client_acknowledged": False,
                        "map_state": state["state"],
                        "capacity_reserved": mode != "finish_after_commit",
                        "journal_phase": record.phase.value,
                        "recovery": asdict(recovered),
                        "recovery_transport_calls": 0,
                        "same_attempt_relaunches": 0,
                        "claim_calls": 1,
                        "finish_calls": 1,
                        "target_charge": 1,
                        "duration_allocated_seconds": 120,
                        "tool_timeout_seconds": 90,
                        "grant_ttl_seconds": 300,
                        "control_http_read_timeout_seconds": 15 if mode == "control_delay" else 1,
                    }
                )
                client.session.close()
                print(f"PASS {mode}: {state['state']}; retained accounting; recovery deferred")

        for mode in (
            "control_drop",
            "control_delay",
            "finish_before_commit",
            "finish_after_commit",
        ):
            scenario(mode)
    finally:
        fault.release.set()
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(5)
        server.should_exit = True
        thread.join(5)
        listener.close()
        engine.dispose()
    receipt = {
        "schema": "vardr.nm2-native-faults/1",
        "cases": receipts,
        "scope": "real Map loopback HTTP through disposable fault proxy; native synthetic tree",
        "database": "disposable SQLite; no new PostgreSQL concurrency claim",
        "gate_execution": False,
        "managed_signed_authorization": False,
        "unsupported_controlled_profiles": ["Linux", "Docker", "ffuf"],
    }
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
