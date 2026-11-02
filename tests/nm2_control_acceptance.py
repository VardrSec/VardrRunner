"""Explicit cross-repository loopback acceptance; run in Map's test environment.

No real tool/target, retained installation, API key, or external service is used.
The fixture uses real HTTP, the real job lifecycle, journal and OS process tree.
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
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--map-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(exist_ok=False)
    os.environ.update(
        DATABASE_URL="sqlite:///" + (root / "fixture.db").as_posix(),
        BACKEND_JWT_SECRET="nm2-disposable-local-authentication-only-0123456789",
        ENV="test",
        ALLOWED_ORIGINS="http://localhost:3000",
    )
    sys.path.insert(0, str(args.map_source.resolve() / "backend"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import jwt
    import requests
    import uvicorn
    from db import Base, engine
    from main import app
    from models import ApiKey, ScopeItem, User
    from rich.console import Console
    from sqlalchemy.orm import Session

    from vardrrunner import api, config, handlers, identity, runner
    from vardrrunner.commands import jobs
    from vardrrunner.journal import Journal, Phase
    from vardrrunner.windows_job import process_running

    Base.metadata.create_all(engine)
    key = "vmap_" + uuid.uuid4().hex
    with Session(engine) as db:
        db.add(User(github_id="nm2-fixture", username="fixture"))
        db.commit()
        db.add(
            ApiKey(
                github_id="nm2-fixture",
                key_hash=hashlib.sha256(key.encode()).hexdigest(),
                scope="runner",
            )
        )
        db.commit()
    token = jwt.encode(
        {
            "sub": "nm2-fixture",
            "aud": "vardrmap-backend",
            "iss": "vardrmap-frontend",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        os.environ["BACKEND_JWT_SECRET"],
        algorithm="HS256",
    )
    headers = {"Authorization": "Bearer " + token}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    until = time.monotonic() + 10
    while not server.started and time.monotonic() < until:
        time.sleep(0.02)
    assert server.started
    original = handlers.REGISTRY["httpx"]
    original_available = runner.tool_available
    original_make = jobs._make_run_dir
    original_data, original_config, original_journal = (
        config.DATA_DIR,
        config.CONFIG_FILE,
        config.JOURNAL_FILE,
    )
    receipts = []
    try:

        def scenario(mode):
            trial = root / mode
            trial.mkdir()
            config.DATA_DIR = trial
            config.CONFIG_FILE = trial / "config.json"
            config.JOURNAL_FILE = trial / "journal.db"
            identity.identity_file = lambda: trial / "identity.json"
            store = Journal(config.JOURNAL_FILE)
            response = requests.post(
                url + "/engagements",
                json={"name": "NM2 synthetic fixture"},
                headers=headers,
                timeout=2,
            )
            response.raise_for_status()
            engagement = response.json()["id"]
            with Session(engine) as db:
                db.add(
                    ScopeItem(
                        program_id=engagement, value="http://127.0.0.1", kind="url", scope_type="in"
                    )
                )
                db.commit()
            response = requests.post(
                url + f"/engagements/{engagement}/jobs",
                json={"tool_type": "httpx", "target_source": "scope"},
                headers=headers,
                timeout=2,
            )
            response.raise_for_status()
            job = response.json()
            job["engagement_id"] = engagement
            fixture = trial / "tree.py"
            fixture.write_text("""import os, signal, subprocess, sys, time
from pathlib import Path
root, depth = Path(sys.argv[1]), int(sys.argv[2])
signal.signal(signal.SIGTERM, lambda *_: None)
if hasattr(signal,"SIGBREAK"): signal.signal(signal.SIGBREAK, lambda *_: None)
child=subprocess.Popen([sys.executable,__file__,str(root),str(depth-1)]) if depth else None
(root/(str(depth)+".pid")).write_text(str(os.getpid()))
(root/(str(depth)+".partial")).write_text("partial synthetic evidence")
while True: time.sleep(.05)
""")

            class Fixture(handlers.HttpxHandler):
                def execute(self, targets, run_dir, cfg):
                    runner._run_tool(
                        [sys.executable, str(fixture), str(trial), "2"], None, "fixture", 20
                    )
                    raise AssertionError("cancelled tool must not complete")

                def upload(self, *a, **kw):
                    raise AssertionError("partial output must not upload as completed")

            handlers.REGISTRY["httpx"] = Fixture()
            runner.tool_available = lambda _: True
            jobs._make_run_dir = lambda: trial
            client = api.VardrMapClient(url, key, retries=0)
            if mode == "disconnect":

                def unavailable(*a, **kw):
                    raise OSError("synthetic lost control connectivity")

                client.execution_control = unavailable
            triggered = threading.Event()
            trigger_result = []

            def stop():
                limit = time.monotonic() + 8
                while len(list(trial.glob("*.partial"))) < 3 and time.monotonic() < limit:
                    time.sleep(0.02)
                if len(list(trial.glob("*.partial"))) != 3:
                    trigger_result.append("fixture_not_ready")
                    return
                if mode == "remote_stop":
                    r = requests.post(
                        url + f"/engagements/{engagement}/stop-work",
                        headers=headers,
                        json={"reason": "synthetic stop"},
                        timeout=2,
                    )
                    trigger_result.append(r.status_code)
                elif mode == "local_stop":
                    jobs.stop_job(store.unfinished()[0].run_id)
                    trigger_result.append("requested")
                triggered.set()

            stopper = threading.Thread(target=stop)
            stopper.start()
            started = time.monotonic()
            jobs._execute_one(
                client,
                Console(quiet=True),
                job,
                True,
                journal_store=store,
                backend_url=url,
                controlled=True,
            )
            elapsed = time.monotonic() - started
            stopper.join(timeout=2)
            assert triggered.is_set(), trigger_result
            assert mode != "remote_stop" or trigger_result == [200]
            records = store.list()
            assert len(records) == 1
            record = records[0]
            assert record.status == "cancelled"
            assert record.phase == (Phase.EXECUTING if mode == "disconnect" else Phase.INTERRUPTED)
            pids = [int(path.read_text()) for path in trial.glob("*.pid")]
            assert len(pids) == 3 and not any(process_running(pid) for pid in pids)
            state = requests.get(url + f"/jobs/{job['id']}/execution", headers=headers, timeout=2)
            state.raise_for_status()
            assert state.json()["state"] == ("uncertain" if mode == "disconnect" else "cancelled")
            receipts.append(
                {
                    "scenario": mode,
                    "elapsed_seconds": round(elapsed, 3),
                    "processes": 3,
                    "all_stopped": True,
                    "partial_files": 3,
                    "journal_phase": record.phase.value,
                    "map_state": state.json()["state"],
                    "map_termination_confirmed": state.json()["termination_confirmed"],
                }
            )

        for mode in ["remote_stop", "local_stop", "disconnect"]:
            scenario(mode)
    finally:
        handlers.REGISTRY["httpx"] = original
        runner.tool_available = original_available
        jobs._make_run_dir = original_make
        config.DATA_DIR, config.CONFIG_FILE, config.JOURNAL_FILE = (
            original_data,
            original_config,
            original_journal,
        )
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        engine.dispose()
    receipt = {
        "schema": "vardr.nm2-cancellation-acceptance/1",
        "scenarios": receipts,
        "scope": "real loopback Map HTTP and real synthetic process trees; no scanner or external target",
        "strict_authorization": "not claimed; controlled manual legacy jobs only",
        "linux_postgres": "not exercised by this native Windows/SQLite receipt",
    }
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
