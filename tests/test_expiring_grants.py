"""Local reference-grant authority, stale state and actual launch boundaries."""

import copy
import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from vardrrunner import config, execution_control, handlers, launch_guard, runner
from vardrrunner import credential_grants as grants

ISSUER = "https://map.example.test"
ORIGIN = "http://127.0.0.1:17001"
ENGAGEMENT = "synthetic-engagement"
REFERENCE = "SYNTHETIC_GATE_TOKEN"


def case():
    return {
        "id": "synthetic",
        "request": {"method": "GET", "url": ORIGIN + "/resource"},
        "identities": [{"id": "owner", "credential": {"type": "bearer", "value_env": REFERENCE}}],
    }


def approve(seconds=60, **changes):
    args = {
        "authority": ISSUER,
        "engagement": ENGAGEMENT,
        "origin": ORIGIN,
        "source": "env",
        "name": REFERENCE,
        "seconds": seconds,
    }
    args.update(changes)
    return grants.Store().approve(**args)


def check(test_case=None, engagement=ENGAGEMENT):
    handlers.check_gate_case(test_case or case(), engagement)


def test_expiry_denial_is_durable_across_clock_rollback(monkeypatch):
    clock = [datetime(2026, 11, 2, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr(grants, "now", lambda: clock[0])
    approve(seconds=10)
    clock[0] += timedelta(seconds=11)
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="expired"):
        check()
    clock[0] -= timedelta(seconds=3)  # t8 is after issuance but before expiry.
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="clock_rollback"):
        check()


@pytest.mark.parametrize("changed", ["issuer", "engagement", "origin", "provider", "reference"])
def test_wrong_binding_never_reads_provider(changed, monkeypatch):
    approve()
    test_case = case()
    authority, engagement = ISSUER, ENGAGEMENT
    if changed == "issuer":
        authority = "standalone"
    if changed == "engagement":
        engagement = "other-engagement"
    if changed == "origin":
        test_case["request"]["url"] = "http://127.0.0.1:17002/resource"
    if changed == "provider":
        test_case["identities"][0]["credential"] = {"type": "bearer", "value_keychain": REFERENCE}
    if changed == "reference":
        test_case["identities"][0]["credential"]["value_env"] = "OTHER_REFERENCE"
    with grants.required(authority), patch.object(handlers, "_resolve_one_credential") as resolve:
        with pytest.raises(grants.GrantError):
            handlers._resolve_identity_secrets(test_case, engagement)
        resolve.assert_not_called()


def test_legacy_approval_is_not_a_fallback():
    config.approve_credential(ENGAGEMENT, ORIGIN, "env", REFERENCE)
    check()  # The legacy path retains its existing semantics.
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="missing"):
        check()
    assert config.credential_approved(ENGAGEMENT, ORIGIN, "env", REFERENCE)


def test_revocation_and_reapproval_cannot_replace_inflight_snapshot():
    first = approve()
    with grants.required(ISSUER):
        check()
        assert grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "env", REFERENCE)
        with pytest.raises(grants.GrantError, match="revoked"):
            check()
        second = approve()
        assert first["id"] != second["id"]
        with pytest.raises(grants.GrantError, match="replaced"):
            check()
    with grants.required(ISSUER):
        check()


def test_stale_config_cannot_resurrect_a_revocation():
    approve()
    old = copy.deepcopy(config.load())
    grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "env", REFERENCE)
    config.save(old)  # Simulate another config writer overwriting a stale copy.
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="stale"):
        check()


@pytest.mark.parametrize(
    "replacement", [None, [], {}, {"schema_version": True, "revision": 0, "grants": []}]
)
def test_malformed_or_missing_catalog_is_never_repaired_implicitly(replacement):
    approve()
    data = config.load()
    data[grants.KEY] = replacement
    config.save(data)
    with grants.required(ISSUER), pytest.raises(grants.GrantError):
        check()


@pytest.mark.parametrize("reference", [True, 17, "", None, " " + REFERENCE, REFERENCE + " "])
def test_noncanonical_case_reference_denied(reference):
    approve()
    value = case()
    value["identities"][0]["credential"]["value_env"] = reference
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="malformed"):
        check(value)


def test_provider_failure_cannot_echo_a_secret(monkeypatch):
    approve(source="keychain")
    value = case()
    value["identities"][0]["credential"] = {"type": "bearer", "value_keychain": REFERENCE}
    with (
        grants.required(ISSUER),
        patch.object(
            handlers.keychain,
            "get_secret",
            side_effect=RuntimeError("synthetic-private-provider-value"),
        ),
    ):
        with pytest.raises(grants.GrantError) as error:
            handlers._resolve_identity_secrets(value, ENGAGEMENT)
    assert "synthetic-private-provider-value" not in str(error.value)


def test_revocation_during_provider_resolution_denies_use(monkeypatch):
    approve(source="keychain")
    value = case()
    value["identities"][0]["credential"] = {"type": "bearer", "value_keychain": REFERENCE}

    def resolve(_):
        grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "keychain", REFERENCE)
        return "synthetic-private-provider-value"

    with (
        grants.required(ISSUER),
        patch.object(handlers.keychain, "get_secret", side_effect=resolve),
    ):
        with pytest.raises(grants.GrantError, match="revoked"):
            handlers._resolve_identity_secrets(value, ENGAGEMENT)


def test_real_process_creation_and_concurrent_revocation(tmp_path):
    approve()
    attempted, completed = threading.Event(), threading.Event()

    def revoke():
        attempted.set()
        grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "env", REFERENCE)
        completed.set()

    with grants.required(ISSUER):
        check()
        with launch_guard.boundary():
            thread = threading.Thread(target=revoke)
            thread.start()
            assert attempted.wait(1)
            time.sleep(0.1)
            assert not completed.is_set()
            # Use Popen directly inside this already-held boundary to avoid
            # recursively acquiring the same database transaction.
            import subprocess

            marker = tmp_path / "started"
            child = subprocess.Popen(
                [sys.executable, "-c", f"open({str(marker)!r},'w').write('started')"],
                stdin=subprocess.DEVNULL,
                env=config.tool_environment(),
            )
        thread.join(timeout=3)
        assert completed.is_set()
        assert child.wait(timeout=3) == 0 and marker.read_text() == "started"
        with pytest.raises(grants.GrantError, match="revoked"), patch("subprocess.Popen") as spawn:
            runner._spawn_tool(["never-launch"])
        spawn.assert_not_called()


def test_grant_expiry_during_private_file_preparation(tmp_path, monkeypatch):
    import tempfile

    clock = [datetime(2026, 11, 2, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr(grants, "now", lambda: clock[0])
    approve(seconds=10)
    original = runner._write_private_job

    def prepared(payload):
        output = original(payload)
        clock[0] += timedelta(seconds=11)
        return output

    monkeypatch.setattr(runner, "_write_private_job", prepared)
    monkeypatch.setattr(runner, "program", lambda _: "never-launch")
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    with grants.required(ISSUER):
        check()
        with patch("subprocess.Popen") as spawn, pytest.raises(grants.GrantError, match="expired"):
            runner.run_vardrgate({"config": {"test_case": case()}}, tmp_path / "result.json")
        spawn.assert_not_called()
    assert not list(tmp_path.glob("vardrrunner-vardrgate-*"))


@pytest.mark.parametrize("native_job", [False, True])
@pytest.mark.skipif(os.name != "nt", reason="real Windows creation and containment boundary")
def test_post_creation_guard_failure_owns_and_stops_real_process(tmp_path, native_job):
    from vardrrunner.windows_job import WindowsJob, process_running

    marker = tmp_path / "partial"
    pidfile = tmp_path / "pid"
    code = f"import os,time;open({str(pidfile)!r},'w').write(str(os.getpid()));open({str(marker)!r},'w').write('partial evidence');time.sleep(15)"

    @contextmanager
    def failing_exit():
        yield
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise grants.GrantError("injected_commit_failure")

    observed = []
    with launch_guard.install(failing_exit), runner.observe_process(observed.append):
        with pytest.raises(execution_control.ExecutionStopped, match="post_creation") as error:
            if native_job:
                WindowsJob([sys.executable, "-c", code], config.tool_environment())
            else:
                runner._spawn_tool([sys.executable, "-c", code])
    assert error.value.pid is not None
    assert native_job or observed == [error.value.pid]
    until = time.monotonic() + 3
    while process_running(int(pidfile.read_text())) and time.monotonic() < until:
        time.sleep(0.02)
    assert not process_running(int(pidfile.read_text()))
    assert marker.read_text() == "partial evidence"
    if not native_job:
        assert not error.value.confirmed  # legacy fallback is conservative


@pytest.mark.parametrize("native_job", [False, True])
@pytest.mark.skipif(os.name != "nt", reason="Windows creation boundary")
def test_grant_lock_wait_cannot_outlive_signed_deadline(tmp_path, monkeypatch, native_job):
    approve()
    held = threading.Event()
    original = launch_guard.boundary
    creation = []

    def hold():
        with grants.Store().transaction():
            held.set()
            time.sleep(1.5)

    @contextmanager
    def witness():
        with original():
            creation.append(True)
            yield

    monkeypatch.setattr(launch_guard, "boundary", witness)
    monkeypatch.setattr(runner, "program", lambda _: sys.executable)
    with grants.required(ISSUER):
        check()
        thread = threading.Thread(target=hold)
        thread.start()
        assert held.wait(2)
        control = execution_control.Control(
            lambda: {}, {}, 10, started=time.monotonic(), local_stop=lambda: False
        )
        from contextlib import nullcontext

        try:
            with (
                execution_control.controlled(control) if native_job else nullcontext(),
                pytest.raises(runner.ToolTimeout, match="authorization deadline"),
            ):
                runner.run_vardrgate(
                    {"config": {"test_case": case()}},
                    tmp_path / "result.json",
                    execution_deadline=time.time() + 1.1,
                )
        finally:
            thread.join(3)
    assert not creation  # No Popen/CreateProcess body was entered, hence no target requests.


@pytest.mark.parametrize("denied", [False, True])
def test_store_connection_closes_on_success_and_denial(monkeypatch, denied):
    import sqlite3

    approve()
    connected, closed = [], []
    original = sqlite3.connect

    class Tracked(sqlite3.Connection):
        def close(self):
            closed.append(self)
            super().close()

    def connect(*args, **kwargs):
        con = original(*args, **kwargs, factory=Tracked)
        connected.append(con)
        return con

    monkeypatch.setattr(grants.sqlite3, "connect", connect)
    if denied:
        with pytest.raises(grants.GrantError):
            with grants.Store().transaction():
                raise grants.GrantError("injected_denial")
    else:
        grants.Store().entries()
    assert connected and connected == closed


@pytest.mark.parametrize("phase", ["setup", "preflight", "verification", "reset"])
def test_auxiliary_origins_require_grants(phase):
    approve()
    value = case()
    request = {"method": "GET", "url": "http://127.0.0.1:17002/auxiliary"}
    if phase == "setup":
        value["setup"] = [{"request": request}]
    elif phase == "preflight":
        value["identities"][0]["preflight"] = request
    else:
        value["write_verification"] = (
            {"request": request} if phase == "verification" else {"reset": {"request": request}}
        )
    with grants.required(ISSUER), pytest.raises(grants.GrantError, match="missing"):
        check(value)


def test_secret_never_enters_catalog_or_audit(monkeypatch):
    import sqlite3

    secret = "synthetic-private-value-must-not-persist"
    monkeypatch.setenv(REFERENCE, secret)
    approve()
    with grants.required(ISSUER):
        resolved = handlers._resolve_identity_secrets(case(), ENGAGEMENT)
        assert resolved["identities"][0]["credential"]["value"] == secret
    grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "env", REFERENCE)
    from contextlib import closing

    with closing(sqlite3.connect(config.journal_file())) as con:
        dump = "\n".join(con.iterdump())
    assert secret not in config.CONFIG_FILE.read_text() + dump
    assert REFERENCE not in dump and ORIGIN not in dump


@pytest.mark.parametrize("action", ["revoke", "expire"])
def test_environment_preparation_rechecks_grant(tmp_path, monkeypatch, action):
    clock = [grants.now()]
    monkeypatch.setattr(grants, "now", lambda: clock[0])
    approve(seconds=10)
    original = config.tool_environment

    def environment():
        if action == "revoke":
            grants.Store().revoke(ISSUER, ENGAGEMENT, ORIGIN, "env", REFERENCE)
        else:
            clock[0] += timedelta(seconds=11)
        return original()

    monkeypatch.setattr(config, "tool_environment", environment)
    with grants.required(ISSUER):
        check()
        with patch("subprocess.Popen") as spawn, pytest.raises(grants.GrantError):
            runner._spawn_tool(["never-launch"])
        spawn.assert_not_called()


def test_deadline_context_never_extends_outer_permission(monkeypatch):
    clock, monotonic = [100.0], [1.0]
    monkeypatch.setattr(launch_guard.time, "time", lambda: clock[0])
    monkeypatch.setattr(launch_guard.time, "monotonic", lambda: monotonic[0])
    with launch_guard.deadline(110), launch_guard.deadline(200):
        assert launch_guard.timeout(30) == 10
        clock[0] = 90  # Wall-clock rollback cannot extend the monotonic deadline.
        monotonic[0] = 12
        with pytest.raises(launch_guard.DeadlineExpired):
            launch_guard.require_deadline()
    assert launch_guard.timeout(30) == 30


@pytest.mark.parametrize("native_job", [False, True])
@pytest.mark.skipif(os.name != "nt", reason="Windows supervised deadline")
def test_signed_deadline_stops_running_process(tmp_path, native_job):
    marker = tmp_path / "pid"
    code = f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));time.sleep(10)"
    from contextlib import nullcontext

    control = execution_control.Control(
        lambda: {}, {}, 10, started=time.monotonic(), local_stop=lambda: False, grace=0.05
    )
    started = time.monotonic()
    with (
        launch_guard.deadline(time.time() + 0.6),
        execution_control.controlled(control) if native_job else nullcontext(),
    ):
        if native_job:
            with pytest.raises(execution_control.ExecutionStopped, match="authorization_deadline"):
                runner._run_tool_status([sys.executable, "-c", code], None, "fixture", 10)
        else:
            with pytest.raises(runner.ToolTimeout):
                runner._run_tool_status([sys.executable, "-c", code], None, "fixture", 10)
    from vardrrunner.windows_job import process_running

    assert marker.exists() and not process_running(int(marker.read_text()))
    assert time.monotonic() - started < 4


@pytest.mark.parametrize("signed_deadline", [None, 60])
@pytest.mark.skipif(os.name != "nt", reason="Windows native permit-to-creation boundary")
def test_grant_expiry_during_controlled_permission_callback(tmp_path, monkeypatch, signed_deadline):
    from unittest.mock import Mock

    from vardrrunner import windows_job
    from vardrrunner.windows_job import WindowsJob

    native_library = windows_job.ctypes.WinDLL
    creates = []

    def library(*args, **kwargs):
        api = native_library(*args, **kwargs)
        api.CreateProcessW = Mock(side_effect=AssertionError("creation must be refused"))
        creates.append(api.CreateProcessW)
        return api

    monkeypatch.setattr(windows_job.ctypes, "WinDLL", library)
    clock = [grants.now()]
    monkeypatch.setattr(grants, "now", lambda: clock[0])
    approve(seconds=1)
    marker = tmp_path / "never-created"
    code = f"open({str(marker)!r},'w').write('bad')"

    def delayed_permission():
        # Deterministic equivalent of a blocked local-stop journal read. The
        # callback runs after grant-lock acquisition, without a second writer.
        clock[0] += timedelta(seconds=2)

    with grants.required(ISSUER):
        check()
        with launch_guard.deadline(time.time() + signed_deadline if signed_deadline else None):
            with pytest.raises(grants.GrantError, match="expired"):
                WindowsJob(
                    [sys.executable, "-c", code], config.tool_environment(), delayed_permission
                )
    assert not marker.exists()
    # Journal name pins also load kernel32. Every actual process-creation
    # entrypoint must remain uncalled, regardless of unrelated library loads.
    assert creates
    for create in creates:
        create.assert_not_called()
