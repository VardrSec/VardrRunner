"""Native per-user service plans and safe command execution."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
import typer

from vardrrunner import service
from vardrrunner.commands import service as service_cmd


def test_linux_plan_is_user_scoped_and_uses_json_logs(tmp_path):
    (tmp_path / "runner.env").write_text("VARDRMAP_URL=https://example.com\n")
    (tmp_path / "runner.env").chmod(0o600)
    plan = service.build_plan(
        executable=tmp_path / "bin" / "vardrrunner",
        system="Linux",
        home=tmp_path,
        env_file=tmp_path / "runner.env",
    )
    assert plan.kind == "systemd-user"
    assert plan.definition_path == tmp_path / ".config/systemd/user/vardrrunner.service"
    assert '--log-format" "json' in plan.definition
    assert "EnvironmentFile=" in plan.definition
    assert "VARDRMAP_API_KEY" not in plan.definition
    assert plan.start_command[:2] == ("systemctl", "--user")
    assert plan.environment_file == tmp_path / "runner.env"


def test_linux_plan_requires_existing_environment_file(tmp_path):
    with pytest.raises(service.ServiceError, match="does not exist"):
        service.build_plan(
            executable=tmp_path / "runner",
            system="Linux",
            home=tmp_path,
            env_file=tmp_path / "missing.env",
        )


def test_linux_plan_rejects_exposed_environment_file(tmp_path):
    env_file = tmp_path / "runner.env"
    env_file.write_text("VARDRMAP_API_KEY=secret\n")
    with (
        patch("vardrrunner.service.os", SimpleNamespace(name="posix")),
        patch("vardrrunner.service.stat.S_IMODE", return_value=0o644),
        pytest.raises(service.ServiceError, match="chmod 600"),
    ):
        service.build_plan(
            executable=tmp_path / "runner", system="Linux", home=tmp_path, env_file=env_file
        )


def test_windows_plan_uses_scheduled_task_without_shell(tmp_path):
    plan = service.build_plan(
        executable=tmp_path / "Vardr Runner" / "vardrrunner.exe",
        system="Windows",
        home=tmp_path,
    )
    assert plan.kind == "scheduled-task"
    assert plan.definition_path is None
    assert plan.install_commands[0][0] == "schtasks.exe"
    assert "/TR" in plan.install_commands[0]


def test_macos_plan_is_valid_plist(tmp_path):
    with patch("vardrrunner.service.os.getuid", return_value=501, create=True):
        plan = service.build_plan(
            executable=tmp_path / "vardrrunner", system="Darwin", home=tmp_path
        )
    assert plan.kind == "launchd-user"
    assert "com.vardrsec.vardrrunner" in plan.definition
    assert plan.start_command[:2] == ("launchctl", "bootstrap")


def test_unsupported_system_and_missing_executable_fail(tmp_path):
    with patch("vardrrunner.service.shutil.which", return_value=None):
        with pytest.raises(service.ServiceError, match="not on PATH"):
            service.build_plan(system="Linux", home=tmp_path)
    with pytest.raises(service.ServiceError, match="unsupported"):
        service.build_plan(executable=tmp_path / "runner", system="Haiku", home=tmp_path)
    with pytest.raises(service.ServiceError, match="only by systemd"):
        service.build_plan(
            executable=tmp_path / "runner",
            system="Windows",
            home=tmp_path,
            env_file=tmp_path / "runner.env",
        )


def test_install_writes_definition_then_runs_commands(tmp_path):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    with patch("vardrrunner.service._run") as run:
        service.install(plan, start=True)
    assert plan.definition_path.exists()
    assert run.call_args_list == [call(plan.install_commands[0]), call(plan.start_command)]


def test_uninstall_disables_deletes_then_reloads(tmp_path):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    plan.definition_path.parent.mkdir(parents=True)
    plan.definition_path.write_text("unit")
    observed = []

    def record(command, **_kwargs):
        observed.append((command, plan.definition_path.exists()))
        return MagicMock(returncode=0)

    with patch("vardrrunner.service._run", side_effect=record):
        service.uninstall(plan)
    assert observed[0][1] is True
    assert observed[1][1] is False
    assert not plan.definition_path.exists()


def test_status_and_run_error_paths(tmp_path):
    plan = service.build_plan(executable=tmp_path / "runner", system="Windows", home=tmp_path)
    with patch("vardrrunner.service._run", return_value=MagicMock(returncode=0, stdout="Ready")):
        assert service.status(plan) == (True, "Ready")
    with patch("vardrrunner.service.subprocess.run", side_effect=OSError("missing")):
        with pytest.raises(service.ServiceError, match="missing"):
            service._run(("tool",))
    result = MagicMock(returncode=2, stderr="token=vmap_abcdefghi")
    with patch("vardrrunner.service.subprocess.run", return_value=result):
        with pytest.raises(service.ServiceError) as exc:
            service._run(("tool",))
    assert "vmap_abcdefghi" not in str(exc.value)


def test_service_commands_dry_run_and_errors(tmp_path, capsys):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    with patch("vardrrunner.commands.service._plan", return_value=plan):
        service_cmd.install(dry_run=True)
    assert "systemd-user" in capsys.readouterr().out
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service._preflight"),
        patch(
            "vardrrunner.commands.service.service.install", side_effect=service.ServiceError("x")
        ),
    ):
        with pytest.raises(typer.Exit):
            service_cmd.install()


def test_service_command_success_status_and_uninstall(tmp_path, capsys):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service._preflight"),
        patch("vardrrunner.commands.service.service.install") as install,
    ):
        service_cmd.install(start=False)
    install.assert_called_once_with(plan, start=False)
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service.service.status", return_value=(True, "running")),
    ):
        service_cmd.show_status()
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service.service.uninstall") as uninstall,
    ):
        service_cmd.uninstall()
    uninstall.assert_called_once_with(plan)
    assert "running" in capsys.readouterr().out


def test_service_command_failure_paths(tmp_path):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    with patch(
        "vardrrunner.commands.service.service.build_plan", side_effect=service.ServiceError("bad")
    ):
        with pytest.raises(typer.Exit):
            service_cmd._plan()
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service._preflight"),
        patch(
            "vardrrunner.commands.service.service.uninstall",
            side_effect=service.ServiceError("bad"),
        ),
    ):
        with pytest.raises(typer.Exit):
            service_cmd.uninstall()
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch(
            "vardrrunner.commands.service.service.status",
            side_effect=service.ServiceError("bad"),
        ),
    ):
        with pytest.raises(typer.Exit):
            service_cmd.show_status()


def test_service_status_without_detail(tmp_path, capsys):
    plan = service.build_plan(executable=tmp_path / "runner", system="Linux", home=tmp_path)
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service.service.status", return_value=(False, "")),
    ):
        service_cmd.show_status()
    assert "not active" in capsys.readouterr().out


def test_service_preflight_failure_exits():
    plan = MagicMock(environment_file=None)
    with patch(
        "vardrrunner.commands.service.config.require_auth", side_effect=RuntimeError("no auth")
    ):
        with pytest.raises(typer.Exit):
            service_cmd._preflight(plan)


def test_service_preflight_rejects_shell_only_credentials():
    plan = MagicMock(environment_file=None)
    with (
        patch(
            "vardrrunner.commands.service.config.require_auth",
            return_value=("https://api.example.com", "vmap_env"),
        ),
        patch(
            "vardrrunner.commands.service.config.persistent_credential_source",
            return_value=None,
        ),
        pytest.raises(typer.Exit),
    ):
        service_cmd._preflight(plan)


def test_service_preflight_accepts_environment_file():
    plan = MagicMock(environment_file=Path("runner.env"))
    with (
        patch(
            "vardrrunner.commands.service.config.require_auth",
            return_value=("https://api.example.com", "vmap_env"),
        ),
        patch(
            "vardrrunner.commands.service.config.persistent_credential_source",
            return_value=None,
        ),
        patch("vardrrunner.commands.service.Journal"),
        patch("vardrrunner.commands.service.identity.load_or_create"),
    ):
        service_cmd._preflight(plan)


def test_plan_rejects_control_characters(tmp_path):
    with pytest.raises(service.ServiceError, match="control"):
        service.build_plan(executable=Path(str(tmp_path / "runner") + "\n"), system="Linux")
