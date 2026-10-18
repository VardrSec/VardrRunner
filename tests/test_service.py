"""Legacy service removal and rejection of every installation path."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner import service
from vardrrunner.commands import service as service_cmd


def test_uninstall_disables_deletes_then_reloads(tmp_path):
    plan = service.build_plan(system="Linux", home=tmp_path)
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
    plan = service.build_plan(system="Windows", home=tmp_path)
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


def test_service_command_failure_paths(tmp_path):
    plan = service.build_plan(system="Linux", home=tmp_path)
    with patch(
        "vardrrunner.commands.service.service.build_plan", side_effect=service.ServiceError("bad")
    ):
        with pytest.raises(typer.Exit):
            service_cmd._plan()
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
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
    plan = service.build_plan(system="Linux", home=tmp_path)
    with (
        patch("vardrrunner.commands.service._plan", return_value=plan),
        patch("vardrrunner.commands.service.service.status", return_value=(False, "")),
    ):
        service_cmd.show_status()
    assert "not active" in capsys.readouterr().out


def test_plan_rejects_control_characters(tmp_path):
    with pytest.raises(service.ServiceError, match="control"):
        service.build_plan(home=Path(str(tmp_path / "runner") + "\n"), system="Linux")


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
def test_plans_only_inspect_and_remove_legacy_services(tmp_path, system):
    with patch("vardrrunner.service.os.getuid", return_value=501, create=True):
        plan = service.build_plan(system=system, home=tmp_path)
    with patch.object(
        service, "_run", return_value=MagicMock(returncode=0, stdout="legacy")
    ) as run:
        service.status(plan)
        service.uninstall(plan)
    commands = [call.args[0] for call in run.call_args_list]
    forbidden = {"/Create", "/Run", "enable", "bootstrap", "start"}
    assert all(not forbidden.intersection(command) for command in commands)
    assert not list(tmp_path.rglob("*.service"))
    assert not list(tmp_path.rglob("*.plist"))


@pytest.mark.parametrize(
    "options",
    [{}, {"dry_run": True}, {"start": False}, {"run_jobs": True}, {"env_file": Path("runner.env")}],
)
def test_install_is_rejected_without_native_commands(options, capsys):
    with patch.object(service, "build_plan") as plan, patch.object(service, "_run") as run:
        with pytest.raises(typer.Exit) as exc:
            service_cmd.install(**options)
    assert exc.value.exit_code == 2
    plan.assert_not_called()
    run.assert_not_called()
    assert "Startup services are no longer supported" in capsys.readouterr().out


def test_unsupported_cleanup_platform(tmp_path):
    with pytest.raises(service.ServiceError, match="unsupported"):
        service.build_plan(system="Haiku", home=tmp_path)


def test_legacy_uninstall_success(tmp_path, capsys):
    plan = service.build_plan(system="Windows", home=tmp_path)
    with (
        patch.object(service_cmd, "_plan", return_value=plan),
        patch.object(service, "uninstall") as remove,
    ):
        service_cmd.uninstall()
    remove.assert_called_once_with(plan)
    assert "Removed" in capsys.readouterr().out
