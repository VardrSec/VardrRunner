"""Tests for nmap integration: runner functions and job dispatch.
All subprocess and HTTP calls are mocked.
"""

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from vardrrunner import runner
from vardrrunner.commands import jobs as jobs_cmd

# ---------------------------------------------------------------------------
# runner.run_nmap — subprocess args
# ---------------------------------------------------------------------------


def test_run_nmap_uses_safe_arg_list(tmp_path):
    output = tmp_path / "nmap.xml"
    process = MagicMock(pid=1234)
    process.wait.return_value = 0
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_nmap(["10.0.0.1", "10.0.0.2"], output, top_ports=50, timing=3)
        args = mock_spawn.call_args[0][0]

    assert isinstance(args, list)
    assert args[0] == "nmap"
    assert "-iL" in args
    assert "--top-ports" in args
    assert "50" in args
    assert "-sV" in args
    assert "--version-intensity" in args
    assert "2" in args
    assert "-T3" in args
    assert "-oX" in args
    assert str(output) in args
    assert "--open" in args
    # Must never use dangerous flags
    assert "-A" not in args
    assert "-O" not in args
    assert "-p-" not in args
    assert "--script" not in args


def test_run_nmap_clamps_timing(tmp_path):
    output = tmp_path / "nmap.xml"
    process = MagicMock(pid=1234)
    process.wait.return_value = 0
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as mock_spawn:
        runner.run_nmap(["10.0.0.1"], output, timing=9)
        args = mock_spawn.call_args[0][0]
    # timing clamped to 4
    assert "-T4" in args
    assert "-T9" not in args


def test_run_nmap_raises_on_nonzero_exit(tmp_path):
    output = tmp_path / "nmap.xml"
    process = MagicMock(pid=1234)
    process.wait.return_value = 1
    with patch("vardrrunner.runner._spawn_tool", return_value=process):
        with pytest.raises(runner.ToolError):
            runner.run_nmap(["10.0.0.1"], output)


# ---------------------------------------------------------------------------
# runner.parse_nmap_xml
# ---------------------------------------------------------------------------

_NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="target.example.com" type="user"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.24.0"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx" version="1.24.0"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")


def test_parse_nmap_xml_returns_open_ports(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(_NMAP_XML)
    services = runner.parse_nmap_xml(xml_path)
    assert len(services) == 2
    ports = {s["port"] for s in services}
    assert ports == {80, 443}


def test_parse_nmap_xml_excludes_closed(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(_NMAP_XML)
    services = runner.parse_nmap_xml(xml_path)
    assert all(s["state"] == "open" for s in services)
    assert all(s["port"] != 22 for s in services)


def test_parse_nmap_xml_prefers_hostname(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(_NMAP_XML)
    services = runner.parse_nmap_xml(xml_path)
    assert all(s["host"] == "target.example.com" for s in services)


def test_parse_nmap_xml_service_fields(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(_NMAP_XML)
    services = runner.parse_nmap_xml(xml_path)
    http_svc = next(s for s in services if s["port"] == 80)
    assert http_svc["service_name"] == "http"
    assert http_svc["product"] == "nginx"
    assert http_svc["version"] == "1.24.0"
    assert http_svc["protocol"] == "tcp"
    assert http_svc["source"] == "nmap"


def test_parse_nmap_xml_invalid_xml_returns_empty(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text("not valid xml <<<<")
    assert runner.parse_nmap_xml(xml_path) == []


def test_parse_nmap_xml_falls_back_to_ip(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames/>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh"/>
              </port>
            </ports>
          </host>
        </nmaprun>
    """)
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(xml)
    services = runner.parse_nmap_xml(xml_path)
    assert services[0]["host"] == "192.168.1.1"


# ---------------------------------------------------------------------------
# api.create_services
# ---------------------------------------------------------------------------


def test_client_create_services():
    from vardrrunner.api import VardrMapClient

    client = VardrMapClient("http://api", "key")
    svcs = [{"host": "10.0.0.1", "port": 80, "protocol": "tcp"}]
    with patch.object(client, "post", return_value={"created": 1, "updated": 0}) as mock_post:
        result = client.create_services("prog-1", svcs)
    mock_post.assert_called_once_with("/engagements/prog-1/services", json={"services": svcs})
    assert result["created"] == 1


# ---------------------------------------------------------------------------
# jobs.run_jobs — nmap dispatch
# ---------------------------------------------------------------------------


def test_run_nmap_job_dispatches_and_uploads(tmp_path):
    xml_path = tmp_path / "nmap.xml"
    xml_path.write_text(_NMAP_XML)

    job = {
        "id": "job-nmap-1",
        "engagement_id": "prog-1",
        "tool_type": "nmap",
        "target_source": "scope",
        "config": {"top_ports": 100, "timing": 3},
    }

    client = MagicMock()
    client.pending_jobs.return_value = [job]
    client.scope.return_value = {"in": [{"value": "10.0.0.1"}], "out": []}
    client.create_services.return_value = {"created": 2, "updated": 0}

    with (
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("http://api", "key")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.runner.run_nmap", return_value=0),
        patch(
            "vardrrunner.commands.jobs.runner.parse_nmap_xml",
            return_value=[
                {
                    "host": "10.0.0.1",
                    "port": 80,
                    "protocol": "tcp",
                    "service_name": "http",
                    "product": "",
                    "version": "",
                    "state": "open",
                    "source": "nmap",
                }
            ],
        ),
    ):
        jobs_cmd.run_jobs(yes=True)

    client.claim_job.assert_called_once_with("job-nmap-1")
    client.create_services.assert_called_once()
    client.complete_job.assert_called_once_with("job-nmap-1", "done")


def test_run_nmap_job_no_open_ports_marks_done(tmp_path):
    """If parse_nmap_xml returns empty, job completes as done without calling create_services."""
    job = {
        "id": "job-nmap-2",
        "engagement_id": "prog-1",
        "tool_type": "nmap",
        "target_source": "scope",
        "config": {},
    }
    # Write a minimal xml file so the "file exists" check passes
    (tmp_path / "nmap.xml").write_text("<nmaprun/>")

    client = MagicMock()
    client.pending_jobs.return_value = [job]
    client.scope.return_value = {"in": [{"value": "10.0.0.1"}], "out": []}

    with (
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("http://api", "key")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.runner.run_nmap", return_value=0),
        patch("vardrrunner.commands.jobs.runner.parse_nmap_xml", return_value=[]),
    ):
        jobs_cmd.run_jobs(yes=True)

    client.create_services.assert_not_called()
    client.complete_job.assert_called_once_with("job-nmap-2", "done")


# ---------------------------------------------------------------------------
# runner.strip_url_to_host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "input_url,expected",
    [
        ("https://app.example.com/path", "app.example.com"),
        ("https://app.example.com", "app.example.com"),
        ("http://10.0.0.1:8080", "10.0.0.1"),
        ("http://10.0.0.1:8080/api/v1", "10.0.0.1"),
        ("app.example.com", "app.example.com"),
        ("10.0.0.1", "10.0.0.1"),
        ("sub.example.com/path", "sub.example.com"),
        ("https://EXAMPLE.COM/page", "example.com"),  # hostname lowercased
    ],
)
def test_strip_url_to_host(input_url, expected):
    assert runner.strip_url_to_host(input_url) == expected


def test_strip_url_to_host_empty():
    assert runner.strip_url_to_host("") == ""


def test_strip_url_to_host_whitespace():
    assert runner.strip_url_to_host("  https://app.example.com  ") == "app.example.com"


# ---------------------------------------------------------------------------
# jobs.run_jobs — nmap strips URLs before passing to run_nmap
# ---------------------------------------------------------------------------


def test_run_nmap_job_strips_url_targets(tmp_path):
    """Verify that URL targets (https://...) are normalized to hostnames before nmap."""
    (tmp_path / "nmap.xml").write_text(_NMAP_XML)
    job = {
        "id": "job-nmap-3",
        "engagement_id": "prog-1",
        "tool_type": "nmap",
        "target_source": "recon",
        "config": {"top_ports": 50, "timing": 2},
    }

    client = MagicMock()
    client.pending_jobs.return_value = [job]
    client.create_services.return_value = {"created": 2, "updated": 0}

    captured_targets = []

    def fake_run_nmap(targets, *a, **kw):
        captured_targets.extend(targets)
        return 0

    with (
        patch("vardrrunner.commands.jobs.config.require_auth", return_value=("http://api", "key")),
        patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch(
            "vardrrunner.handlers._resolve_targets",
            return_value=["https://app.example.com/path", "http://10.0.0.2:8080/api"],
        ),
        patch("vardrrunner.commands.jobs.runner.run_nmap", side_effect=fake_run_nmap),
        patch("vardrrunner.commands.jobs.runner.parse_nmap_xml", return_value=[]),
    ):
        jobs_cmd.run_jobs(yes=True)

    assert "app.example.com" in captured_targets
    assert "10.0.0.2" in captured_targets
    assert not any("https" in t for t in captured_targets)


# ---------------------------------------------------------------------------
# vardrrunner run nmap — manual command
# ---------------------------------------------------------------------------


def test_run_nmap_command_normalizes_and_uploads_services(tmp_path):
    from vardrrunner.commands import run as run_cmd

    # The command checks for nmap XML output after running; create it (run_nmap is mocked).
    (tmp_path / "nmap.xml").write_text("<nmaprun></nmaprun>")

    client = MagicMock()
    client.create_services.return_value = {"created": 2, "updated": 1}
    services = [{"host": "app.example.com", "port": 443, "protocol": "tcp"}]

    with (
        patch("vardrrunner.commands.run.config.require_auth", return_value=("https://api", "key")),
        patch("vardrrunner.commands.run.api.VardrMapClient", return_value=client),
        patch("vardrrunner.commands.run.runner.check_tool"),
        patch(
            "vardrrunner.commands.run._resolve_targets",
            return_value=["https://app.example.com/path"],
        ),
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.run.runner.run_nmap", return_value=0) as mock_nmap,
        patch("vardrrunner.commands.run.runner.parse_nmap_xml", return_value=services),
    ):
        run_cmd.run_nmap(engagement_id="prog-1", target="https://app.example.com/path", yes=True)

    # URL was normalized to bare host before nmap, and services uploaded.
    assert mock_nmap.call_args[0][0] == ["app.example.com"]
    client.create_services.assert_called_once_with("prog-1", services)
