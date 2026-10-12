from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from rich.console import Console

from tests.test_mcp_server import _call, _expand, _server
from vardrrunner.commands import jobs


def test_playbook_reads_use_backend_catalog_without_writes():
    fake = MagicMock()
    fake.get.return_value = {"playbooks": [{"id": "API-01", "version": "1.0"}], "total": 1}
    assert _call(_server(fake), "list_api_playbooks", engagement_id="eng")["total"] == 1
    fake.get.assert_called_once_with("/engagements/eng/playbooks")
    fake.get.reset_mock()
    fake.get.return_value = {"id": "API-01", "version": "1.0", "steps": ["Review"]}
    assert (
        _call(_server(fake), "get_api_playbook", engagement_id="eng", playbook_id="API-01")[
            "version"
        ]
        == "1.0"
    )
    fake.get.assert_called_once_with("/engagements/eng/playbooks/API-01")
    fake.post.assert_not_called()


@pytest.mark.parametrize("value", ["API-99", "../settings", "API-01/../../settings"])
def test_unrecognized_playbook_cannot_become_a_path(value):
    fake = MagicMock()
    with pytest.raises(ToolError, match="Choose API"):
        _call(_server(fake), "get_api_playbook", engagement_id="eng", playbook_id=value)
    fake.get.assert_not_called()


@pytest.mark.parametrize(
    "name,args,data",
    [
        ("list_api_playbooks", {}, []),
        ("list_api_playbooks", {}, {"playbooks": None}),
        ("get_api_playbook", {"playbook_id": "API-01"}, {"id": "API-02", "steps": []}),
    ],
)
def test_malformed_backend_guidance_is_unknown_not_empty(name, args, data):
    fake = MagicMock()
    fake.get.return_value = data
    with pytest.raises(ToolError):
        _call(_server(fake), name, engagement_id="eng", **args)


def test_evidence_pagination_retains_identity_case_and_caps_page():
    fake = MagicMock()
    fake.get.return_value = {"evidence": [{"id": "e1", "job_id": "job"}], "total": 501}
    result = _call(
        _server(fake),
        "list_evidence",
        engagement_id="eng",
        job_id="job",
        identity_id="OwnerA",
        limit=500,
        offset=200,
    )
    fake.get.assert_called_once_with(
        "/engagements/eng/evidence",
        params={"job_id": "job", "identity_id": "OwnerA", "limit": 200, "offset": 200},
    )
    assert result["next_offset"] == 201 and result["count"] == 501


def test_malformed_evidence_is_not_reported_as_no_evidence():
    fake = MagicMock()
    fake.get.return_value = {"total": 0}
    with pytest.raises(ToolError, match="requested records"):
        _call(_server(fake), "list_evidence", engagement_id="eng")


def test_selected_playbook_prompt_expands_without_fetch_and_explains_unknowns():
    fake = MagicMock()
    text = _expand(_server(fake), "api_playbook", engagement_id="eng", playbook_id="API-01")
    assert "API-01" in text and "get_api_playbook" in text
    assert "assessment.status" in text and "legitimate baseline" in text
    assert "major" in text and "not independent verification" in text
    assert fake.mock_calls == []


@pytest.mark.parametrize("changed", [True, False])
def test_case_changed_at_claim_never_runs_previously_resolved_targets(tmp_path, changed):
    spec = {"id": "original"}
    handler = MagicMock(tool="vardrgate")
    handler.resolve_targets.return_value = ["https://api.example.test/object"]
    handler.execute.return_value = None
    client = MagicMock()
    client.claim_job.return_value = {
        "config": {"test_case": {"id": "changed"} if changed else spec}
    }
    job = {
        "id": "job",
        "engagement_id": "eng",
        "tool_type": "vardrgate_api_test",
        "target_source": "scope",
        "config": {"test_case": spec},
    }
    with (
        patch.dict("vardrrunner.commands.jobs.handlers.REGISTRY", {"vardrgate_api_test": handler}),
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs.config.runs_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.resources.ensure_free_space"),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.target_safety.load_deny_rules", return_value=()),
    ):
        jobs._execute_one(client, Console(file=StringIO()), job, yes=True)
    if changed:
        handler.execute.assert_not_called()
        assert client.complete_job.call_args.args[1] == "failed"
        assert "changed between polling and claim" in client.complete_job.call_args.kwargs["error"]
    else:
        handler.execute.assert_called_once()
        client.complete_job.assert_called_once_with("job", "done")
