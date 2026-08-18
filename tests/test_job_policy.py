"""Job-lifecycle behaviour for backend policy responses.

Covers the defect this phase exists to fix: before v0.29.0 a stop-work refusal,
an expired key, a backend outage and a lost claim race all printed the same
line and left the job pending, so the daemon re-attempted a halted job every
polling cycle with no explanation.
"""

from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from vardrrunner import errors
from vardrrunner.commands import jobs as jobs_cmd

JOB = {
    "id": "job-1",
    "engagement_id": "eng-1",
    "tool_type": "httpx",
    "target_source": "scope",
    "config": {},
}


def _client(claim_result=None, claim_error=None):
    c = MagicMock()
    c.pending_jobs.return_value = [dict(JOB)]
    c.scope.return_value = {"in": [{"value": "app.example.com"}], "out": []}
    if claim_error is not None:
        c.claim_job.side_effect = claim_error
    else:
        c.claim_job.return_value = claim_result if claim_result is not None else {}
    return c


def _run(client, tmp_path, blocked=None):
    """Drive one batch with tools and target resolution stubbed out."""
    con = Console(record=True, width=200)
    with (
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.handlers.REGISTRY") as reg,
    ):
        handler = reg.get.return_value
        handler.tool = "httpx"
        handler.resolve_targets.return_value = ["https://app.example.com"]
        handler.execute.return_value = None  # no output → completes without upload
        jobs_cmd.execute_pending_jobs(client, con, yes=True, blocked_engagements=blocked)
    return con.export_text()


class TestStopWork:
    def test_halts_and_is_not_reported_as_a_claim_failure(self, tmp_path):
        client = _client(claim_error=errors.StopWorkError("halted", reason="stop_work_active"))
        out = _run(client, tmp_path)
        assert "STOP-WORK" in out
        assert "Could not claim job" not in out

    def test_job_is_not_marked_failed(self, tmp_path):
        """The job is blocked, not broken — marking it failed would misreport it."""
        client = _client(claim_error=errors.StopWorkError("halted"))
        _run(client, tmp_path)
        client.complete_job.assert_not_called()

    def test_no_tool_runs(self, tmp_path):
        client = _client(claim_error=errors.StopWorkError("halted"))
        con = Console(record=True, width=200)
        with (
            patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
            patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
            patch("vardrrunner.commands.jobs.handlers.REGISTRY") as reg,
        ):
            handler = reg.get.return_value
            handler.tool = "httpx"
            handler.resolve_targets.return_value = ["https://a.com"]
            jobs_cmd.execute_pending_jobs(client, con, yes=True)
            handler.execute.assert_not_called()

    def test_emits_a_blocked_event(self, tmp_path):
        client = _client(claim_error=errors.StopWorkError("halted"))
        _run(client, tmp_path)
        kinds = [c.args[1] for c in client.post_event.call_args_list]
        assert "blocked" in kinds

    def test_engagement_is_suppressed_for_subsequent_polls(self, tmp_path):
        """The daemon's memory: a halted engagement must not be re-claimed every
        poll_interval seconds forever."""
        blocked: set[str] = set()
        client = _client(claim_error=errors.StopWorkError("halted"))
        _run(client, tmp_path, blocked=blocked)
        assert blocked == {"eng-1"}

        client.claim_job.reset_mock()
        out = _run(client, tmp_path, blocked=blocked)
        client.claim_job.assert_not_called()
        assert "stop-work still engaged" in out


class TestClaimRace:
    def test_is_non_fatal_and_does_not_mark_the_job_failed(self, tmp_path):
        client = _client(claim_error=errors.ClaimRace("another runner won"))
        _run(client, tmp_path)
        client.complete_job.assert_not_called()

    def test_does_not_suppress_the_engagement(self, tmp_path):
        """A race is normal contention, not a halt — the next poll should retry."""
        blocked: set[str] = set()
        client = _client(claim_error=errors.ClaimRace("raced"))
        _run(client, tmp_path, blocked=blocked)
        assert blocked == set()


class TestOtherClaimFailures:
    @pytest.mark.parametrize(
        "exc,label",
        [
            (errors.AuthError("bad key"), "auth"),
            (errors.BackendUnavailable("503"), "backend_unavailable"),
            (errors.RateLimited("slow down"), "rate_limited"),
        ],
    )
    def test_reported_with_their_category(self, exc, label, tmp_path):
        client = _client(claim_error=exc)
        out = _run(client, tmp_path)
        assert label in out
        client.complete_job.assert_not_called()

    def test_unclassified_error_keeps_the_worker_alive(self, tmp_path):
        """Daemon boundary: one unknown failure must not end the batch."""
        client = _client(claim_error=RuntimeError("something odd"))
        out = _run(client, tmp_path)
        assert "unknown" in out
        client.complete_job.assert_not_called()


class TestAdvisoryWarnings:
    def test_warnings_are_shown_before_execution(self, tmp_path):
        client = _client(
            claim_result={
                "warnings": [{"reason": "target_out_of_scope", "message": "a.com not in scope"}]
            }
        )
        out = _run(client, tmp_path)
        assert "Target is not in the recorded scope" in out

    def test_warnings_do_not_block_execution(self, tmp_path):
        """Advisory means advisory — the job still runs (ADR 0001 amendment)."""
        client = _client(claim_result={"warnings": [{"reason": "target_out_of_scope"}]})
        con = Console(record=True, width=200)
        with (
            patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
            patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
            patch("vardrrunner.commands.jobs.handlers.REGISTRY") as reg,
        ):
            handler = reg.get.return_value
            handler.tool = "httpx"
            handler.resolve_targets.return_value = ["https://a.com"]
            handler.execute.return_value = None
            jobs_cmd.execute_pending_jobs(client, con, yes=True)
            handler.execute.assert_called_once()

    def test_warnings_are_emitted_as_a_job_event(self, tmp_path):
        client = _client(claim_result={"warnings": [{"reason": "outside_testing_window"}]})
        _run(client, tmp_path)
        kinds = [c.args[1] for c in client.post_event.call_args_list]
        assert "policy_warning" in kinds

    def test_no_warnings_means_no_noise(self, tmp_path):
        client = _client(claim_result={"warnings": []})
        _run(client, tmp_path)
        kinds = [c.args[1] for c in client.post_event.call_args_list]
        assert "policy_warning" not in kinds

    def test_malformed_warning_payload_does_not_break_the_job(self, tmp_path):
        client = _client(claim_result={"warnings": "not-a-list"})
        out = _run(client, tmp_path)
        assert "Could not claim job" not in out
