"""Redaction: the single sanitization layer in front of every trust boundary.

These tests are adversarial on purpose. A redactor is only worth having if it
holds against the shapes a secret actually arrives in — nested payloads,
unexpected keys, exception messages, URLs with userinfo — so most of this file
is "does the secret survive this shape", not "does the happy path work".
"""

import logging
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from vardrrunner import redaction
from vardrrunner.commands import jobs as jobs_cmd

KEY = "vmap_AbCd1234EFgh5678"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"


class TestFreeText:
    @pytest.mark.parametrize(
        "text",
        [
            f"using key {KEY}",
            f"Authorization: Bearer {JWT}",
            f"authorization={JWT}",
            f"Bearer {JWT}",
            f"Cookie: session={JWT}",
            "GET /x?api_key=sekret123&page=2",
            "GET /x?token=sekret123",
            "api_key=sekret123",
            "password: hunter2horse",
            'secret="topsecretvalue"',
            "access_token: abc123def456",
        ],
    )
    def test_secret_shapes_are_masked(self, text):
        out = redaction.redact_text(text)
        for leak in (KEY, JWT, "sekret123", "hunter2horse", "topsecretvalue", "abc123def456"):
            assert leak not in out, f"leaked from: {text!r}"
        assert redaction.MASK in out

    def test_ordinary_text_is_untouched(self):
        msg = "resolved 42 targets from scope for engagement eng-1"
        assert redaction.redact_text(msg) == msg

    def test_is_deterministic(self):
        t = f"key {KEY}"
        assert redaction.redact_text(t) == redaction.redact_text(t)

    def test_idempotent(self):
        once = redaction.redact_text(f"key {KEY}")
        assert redaction.redact_text(once) == once

    @pytest.mark.parametrize("value", ["", None, 42, [], {}])
    def test_non_string_input_is_returned_unchanged(self, value):
        assert redaction.redact_text(value) == value


class TestStructures:
    def test_masks_by_key_name_regardless_of_value(self):
        out = redaction.redact({"api_key": "anything-at-all"})
        assert out["api_key"] == redaction.MASK

    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "apiKey",
            "X-API-KEY",
            "authorization",
            "Cookie",
            "token",
            "auth_token",
            "access_token",
            "refresh_token",
            "password",
            "secret",
            "private_key",
            "value_env",
            "value_keychain",
            "session",
        ],
    )
    def test_every_sensitive_key_form(self, key):
        assert redaction.redact({key: "leak-me"})[key] == redaction.MASK

    def test_nested_dicts_and_lists(self):
        payload = {
            "ok": "visible",
            "nested": {"Authorization": f"Bearer {JWT}", "deeper": [{"token": KEY}]},
            "items": [f"raw {KEY}", "clean"],
        }
        out = redaction.redact(payload)
        flat = repr(out)
        assert KEY not in flat and JWT not in flat
        assert out["ok"] == "visible"
        assert "clean" in flat

    def test_non_secret_values_survive(self):
        out = redaction.redact({"count": 5, "ok": True, "none": None, "name": "httpx"})
        assert out == {"count": 5, "ok": True, "none": None, "name": "httpx"}

    def test_tuple_type_is_preserved(self):
        assert isinstance(redaction.redact(("a", "b")), tuple)

    def test_deep_nesting_is_bounded_not_crashed(self):
        """Backend payloads are untrusted; a hostile nest must not exhaust the
        stack or become a DoS on the runner."""
        node: dict = {"end": KEY}
        for _ in range(60):
            node = {"n": node}
        out = repr(redaction.redact(node))
        assert KEY not in out
        assert "TRUNCATED" in out

    def test_original_is_not_mutated(self):
        original = {"api_key": KEY}
        redaction.redact(original)
        assert original["api_key"] == KEY


class TestExceptionsAndUrls:
    def test_exception_message_is_sanitized_and_typed(self):
        out = redaction.redact_exception(ValueError(f"failed for {KEY}"))
        assert KEY not in out and "ValueError" in out

    def test_url_userinfo_is_stripped(self):
        out = redaction.redact_url("https://user:hunter2horse@api.example.com/x")
        assert "hunter2horse" not in out and "api.example.com" in out

    def test_url_query_secret_is_stripped(self):
        assert "abc123def" not in redaction.redact_url("https://h/x?token=abc123def")

    def test_plain_url_survives_readable(self):
        url = "https://vardrmap-production.up.railway.app/jobs/pending"
        assert redaction.redact_url(url) == url

    def test_rich_text_masks_secrets_and_escapes_markup(self):
        out = redaction.redact_rich_text(f"[link=https://evil]click[/link] {KEY}")
        assert KEY not in out
        assert r"\[link=" in out and r"\[/link]" in out

    def test_rich_exception_masks_and_escapes(self):
        out = redaction.redact_rich_exception(ValueError(f"[bold]{KEY}[/bold]"))
        assert KEY not in out and r"\[bold]" in out


class TestBoundaryApplication:
    """The layer is only worth anything if it is actually wired in."""

    def test_job_events_are_sanitized_before_upload(self):
        client = MagicMock()
        jobs_cmd._emit(client, "job-1", "running", f"executing with {KEY}")
        sent = client.post_event.call_args.args[2]
        assert KEY not in sent and redaction.MASK in sent

    def test_failure_reasons_are_sanitized_to_terminal_and_backend(self):
        client = MagicMock()
        con = Console(record=True, width=200)
        jobs_cmd._fail_job(client, con, "job-1", f"tool died calling ?api_key={KEY}")
        assert KEY not in con.export_text()
        assert KEY not in client.complete_job.call_args.kwargs["error"]

    def test_failed_event_post_failure_is_logged_sanitized(self, caplog):
        client = MagicMock()
        client.post_event.side_effect = RuntimeError(f"boom {KEY}")
        with caplog.at_level(logging.WARNING):
            jobs_cmd._emit(client, "job-1", "running", "text")
        assert KEY not in caplog.text

    def test_unclassified_claim_failure_is_sanitized(self, tmp_path):
        job = {
            "id": "job-1",
            "engagement_id": "eng-1",
            "tool_type": "httpx",
            "target_source": "scope",
            "config": {},
        }
        client = MagicMock()
        client.pending_jobs.return_value = [job]
        client.claim_job.side_effect = RuntimeError(f"odd failure {KEY}")
        con = Console(record=True, width=200)
        with (
            patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
            patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
            patch("vardrrunner.commands.jobs.handlers.REGISTRY") as reg,
        ):
            reg.get.return_value.tool = "httpx"
            reg.get.return_value.resolve_targets.return_value = ["https://a.com"]
            jobs_cmd.execute_pending_jobs(client, con, yes=True)
        assert KEY not in con.export_text()

    def test_job_list_redacts_literal_credentials(self, capsys):
        client = MagicMock()
        client.pending_jobs.return_value = [
            {
                "id": "job-1",
                "tool_type": "vardrgate_api_test",
                "target_source": "inline",
                "created_at": "2026-08-18T00:00:00Z",
                "config": {"identity": {"credential": {"value": KEY}}},
            }
        ]
        with (
            patch("vardrrunner.commands.jobs.config.require_auth", return_value=("https://a", KEY)),
            patch("vardrrunner.commands.jobs.api.VardrMapClient", return_value=client),
        ):
            jobs_cmd.list_jobs()
        output = capsys.readouterr().out
        assert KEY not in output
        assert redaction.MASK in output
