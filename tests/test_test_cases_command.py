"""`test-cases draft` / `save`: a review artifact that is never overwritten, never carries a literal
credential, and is only sent to VardrMap once the operator confirms it was reviewed."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests
import typer

from vardrrunner.commands import test_cases as cmd

DRAFTS = [
    {
        "name": "GET /users/{id}",
        "description": "Draft from observed API operation",
        "spec": {
            "id": "case-1",
            "request": {"method": "GET", "url": "https://api.example.test/users/1"},
            "identities": [
                {
                    "id": "anonymous",
                    "credential": {"type": "static_header", "header": "", "value": ""},
                },
                {
                    "id": "member",
                    "credential": {"type": "bearer", "value_env": "VARDRGATE_MEMBER_TOKEN"},
                },
            ],
            "expected_access": [
                {"identity_id": "anonymous", "decision": "skip"},
                {"identity_id": "member", "decision": "skip"},
            ],
        },
    }
]
PREVIEW = {"drafts": DRAFTS, "total": 1, "offset": 0, "limit": 50, "next_offset": None}


@pytest.fixture
def server():
    """A fake VardrMap: authenticated, and recording what the command posts."""
    client = MagicMock()
    client.post.return_value = PREVIEW
    with (
        patch.object(
            cmd.config, "require_auth", return_value=("https://api.example.com", "vmap_k")
        ),
        patch.object(cmd.api, "VardrMapClient", return_value=client),
    ):
        yield client


def _text(capsys) -> str:
    return " ".join(capsys.readouterr().out.split())


def _exit_code(call, *args, **kwargs) -> int:
    with pytest.raises(typer.Exit) as exc:
        call(*args, **kwargs)
    return exc.value.exit_code


# ── draft ────────────────────────────────────────────────────────────────────


def test_draft_from_endpoints_writes_a_review_file_and_stores_nothing(tmp_path, server, capsys):
    out = tmp_path / "review.json"
    cmd.draft_cases("eng", None, ["ep1", "ep2"], out, "https://api.example.test", 0, 50)
    path = server.post.call_args.args[0]
    body = server.post.call_args.kwargs["json"]
    assert path == "/engagements/eng/test-cases/preview"
    assert body == {
        "base_url": "https://api.example.test",
        "offset": 0,
        "limit": 50,
        "endpoint_ids": ["ep1", "ep2"],
    }
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact == {"cases": DRAFTS, "total": 1, "offset": 0, "next_offset": None}
    assert "No cases stored or queued" in _text(capsys)


def test_draft_from_an_openapi_file_sends_the_parsed_document(tmp_path, server):
    spec = tmp_path / "api.json"
    spec.write_text(json.dumps({"openapi": "3.1.0", "paths": {}}), encoding="utf-8")
    cmd.draft_cases("eng", spec, [], tmp_path / "review.json")
    body = server.post.call_args.kwargs["json"]
    assert body["openapi"] == {"openapi": "3.1.0", "paths": {}}
    assert "endpoint_ids" not in body


def test_draft_reads_a_file_written_with_a_byte_order_mark(tmp_path, server):
    """PowerShell's `>` redirect writes a BOM; the document must still parse."""
    spec = tmp_path / "api.json"
    spec.write_bytes(b"\xef\xbb\xbf" + json.dumps({"openapi": "3.0.0", "paths": {}}).encode())
    cmd.draft_cases("eng", spec, [], tmp_path / "review.json")
    assert server.post.call_args.kwargs["json"]["openapi"]["openapi"] == "3.0.0"


@pytest.mark.parametrize("openapi, endpoints", [(False, []), (True, ["ep1"])])
def test_draft_needs_exactly_one_source(tmp_path, server, capsys, openapi, endpoints):
    spec = None
    if openapi:
        spec = tmp_path / "api.json"
        spec.write_text("{}", encoding="utf-8")
    assert _exit_code(cmd.draft_cases, "eng", spec, endpoints, tmp_path / "review.json") == 1
    assert "Choose --openapi or one or more --endpoint" in _text(capsys)
    server.post.assert_not_called()


def test_draft_never_overwrites_an_existing_review_file(tmp_path, server, capsys):
    out = tmp_path / "review.json"
    out.write_text("my careful edits", encoding="utf-8")
    assert _exit_code(cmd.draft_cases, "eng", None, ["ep1"], out) == 1
    assert out.read_text(encoding="utf-8") == "my careful edits"
    assert "choose a new path" in _text(capsys)
    server.post.assert_not_called()


def test_draft_refuses_a_literal_credential_and_writes_no_file(tmp_path, server, capsys):
    leaky = json.loads(json.dumps(PREVIEW))
    leaky["drafts"][0]["spec"]["identities"][1]["credential"] = {
        "type": "bearer",
        "value": "s3cr3t-token",
    }
    server.post.return_value = leaky
    out = tmp_path / "review.json"
    assert _exit_code(cmd.draft_cases, "eng", None, ["ep1"], out) == 1
    assert not out.exists()
    printed = _text(capsys)
    assert "literal credential" in printed and "s3cr3t-token" not in printed


def test_draft_keeps_credential_references_intact(tmp_path, server):
    """The generic log redactor would mask a whole credential object; drafts are editable specs."""
    out = tmp_path / "review.json"
    cmd.draft_cases("eng", None, ["ep1"], out)
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["cases"][0]["spec"]["identities"][1]["credential"] == {
        "type": "bearer",
        "value_env": "VARDRGATE_MEMBER_TOKEN",
    }


def test_draft_rejects_an_oversized_openapi_file(tmp_path, server, capsys):
    spec = tmp_path / "huge.json"
    spec.write_bytes(b" " * (cmd.MAX_DOCUMENT_BYTES + 1))
    assert _exit_code(cmd.draft_cases, "eng", spec, [], tmp_path / "review.json") == 1
    assert "exceeds 2 MiB" in _text(capsys)
    server.post.assert_not_called()


def test_draft_reports_invalid_json(tmp_path, server, capsys):
    spec = tmp_path / "bad.json"
    spec.write_text("{not json", encoding="utf-8")
    assert _exit_code(cmd.draft_cases, "eng", spec, [], tmp_path / "review.json") == 1
    assert "Case authoring failed" in _text(capsys)


def test_draft_forwards_the_servers_reason(tmp_path, server, capsys):
    response = MagicMock()
    response.json.return_value = {"detail": "Provide an absolute HTTP(S) base_url"}
    server.post.side_effect = requests.HTTPError(response=response)
    assert _exit_code(cmd.draft_cases, "eng", None, ["ep1"], tmp_path / "review.json") == 1
    assert "absolute HTTP(S) base_url" in _text(capsys)


def test_draft_survives_an_unreadable_error_body(tmp_path, server, capsys):
    response = MagicMock()
    response.json.side_effect = ValueError("not json")
    server.post.side_effect = requests.HTTPError(response=response)
    assert _exit_code(cmd.draft_cases, "eng", None, ["ep1"], tmp_path / "review.json") == 1
    assert "Request failed" in _text(capsys)


def test_draft_reports_a_network_failure(tmp_path, server, capsys):
    server.post.side_effect = requests.ConnectionError("connection refused")
    assert _exit_code(cmd.draft_cases, "eng", None, ["ep1"], tmp_path / "review.json") == 1
    assert "Case authoring failed" in _text(capsys)


# ── save ─────────────────────────────────────────────────────────────────────


def _reviewed_file(tmp_path, payload=None):
    path = tmp_path / "reviewed.json"
    path.write_text(
        json.dumps(payload if payload is not None else {"cases": DRAFTS}), encoding="utf-8"
    )
    return path


def test_save_refuses_without_the_review_flag(tmp_path, server, capsys):
    assert _exit_code(cmd.save_cases, "eng", _reviewed_file(tmp_path), False) == 1
    assert "pass --reviewed" in _text(capsys)
    server.post.assert_not_called()


def test_save_posts_the_reviewed_cases_and_queues_nothing(tmp_path, server, capsys):
    server.post.return_value = {"test_cases": [{"id": "tc-1"}, {"id": "tc-2"}]}
    cmd.save_cases("eng", _reviewed_file(tmp_path), True)
    assert server.post.call_args.args[0] == "/engagements/eng/test-cases/reviewed"
    assert server.post.call_args.kwargs["json"] == {"reviewed": True, "cases": DRAFTS}
    printed = _text(capsys)
    assert "Saved case tc-1" in printed and "Saved case tc-2" in printed
    assert "No jobs queued" in printed


def test_save_accepts_a_bare_list_of_cases(tmp_path, server):
    server.post.return_value = {"test_cases": []}
    cmd.save_cases("eng", _reviewed_file(tmp_path, DRAFTS), True)
    assert server.post.call_args.kwargs["json"]["cases"] == DRAFTS


@pytest.mark.parametrize("payload", [{"cases": []}, {"cases": "nope"}, {"other": 1}, []])
def test_save_requires_a_non_empty_cases_array(tmp_path, server, capsys, payload):
    assert _exit_code(cmd.save_cases, "eng", _reviewed_file(tmp_path, payload), True) == 1
    assert "non-empty cases array" in _text(capsys)
    server.post.assert_not_called()


def test_save_forwards_a_server_refusal(tmp_path, server, capsys):
    response = MagicMock()
    response.json.return_value = {"detail": "Review exactly one access decision per identity"}
    server.post.side_effect = requests.HTTPError(response=response)
    assert _exit_code(cmd.save_cases, "eng", _reviewed_file(tmp_path), True) == 1
    assert "exactly one access decision per identity" in _text(capsys)


def test_save_reports_a_missing_file(tmp_path, server, capsys):
    assert _exit_code(cmd.save_cases, "eng", tmp_path / "missing.json", True) == 1
    assert "Case authoring failed" in _text(capsys)
    server.post.assert_not_called()
