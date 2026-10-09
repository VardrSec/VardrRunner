"""Every upload names the job that produced it, so VardrMap can record what each run observed.

VardrMap validates `job_id` against the engagement's own jobs, so the runner must send the id of
the job it is executing - and must keep sending nothing when there is no job (direct `run`
commands), so older backends and existing call sites behave exactly as before.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vardrrunner import api, handlers

JOB = "job-9"


def _api_client() -> api.VardrMapClient:
    return api.VardrMapClient("https://api.example.com", "vmap_key")


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.import_file.return_value = {"import_record": {"imported_count": 1}}
    client.create_services.return_value = {"created": 1, "updated": 0}
    return client


# ── api.py ───────────────────────────────────────────────────────────────────


def test_import_file_sends_job_id_only_when_given(tmp_path):
    out = tmp_path / "httpx.jsonl"
    out.write_text('{"url":"https://a.com"}\n')
    client = _api_client()
    with patch.object(client, "post", return_value={}) as post:
        client.import_file("eng", "httpx", str(out), job_id=JOB)
        client.import_file("eng", "httpx", str(out))
    with_job, without_job = post.call_args_list
    assert with_job.kwargs["data"] == {"tool_type": "httpx", "job_id": JOB}
    assert without_job.kwargs["data"] == {"tool_type": "httpx"}


def test_create_services_sends_job_id_only_when_given():
    client = _api_client()
    with patch.object(client, "post", return_value={}) as post:
        client.create_services("eng", [{"host": "h", "port": 80}], job_id=JOB)
        client.create_services("eng", [{"host": "h", "port": 80}])
    with_job, without_job = post.call_args_list
    assert with_job.kwargs["json"] == {"services": [{"host": "h", "port": 80}], "job_id": JOB}
    assert without_job.kwargs["json"] == {"services": [{"host": "h", "port": 80}]}


# ── handlers that import a file ──────────────────────────────────────────────

# handler, the tool_type the backend receives (subfinder and dnsx upload as httpx-format)
FILE_IMPORTERS = [
    (handlers.HttpxHandler, "httpx"),
    (handlers.NucleiHandler, "nuclei"),
    (handlers.SubfinderHandler, "httpx"),
    (handlers.DnsxHandler, "httpx"),
]


@pytest.mark.parametrize("handler_cls, backend_tool", FILE_IMPORTERS)
def test_file_imports_carry_the_job_id(handler_cls, backend_tool):
    client = _mock_client()
    handler_cls().upload(client, "eng", Path("out.jsonl"), job_id=JOB)
    client.import_file.assert_called_once_with("eng", backend_tool, "out.jsonl", job_id=JOB)


@pytest.mark.parametrize("handler_cls, backend_tool", FILE_IMPORTERS)
def test_file_imports_without_a_job_send_no_job_id(handler_cls, backend_tool):
    client = _mock_client()
    handler_cls().upload(client, "eng", Path("out.jsonl"))
    client.import_file.assert_called_once_with("eng", backend_tool, "out.jsonl")


# ── handlers that post services ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "handler_cls, parser",
    [
        (handlers.NmapHandler, "vardrrunner.runner.parse_nmap_xml"),
        (handlers.NaabuHandler, "vardrrunner.runner.parse_naabu_json"),
    ],
)
def test_service_posts_carry_the_job_id_when_there_is_one(handler_cls, parser):
    services = [{"host": "h", "port": 80, "protocol": "tcp"}]
    with_job, without_job = _mock_client(), _mock_client()
    with patch(parser, return_value=services):
        handler_cls().upload(with_job, "eng", Path("scan.out"), job_id=JOB)
        handler_cls().upload(without_job, "eng", Path("scan.out"))
    with_job.create_services.assert_called_once_with("eng", services, job_id=JOB)
    without_job.create_services.assert_called_once_with("eng", services)


# ── katana and gau, including the chunked path ───────────────────────────────


@pytest.mark.parametrize(
    "handler_cls, tool", [(handlers.KatanaHandler, "katana"), (handlers.GauHandler, "gau")]
)
def test_a_small_result_is_uploaded_with_the_job_id(tmp_path, handler_cls, tool):
    out = tmp_path / "result.jsonl"
    out.write_text(json.dumps({"url": "https://a.test/x"}) + "\n")
    client = _mock_client()
    handler_cls().upload(client, "eng", out, job_id=JOB)
    client.import_file.assert_called_once_with("eng", tool, str(out), job_id=JOB)


def test_every_chunk_of_a_large_result_carries_the_job_id(tmp_path):
    out = tmp_path / "gau_import.jsonl"
    out.write_text("".join(json.dumps({"url": f"https://a.test/{i}"}) + "\n" for i in range(30)))
    client = _mock_client()
    handlers._upload_jsonl_in_chunks(client, "eng", "gau", out, max_bytes=120, job_id=JOB)
    assert client.import_file.call_count > 1
    for call in client.import_file.call_args_list:
        assert call.kwargs == {"job_id": JOB}


def test_chunks_without_a_job_send_no_job_id(tmp_path):
    out = tmp_path / "gau_import.jsonl"
    out.write_text("".join(json.dumps({"url": f"https://a.test/{i}"}) + "\n" for i in range(30)))
    client = _mock_client()
    handlers._upload_jsonl_in_chunks(client, "eng", "gau", out, max_bytes=120)
    assert client.import_file.call_count > 1
    assert all(call.kwargs == {} for call in client.import_file.call_args_list)
