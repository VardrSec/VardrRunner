"""Tests for the VardrMap API client: auth/User-Agent headers and retry config.

These are pure construction/configuration tests — no network. They lock in the
resilience contract: idempotent methods retry on transient failures with backoff,
while POST/PATCH never auto-retry (so a dropped response can't double-act).
"""

from unittest.mock import patch

import pytest
from urllib3.util.retry import Retry

from vardrrunner import __version__
from vardrrunner.api import _RETRY_STATUSES, VardrMapClient


def _client(**kwargs) -> VardrMapClient:
    return VardrMapClient("https://api.example.com/", "vmap_testkey", **kwargs)


def test_base_url_trailing_slash_stripped():
    assert _client().base == "https://api.example.com"


def test_url_join_handles_leading_slash_either_way():
    c = _client()
    assert c._url("/me") == "https://api.example.com/me"
    assert c._url("engagements") == "https://api.example.com/engagements"


def test_authorization_header_set():
    assert _client().session.headers["Authorization"] == "Bearer vmap_testkey"


def test_user_agent_reports_runner_version():
    ua = _client().session.headers["User-Agent"]
    assert ua.startswith(f"vardrrunner/{__version__}")


def test_retry_adapter_mounted_for_http_and_https():
    c = _client()
    for scheme in ("https://x", "http://x"):
        adapter = c.session.get_adapter(scheme)
        assert isinstance(adapter.max_retries, Retry)


def test_retry_configuration_defaults():
    retry = _client().session.get_adapter("https://x").max_retries
    assert retry.total == 3
    assert retry.backoff_factor == 0.5
    assert tuple(retry.status_forcelist) == _RETRY_STATUSES
    assert retry.raise_on_status is False


def test_idempotent_methods_retry_but_post_and_patch_do_not():
    retry = _client().session.get_adapter("https://x").max_retries
    allowed = retry.allowed_methods
    assert "GET" in allowed
    assert "POST" not in allowed
    assert "PATCH" not in allowed


def test_retries_and_backoff_are_configurable():
    retry = _client(retries=5, backoff_factor=1.0).session.get_adapter("https://x").max_retries
    assert retry.total == 5
    assert retry.backoff_factor == 1.0


# ---------------------------------------------------------------------------
# recon() pagination
# ---------------------------------------------------------------------------


def test_recon_single_page_when_results_fit():
    """If the first page is smaller than the requested limit, stop after one request."""
    c = _client()
    page = [{"url": "https://a.com"}, {"url": "https://b.com"}]
    with patch.object(c, "get", return_value={"recon": page}) as mock_get:
        result = c.recon("p1", limit=100)
    assert result == page
    assert mock_get.call_count == 1


def test_recon_paginates_until_exhausted():
    """Multiple pages are requested when the first page is full (== page_size)."""
    page_size = VardrMapClient.RECON_PAGE_SIZE
    page1 = [{"url": f"https://{i}.com"} for i in range(page_size)]
    page2 = [{"url": "https://extra.com"}]

    c = _client()
    call_count = 0

    def fake_get(path, params=None):
        nonlocal call_count
        call_count += 1
        return {"recon": page1 if call_count == 1 else page2}

    with patch.object(c, "get", side_effect=fake_get):
        result = c.recon("p1", limit=page_size + 10)

    assert len(result) == page_size + 1
    assert call_count == 2


def test_recon_respects_caller_limit():
    """The caller's limit caps how many items we collect even when pages are full."""
    c = _client()
    # Each call returns 3 items; caller wants 5 → collect first 5 only.
    calls = [0]

    def fake_get(path, params=None):
        calls[0] += 1
        fetch = (params or {}).get("limit", 3)
        return {"recon": [{"url": f"https://{calls[0]}-{i}.com"} for i in range(fetch)]}

    with patch.object(c, "get", side_effect=fake_get):
        result = c.recon("p1", limit=5)

    assert len(result) == 5


def test_recon_page_size_constant():
    assert VardrMapClient.RECON_PAGE_SIZE == 500


# ---------------------------------------------------------------------------
# HTTP methods (get / post / patch) and high-level wrappers
# ---------------------------------------------------------------------------


def _mock_response(json_data, status=200, raise_error=None):
    from unittest.mock import MagicMock

    r = MagicMock()
    r.json.return_value = json_data
    if raise_error:
        r.raise_for_status.side_effect = raise_error
    else:
        r.raise_for_status.return_value = None
    return r


def test_get_returns_json():
    c = _client()
    with patch.object(c.session, "get", return_value=_mock_response({"ok": True})):
        assert c.get("/test") == {"ok": True}


def test_get_raises_on_http_error():
    import requests

    c = _client()
    with patch.object(
        c.session, "get", return_value=_mock_response({}, raise_error=requests.HTTPError("404"))
    ):
        with pytest.raises(requests.HTTPError):
            c.get("/bad")


def test_post_returns_json():
    c = _client()
    with patch.object(c.session, "post", return_value=_mock_response({"created": True})):
        assert c.post("/test", json={"x": 1}) == {"created": True}


def test_post_with_files_passes_them():
    c = _client()
    with patch.object(c.session, "post", return_value=_mock_response({})) as mock_post:
        c.post("/upload", files={"file": b"data"}, data={"tool_type": "httpx"})
    _, kwargs = mock_post.call_args
    assert kwargs["files"] == {"file": b"data"}
    assert kwargs["data"] == {"tool_type": "httpx"}


def test_patch_returns_json():
    c = _client()
    with patch.object(c.session, "patch", return_value=_mock_response({"status": "done"})):
        assert c.patch("/jobs/j1", json={"status": "done"}) == {"status": "done"}


def test_whoami():
    c = _client()
    with patch.object(c, "get", return_value={"username": "jorge"}):
        assert c.whoami() == {"username": "jorge"}


def test_programs_returns_list():
    c = _client()
    with patch.object(c, "get", return_value={"engagements": [{"id": "p1"}]}):
        assert c.engagements() == [{"id": "p1"}]


def test_programs_missing_key_returns_empty():
    c = _client()
    with patch.object(c, "get", return_value={}):
        assert c.engagements() == []


def test_program():
    c = _client()
    with patch.object(c, "get", return_value={"id": "p1"}):
        assert c.engagement("p1") == {"id": "p1"}


def test_scope():
    c = _client()
    scope_data = {"in": [{"value": "*.example.com"}], "out": []}
    with patch.object(c, "get", return_value={"scope": scope_data}):
        assert c.scope("p1") == scope_data


def test_scope_missing_returns_defaults():
    c = _client()
    with patch.object(c, "get", return_value={}):
        assert c.scope("p1") == {"in": [], "out": []}


def test_pending_jobs():
    c = _client()
    with patch.object(c, "get", return_value={"jobs": [{"id": "j1"}]}):
        assert c.pending_jobs() == [{"id": "j1"}]


def test_pending_jobs_missing_key():
    c = _client()
    with patch.object(c, "get", return_value={}):
        assert c.pending_jobs() == []


def test_claim_job():
    c = _client()
    with patch.object(c, "post", return_value={"status": "claimed"}):
        assert c.claim_job("j1") == {"status": "claimed"}


def test_complete_job_done():
    c = _client()
    with patch.object(
        c.session, "patch", return_value=_mock_response({"status": "done"})
    ) as mock_patch:
        c.complete_job("j1", "done")
    _, kwargs = mock_patch.call_args
    assert kwargs["json"] == {"status": "done"}


def test_complete_job_with_error_message():
    c = _client()
    with patch.object(c.session, "patch", return_value=_mock_response({})) as mock_patch:
        c.complete_job("j1", "failed", error="boom")
    _, kwargs = mock_patch.call_args
    assert kwargs["json"]["error_message"] == "boom"


def test_send_heartbeat():
    c = _client()
    with patch.object(c, "post", return_value={"ok": True}):
        assert c.send_heartbeat({"hostname": "box"}) == {"ok": True}


def test_post_event():
    c = _client()
    with patch.object(c, "post", return_value={"id": "e1"}):
        assert c.post_event("j1", "started", "running") == {"id": "e1"}


def test_create_services():
    c = _client()
    with patch.object(c, "post", return_value={"created": 2}):
        assert c.create_services("p1", []) == {"created": 2}


def test_import_file(tmp_path):
    out = tmp_path / "httpx.jsonl"
    out.write_text('{"url":"https://a.com"}\n')
    c = _client()
    with patch.object(c, "post", return_value={"import_record": {"imported_count": 1}}):
        result = c.import_file("p1", "httpx", str(out))
    assert result["import_record"]["imported_count"] == 1
