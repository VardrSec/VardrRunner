"""Explicit managed HTTP bounds; no route activation or live credentials."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from vardrrunner.api import ManagedTransportError, VardrMapClient


@pytest.fixture
def wire():
    client = VardrMapClient("https://map.example.test", "vmap_synthetic")
    session, response = MagicMock(), MagicMock()
    session.headers, session.proxies = {}, {}
    response.status_code = 200
    response.headers = {"Content-Type": "application/json"}
    response.iter_content.return_value = [b'{"ok":true}']
    session.post.return_value.__enter__.return_value = response
    with patch("vardrrunner.api.requests.Session") as factory:
        factory.return_value.__enter__.return_value = session
        yield client, session, response, factory


def test_managed_request_is_separate_exact_and_never_retries_or_redirects(wire):
    client, session, _, _ = wire
    client.session.verify = "/synthetic/operator-ca.pem"
    client.session.proxies = {"https": "http://synthetic-proxy.test:8080"}
    client.session.cookies.set("must_not_copy", "synthetic")
    assert client.managed_post("/fixture/claim", {"n": 1}) == {"ok": True}
    session.post.assert_called_once_with(
        "https://map.example.test/fixture/claim",
        data=b'{"n":1}',
        timeout=(3.05, 3),
        stream=True,
        allow_redirects=False,
    )
    assert session.verify == client.session.verify
    assert session.proxies == client.session.proxies
    assert session.trust_env is client.session.trust_env
    assert session.headers["Authorization"] == "Bearer vmap_synthetic"
    assert session.headers["Accept-Encoding"] == "identity"
    session.cookies.update.assert_not_called()
    for call in session.mount.call_args_list:
        assert call.args[1].max_retries.total == 0
    prepared = requests.Request("POST", "https://map.example.test").prepare()
    assert session.auth(prepared) is prepared
    assert client.session.get_adapter(client.base).max_retries.total == 3


@pytest.mark.parametrize(
    "base",
    [
        "http://localhost",
        "https://user:secret@map.example.test",
        "https://map.example.test/api",
        "https://map.example.test?",
        "https://map.example.test#",
        "https://map.example.test:0",
    ],
)
def test_managed_origin_failure_precedes_transport(wire, base):
    client, _, _, factory = wire
    client.base = base
    with pytest.raises(ManagedTransportError, match="^managed request failed$"):
        client.managed_post("/fixture/claim", {})
    factory.assert_not_called()


@pytest.mark.parametrize(
    "path",
    [
        "https://other.test",
        "//other.test",
        "/x?token=secret",
        "/x/../y",
        "/x%2fy",
        "/x\\y",
        "/x#y",
        "",
        None,
    ],
)
def test_managed_path_failure_precedes_transport(wire, path):
    client, _, _, factory = wire
    with pytest.raises(ManagedTransportError):
        client.managed_post(path, {})
    factory.assert_not_called()


@pytest.mark.parametrize("verify", [False, 0, "", None])
def test_disabled_or_ambiguous_tls_never_sends(wire, verify):
    client, _, _, factory = wire
    client.session.verify = verify
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", {})
    factory.assert_not_called()


@pytest.mark.parametrize("timeout", [(True, 1), (0, 1), (1, float("inf")), (1, 11), [1, 1], (1,)])
def test_invalid_wait_bounds_never_send(wire, timeout):
    client, _, _, factory = wire
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", {}, timeout=timeout)
    factory.assert_not_called()


@pytest.mark.parametrize("payload", [[], {"x": float("inf")}, {"x": "a" * (1024 * 1024)}])
def test_invalid_or_oversized_request_never_sends(wire, payload):
    client, _, _, factory = wire
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", payload)
    factory.assert_not_called()


@pytest.mark.parametrize("status", [201, 204, 301, 302, 303, 307, 308, 401, 429, 500])
def test_noncontract_http_status_is_not_read_or_retried(wire, status):
    client, session, response, _ = wire
    response.status_code = status
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", {})
    response.iter_content.assert_not_called()
    assert session.post.call_count == 1


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "text/html"},
        {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        {"Content-Type": "application/json", "Content-Length": "262145"},
        {"Content-Type": "application/json", "Content-Length": "-1"},
        {"Content-Type": "application/json", "Content-Length": "2,2"},
    ],
)
def test_unbounded_or_encoded_response_rejected_before_read(wire, headers):
    client, _, response, _ = wire
    response.headers = headers
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", {})
    response.iter_content.assert_not_called()


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"\xff",
        b"{" * 33 + b'"x":0' + b"}" * 33,
    ],
)
def test_json_body_requires_strict_bounded_finite_object(wire, body):
    client, session, response, _ = wire
    response.iter_content.return_value = [body]
    with pytest.raises(ManagedTransportError) as error:
        client.managed_post("/fixture/claim", {})
    assert str(error.value) == "managed request failed"
    assert session.post.call_count == 1


def test_chunked_size_limit_closes_without_reading_further(wire):
    client, session, response, _ = wire
    seen = []

    def chunks(chunk_size):
        yield b"x" * 262144
        yield b"x"
        seen.append("read beyond bound")

    response.iter_content.side_effect = chunks
    with pytest.raises(ManagedTransportError):
        client.managed_post("/fixture/claim", {})
    assert not seen and session.post.call_count == 1
    session.post.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [requests.ReadTimeout("synthetic secret"), requests.ConnectionError("synthetic secret")],
)
def test_transport_errors_are_fixed_and_single_attempt(wire, error):
    client, session, _, _ = wire
    session.post.side_effect = error
    with pytest.raises(ManagedTransportError) as caught:
        client.managed_post("/fixture/claim", {})
    assert str(caught.value) == "managed request failed"
    assert caught.value.__suppress_context__
    assert session.post.call_count == 1
