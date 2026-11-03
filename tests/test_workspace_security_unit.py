"""Exercise ASGI resource and exception boundaries without a database or socket."""

from __future__ import annotations

import asyncio

import pytest

from cloudsecops_live.workspace_web import SecurityBoundary

ORIGIN = "https://127.0.0.1:8443"
HOST = (b"host", b"127.0.0.1:8443")


def exchange(*, change=None, messages=None, fail=False, timeout=False):
    scope = {
        "type": "http",
        "scheme": "https",
        "method": "GET",
        "path": "/cases",
        "query_string": b"",
        "headers": [HOST],
    }
    scope.update(change or {})
    incoming = iter(messages or [{"type": "http.request", "body": b""}])
    output = []
    reached = []

    async def receive():
        if timeout:
            raise TimeoutError
        return next(incoming)

    async def send(message):
        output.append(message)

    async def downstream(actual_scope, actual_receive, actual_send):
        reached.append((actual_scope["type"], await actual_receive()))
        if fail:
            raise RuntimeError("synthetic exception text must stay private")
        await actual_send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": [(b"cache-control", b"public"), (b"x-frame-options", b"ALLOWALL")],
            }
        )
        await actual_send({"type": "http.response.body", "body": b""})

    asyncio.run(SecurityBoundary(downstream, ORIGIN)(scope, receive, send))
    return output, reached


@pytest.mark.parametrize(
    ("change", "status"),
    [
        ({"scheme": "http"}, 400),
        ({"headers": [HOST, HOST]}, 403),
        ({"headers": []}, 403),
        ({"headers": [HOST, (b"origin", b"https://other.example")]}, 403),
        ({"headers": [HOST, (b"origin", ORIGIN.encode()), (b"origin", ORIGIN.encode())]}, 403),
        ({"method": "POST"}, 403),
        ({"headers": [HOST, (b"sec-fetch-site", b"cross-site")]}, 403),
        ({"headers": [HOST, (b"x-large", b"a" * 16385)]}, 431),
        ({"path": "/" + "a" * 2048}, 414),
        ({"query_string": b"a" * 2049}, 414),
        ({"headers": [HOST, (b"content-length", b"1"), (b"content-length", b"1")]}, 400),
        ({"headers": [HOST, (b"content-length", b"-1")]}, 400),
        ({"headers": [HOST, (b"content-length", b"16385")]}, 413),
    ],
)
def test_rejects_untrusted_authority_and_resource_metadata_before_dispatch(change, status):
    output, reached = exchange(change=change)
    assert not reached
    assert output[0]["status"] == status
    assert dict(output[0]["headers"])[b"cache-control"] == b"no-store"


@pytest.mark.parametrize(
    ("messages", "status"),
    [
        ([{"type": "http.disconnect"}], 400),
        ([{"type": "http.request", "body": b"a"}], 400),
        ([{"type": "http.request", "body": b"a" * 16385}], 413),
        ([{"type": "http.request", "body": b"", "more_body": True}] * 65, 413),
    ],
)
def test_bounds_streamed_request_body_and_rejects_disconnect(messages, status):
    output, reached = exchange(messages=messages)
    assert not reached
    assert output[0]["status"] == status


def test_timeout_fails_closed_and_exception_text_never_reaches_client_or_log(caplog):
    output, reached = exchange(timeout=True)
    assert not reached and output[0]["status"] == 408
    output, reached = exchange(fail=True)
    assert len(reached) == 1 and output[0]["status"] == 500
    assert b"synthetic exception" not in output[1]["body"]
    assert "synthetic exception" not in caplog.text


def test_valid_post_body_replayed_once_and_downstream_cannot_remove_security_headers():
    output, reached = exchange(
        change={"method": "POST", "headers": [HOST, (b"origin", ORIGIN.encode())]},
        messages=[
            {"type": "http.request", "body": b"body=one&", "more_body": True},
            {"type": "http.request", "body": b"body=two", "more_body": False},
        ],
    )
    assert reached == [
        ("http", {"type": "http.request", "body": b"body=one&body=two", "more_body": False})
    ]
    assert output[0]["status"] == 204
    headers = output[0]["headers"]
    assert [v for k, v in headers if k == b"cache-control"] == [b"no-store"]
    assert [v for k, v in headers if k == b"x-frame-options"] == [b"DENY"]
