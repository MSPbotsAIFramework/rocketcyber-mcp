# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Credential middleware: 401 on missing headers, deferred format errors, per-request isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from rocketcyber_mcp.__main__ import build_http_app
from rocketcyber_mcp.server import (
    GatewayCredentialsMiddleware,
    _credentials_var,
    create_mcp_server,
    get_client_from_context,
)

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize("value", [None, "", "  ", "${ROCKETCYBER_API_KEY}"])
def test_missing_key_returns_401(value):
    headers = dict(MCP_HEADERS)
    if value is not None:
        headers["X-Rocketcyber-Api-Key"] = value
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == ["X-Rocketcyber-Api-Key"]


def test_unknown_region_still_lists_tools():
    # The admin console refreshes the tool catalog with placeholder header values.
    headers = MCP_HEADERS | {"X-Rocketcyber-Api-Key": "placeholder", "X-Rocketcyber-Region": "placeholder"}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=headers)
    assert resp.status_code == 200
    assert "rocketcyber_list_incidents" in resp.text


def test_unknown_region_is_reported_by_tools():
    seen = _run_middleware([(b"x-rocketcyber-api-key", b"k"), (b"x-rocketcyber-region", b"apac")])
    assert "us, eu" in seen["client"].header_error
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "rocketcyber_test_connection", "arguments": {}}}
    headers = MCP_HEADERS | {"X-Rocketcyber-Api-Key": "k", "X-Rocketcyber-Region": "apac"}
    with _client() as client:
        resp = client.post("/mcp", json=call, headers=headers)
    assert resp.status_code == 200
    assert '\\"invalid_argument\\"' in resp.text and "us, eu" in resp.text


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | {"X-Rocketcyber-Api-Key": "your-api-key"})
    assert resp.status_code == 200
    for name in ("rocketcyber_list_incidents", "rocketcyber_list_events", "rocketcyber_get_office"):
        assert name in resp.text


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, receive, send))
    return seen


def test_key_reaches_request_context_and_is_reset():
    seen = _run_middleware([(b"x-rocketcyber-api-key", b" key-123 ")])
    assert seen["credentials"].api_key == "key-123"
    assert seen["client"].base_url == "https://api-us.rocketcyber.com/v3"
    assert _credentials_var.get() is None


@pytest.mark.parametrize("value", [b"eu", b"EU", b" eu "])
def test_eu_region(value):
    seen = _run_middleware([(b"x-rocketcyber-api-key", b"k"), (b"x-rocketcyber-region", value)])
    assert seen["client"].base_url == "https://api-eu.rocketcyber.com/v3"


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().api_key
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().api_key))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = GatewayCredentialsMiddleware(app)

    def scope(key: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-rocketcyber-api-key", key)]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), receive, send), middleware(scope(b"tenant-b"), receive, send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_key():
    seen = _run_middleware([(b"x-rocketcyber-api-key", b"very-secret-key")])
    assert "very-secret-key" not in repr(seen["credentials"])
