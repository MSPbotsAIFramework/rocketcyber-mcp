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
"""Request shapes, filter mapping and retries against a mocked RocketCyber API."""

import json

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from rocketcyber_mcp import api_client
from rocketcyber_mcp.api_client import (
    RocketCyberClient,
    RocketCyberCredentials,
    RocketCyberError,
)
from rocketcyber_mcp.server import _credentials_var, create_mcp_server

CREDS = RocketCyberCredentials(api_key="key-123")
PAGE = {"totalCount": 1, "currentPage": 1, "totalPages": 1, "dataCount": 1, "data": [{"id": "1"}]}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)


class Recorder:
    """Mock transport: replies by path below /v3/."""

    def __init__(self, routes=None, default=None):
        self.requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else PAGE

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/v3/")
        reply = self.routes.get(path, self.default)
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def params(self, index: int = 0) -> dict:
        return dict(self.requests[index].url.params)


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, creds=CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(creds)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder) -> RocketCyberClient:
    return RocketCyberClient(CREDS, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- client ----------------------------------------------------------------


async def test_bearer_header_and_url():
    rec = Recorder()
    await _client(rec).get("agents", {"page": 2})
    request = rec.requests[0]
    assert str(request.url) == "https://api-us.rocketcyber.com/v3/agents?page=2"
    assert request.headers["Authorization"] == "Bearer key-123"


async def test_eu_region_url(monkeypatch):
    rec = Recorder({"account": {"name": "x"}})
    await _call(monkeypatch, rec, "rocketcyber_get_account", {}, RocketCyberCredentials(api_key="k", region="eu"))
    assert rec.requests[0].url.host == "api-eu.rocketcyber.com"


async def test_error_message_and_key_redaction():
    body = {"name": "Authentication Error", "statusCode": 401, "message": "Authentication failed for key-123"}
    rec = Recorder({"account": lambda r: httpx.Response(401, json=body)})
    with pytest.raises(RocketCyberError) as err:
        await _client(rec).get("account")
    assert err.value.status_code == 401
    assert "Authentication failed" in err.value.message and "key-123" not in err.value.message


async def test_get_retries_5xx():
    replies = iter([httpx.Response(502), httpx.Response(200, json=PAGE)])
    rec = Recorder({"agents": lambda r: next(replies)})
    await _client(rec).get("agents")
    assert len(rec.requests) == 2


async def test_429_honours_retry_after_then_fails():
    rec = Recorder({"agents": lambda r: httpx.Response(429, headers={"Retry-After": "1"}, json={"message": "slow down"})})
    with pytest.raises(RocketCyberError) as err:
        await _client(rec).get("agents")
    assert err.value.status_code == 429
    assert len(rec.requests) == 3


async def test_unauthorized_envelope(monkeypatch):
    rec = Recorder({"account": lambda r: httpx.Response(401, json={"message": "Authentication failed."})})
    result = await _call(monkeypatch, rec, "rocketcyber_test_connection", {})
    assert result["error"]["code"] == "unauthorized"


# ---- tools -----------------------------------------------------------------


async def test_test_connection(monkeypatch):
    rec = Recorder({"account": {"name": "x"}})
    result = await _call(monkeypatch, rec, "rocketcyber_test_connection", {})
    assert result == {"connected": True, "base_url": "https://api-us.rocketcyber.com/v3"}


async def test_get_account(monkeypatch):
    rec = Recorder({"account": {"name": "x"}})
    await _call(monkeypatch, rec, "rocketcyber_get_account", {"accountId": 42})
    assert rec.params() == {"accountId": "42"}


async def test_agents_filters(monkeypatch):
    rec = Recorder()
    args = {"accountId": 2, "connectivity": "offline", "hostname": "*-SRV-*", "platform": "Windows*",
            "dates": "2026-01-01", "page": 2, "pageSize": 50, "sort": "hostname:desc"}
    result = await _call(monkeypatch, rec, "rocketcyber_list_agents", args)
    assert rec.params() == {
        "accountId": "2", "connectivity": "offline", "hostname": "*-SRV-*", "os": "Windows*",
        "created": "2026-01-01|", "page": "2", "pageSize": "50", "sort": "hostname:desc",
    }
    assert result["summary"]["count"] == 1


async def test_incidents_defaults_and_trim(monkeypatch):
    long = "x " * 400
    rec = Recorder({"incidents": {**PAGE, "data": [{"id": "1", "description": long}]}})
    result = await _call(monkeypatch, rec, "rocketcyber_list_incidents", {"status": "open", "dates": "2026-01-01|2026-01-31"})
    assert rec.params() == {"pageSize": "25", "sort": "createdAt:desc", "status": "open", "createdAt": "2026-01-01|2026-01-31"}
    assert len(result["data"][0]["description"]) < 360


async def test_incidents_verbose(monkeypatch):
    long = "x " * 400
    rec = Recorder({"incidents": {**PAGE, "data": [{"id": "1", "description": long}]}})
    result = await _call(monkeypatch, rec, "rocketcyber_list_incidents", {"verbose": True})
    assert result["data"][0]["description"] == long


async def test_events_mapping(monkeypatch):
    rec = Recorder()
    args = {"appId": 34, "severity": "malicious", "dates": "|2026-02-01", "deviceId": "d1", "details": "attributes.city:Austin"}
    await _call(monkeypatch, rec, "rocketcyber_list_events", args)
    assert rec.params() == {
        "appId": "34", "verdict": "malicious", "dates": "|2026-02-01", "deviceId": "d1",
        "details": "attributes.city:Austin", "pageSize": "25",
    }


async def test_events_need_app_id(monkeypatch):
    rec = Recorder()
    with pytest.raises(ToolError):
        await _call(monkeypatch, rec, "rocketcyber_list_events", {})
    assert rec.requests == []


async def test_event_summary(monkeypatch):
    rec = Recorder({"events/summary": {"total": 3}})
    await _call(monkeypatch, rec, "rocketcyber_get_event_summary", {"accountId": 2, "dates": "2026-01-01"})
    assert rec.params() == {"accountId": "2", "dates": "2026-01-01|"}


async def test_firewalls_vendor_maps_to_type(monkeypatch):
    rec = Recorder()
    await _call(monkeypatch, rec, "rocketcyber_list_firewalls", {"vendor": "sonicwall", "ipAddress": "203.0.113.1"})
    assert rec.params() == {"type": "sonicwall", "ipAddress": "203.0.113.1", "pageSize": "25"}


async def test_apps_sort_and_name_filter(monkeypatch):
    data = [{"id": 2, "name": "Advanced Breach Detection"}, {"id": 34, "name": "Defender Manager"}]
    rec = Recorder({"apps": {"totalCount": 2, "currentPage": 1, "totalPages": 1, "dataCount": 2, "data": data}})
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {"sort": "name:desc", "status": "active", "name": "defender"})
    assert rec.params() == {"sort": "name", "order": "desc", "status": "active"}
    assert [a["id"] for a in result["data"]] == [34]


async def test_apps_bad_sort(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {"sort": "createdAt"})
    assert result["error"]["code"] == "invalid_argument"
    assert rec.requests == []


@pytest.mark.parametrize("tool,path", [("rocketcyber_get_defender", "defender"), ("rocketcyber_get_office", "office")])
async def test_posture_tools(monkeypatch, tool, path):
    rec = Recorder({path: {"ok": True}})
    result = await _call(monkeypatch, rec, tool, {"accountId": 7})
    assert rec.requests[0].url.path == f"/v3/{path}"
    assert rec.params() == {"accountId": "7"}
    assert result == {"ok": True}
