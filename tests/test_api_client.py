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
    result = await _call(monkeypatch, rec, "rocketcyber_list_events", {})
    assert result["error"]["code"] == "invalid_argument"
    assert "appId" in result["error"]["message"] and "rocketcyber_list_apps" in result["error"]["message"]
    assert rec.requests == []


async def test_bad_argument_type_still_raises(monkeypatch):
    with pytest.raises(ToolError):
        await _call(monkeypatch, Recorder(), "rocketcyber_list_events", {"appId": "not-a-number"})


def _page(items):
    return {"totalCount": 40, "currentPage": 1, "totalPages": 2, "dataCount": len(items), "data": items}


async def test_events_local_event_type_and_hostname(monkeypatch):
    items = [
        {"appId": 60, "valueType": "SignIn", "details": {"hostname": "HQ-SRV-01"}},
        {"appId": 60, "valueType": "signin", "details": {"hostname": "branch-lt-07"}},
        {"appId": 60, "valueType": "process", "details": {"hostname": "hq-srv-02"}},
    ]
    rec = Recorder({"events": _page(items)})
    args = {"appId": 60, "eventType": "SIGNIN", "hostname": "srv"}
    result = await _call(monkeypatch, rec, "rocketcyber_list_events", args)
    assert "eventType" not in rec.params() and "hostname" not in rec.params()
    assert [i["details"]["hostname"] for i in result["data"]] == ["HQ-SRV-01"]
    assert result["summary"]["count"] == 1 and result["summary"]["has_more"] is True
    assert "this page" in result["note"]


async def test_incidents_local_severity(monkeypatch):
    items = [
        {"id": 1, "title": "Sophos Event::Endpoint::CoreCleanFailed - high Severity"},
        {"id": 2, "title": "Webroot Detection - low Severity"},
        {"id": 3, "title": "Other", "severity": "High"},
        {"id": 4, "title": "Mentions high Severity", "severity": "low"},
    ]
    rec = Recorder({"incidents": _page(items)})
    result = await _call(monkeypatch, rec, "rocketcyber_list_incidents", {"severity": "HIGH"})
    assert "severity" not in rec.params()
    assert [i["id"] for i in result["data"]] == [1, 3]


async def test_firewalls_local_connectivity_and_hostname(monkeypatch):
    items = [
        {"id": "1", "connectivity": "online", "hostname": "Edge-FW-01"},
        {"id": "2", "connectivity": "Offline", "hostname": "edge-fw-02"},
        {"id": "3", "details": {"type": "sonicwall"}},
    ]
    rec = Recorder({"firewalls": _page(items)})
    result = await _call(monkeypatch, rec, "rocketcyber_list_firewalls", {"connectivity": "offline", "hostname": "FW"})
    assert rec.params() == {"pageSize": "25"}
    assert [i["id"] for i in result["data"]] == ["2"]
    result = await _call(monkeypatch, rec, "rocketcyber_list_firewalls", {"hostname": "edge"})
    assert [i["id"] for i in result["data"]] == ["1", "2"]


async def test_apps_local_paging(monkeypatch):
    data = [{"id": n, "name": f"App {n}"} for n in range(1, 6)]
    rec = Recorder({"apps": {"totalCount": 5, "currentPage": 1, "totalPages": 1, "dataCount": 5, "data": data}})
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {"page": 2, "pageSize": 2})
    assert rec.params() == {}
    assert [a["id"] for a in result["data"]] == [3, 4]
    assert result["summary"] == {"count": 2, "total": 5, "page": 2, "total_pages": 3, "has_more": True, "next_page": 3}
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {"page": 3, "pageSize": 2})
    assert [a["id"] for a in result["data"]] == [5] and result["summary"]["has_more"] is False
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {})
    assert len(result["data"]) == 5 and result["summary"]["has_more"] is False


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


async def test_local_filter_is_skipped_when_no_item_has_the_field(monkeypatch):
    rec = Recorder({"firewalls": {"totalCount": 2, "dataCount": 2, "data": [{"id": "1"}, {"id": "2"}]}})
    result = await _call(monkeypatch, rec, "rocketcyber_list_firewalls", {"connectivity": "offline"})
    assert len(result["data"]) == 2
    assert "not applied" in result["note"]


# ---- compatibility: enum params accept any casing (normalized) and unknown values (passed through)


@pytest.mark.parametrize(
    "tool,args,key,sent",
    [
        ("rocketcyber_list_agents", {"connectivity": "Online"}, "connectivity", "online"),
        ("rocketcyber_list_agents", {"connectivity": "isolated"}, "connectivity", "isolated"),
        ("rocketcyber_list_events", {"appId": 34, "severity": "MALICIOUS"}, "verdict", "malicious"),
        ("rocketcyber_list_events", {"appId": 34, "severity": "benign"}, "verdict", "benign"),
        ("rocketcyber_list_apps", {"status": "Inactive"}, "status", "inactive"),
        ("rocketcyber_list_apps", {"status": "all"}, "status", "all"),
    ],
)
async def test_enum_params_normalized_or_passed_through(monkeypatch, tool, args, key, sent):
    rec = Recorder()
    result = await _call(monkeypatch, rec, tool, args)
    assert "error" not in result
    assert rec.params()[key] == sent
