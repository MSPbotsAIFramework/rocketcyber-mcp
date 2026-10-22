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


# ---- Page-number paging that survives truncation ----------------------------
# RocketCyber pages by page + pageSize only. offset reads the page that holds a record position
# and next_offset continues right after the last record returned, also when a page is cut to fit
# the response size limit (the rest of a cut page is on no other page).

TOTAL = 130
# Many short fields: shortening long values cannot make 25 such records fit 20,000 characters.
BLOB = {f"field{k}": "z" * 60 for k in range(30)}


def _paged_api(records):
    """Fake API paging ``records`` by page (from 1) and pageSize like RocketCyber."""

    def reply(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", 1))
        size = int(request.url.params.get("pageSize", 1000))
        pages = max((len(records) + size - 1) // size, 1)
        chunk = records[(page - 1) * size : page * size]
        return httpx.Response(
            200,
            json={"totalCount": len(records), "currentPage": page, "totalPages": pages, "dataCount": len(chunk), "data": chunk},
        )

    return reply


def _records(blob=None):
    return [{"id": n, "hostname": f"host-{n}", "connectivity": "online" if n % 2 else "offline", "blob": BLOB if blob is None else blob} for n in range(TOTAL)]


def _routes(records):
    every = {"totalCount": len(records), "currentPage": 1, "totalPages": 1, "dataCount": len(records), "data": records}
    paged = _paged_api(records)
    return {"incidents": paged, "events": paged, "agents": paged, "firewalls": paged, "apps": every}


PAGED_TOOLS = [
    ("rocketcyber_list_incidents", {}),
    ("rocketcyber_list_events", {"appId": 7}),
    ("rocketcyber_list_agents", {}),
    ("rocketcyber_list_firewalls", {}),
    ("rocketcyber_list_apps", {}),
]


async def _walk(monkeypatch, rec, tool, args):
    """Follow next_offset until it ends; every result is checked for a retry hint."""
    seen, calls = [], 0
    result = await _call(monkeypatch, rec, tool, args)
    while True:
        calls += 1
        assert calls < 100
        seen += [r["id"] for r in result["data"]]
        if "next_offset" in result:
            assert "retry_page_size" not in result
        if not result.get("next_offset"):
            assert "next_offset" not in result and result["summary"]["has_more"] is False
            return seen, calls
        rest = {k: v for k, v in args.items() if k != "page"}
        result = await _call(monkeypatch, rec, tool, {**rest, "offset": result["next_offset"]})


@pytest.mark.parametrize("tool,base", PAGED_TOOLS)
async def test_cut_pages_walked_by_next_offset_return_every_record_once(monkeypatch, tool, base):
    rec = Recorder(_routes(_records()))
    seen, calls = await _walk(monkeypatch, rec, tool, {**base, "pageSize": 25})
    assert seen == list(range(TOTAL))
    assert calls > TOTAL // 25 + 1  # pages really were cut


@pytest.mark.parametrize("tool,base", PAGED_TOOLS)
async def test_cut_pages_walked_from_a_later_page(monkeypatch, tool, base):
    rec = Recorder(_routes(_records()))
    seen, _ = await _walk(monkeypatch, rec, tool, {**base, "page": 3, "pageSize": 25})
    assert seen == list(range(50, TOTAL))


@pytest.mark.parametrize("tool,base", PAGED_TOOLS)
@pytest.mark.parametrize("offset,page,ids", [(30, 2, range(30, 50)), (25, 2, range(25, 50)), (0, 1, range(25))])
async def test_offset_reads_the_page_that_holds_it(monkeypatch, tool, base, offset, page, ids):
    rec = Recorder(_routes(_records(blob="")))
    result = await _call(monkeypatch, rec, tool, {**base, "pageSize": 25, "offset": offset})
    assert [r["id"] for r in result["data"]] == list(ids)
    assert result["offset"] == offset
    assert result["next_offset"] == page * 25
    assert result["summary"]["page"] == page
    if tool != "rocketcyber_list_apps":
        assert rec.params()["page"] == str(page) and rec.params()["pageSize"] == "25"


@pytest.mark.parametrize("tool,base", PAGED_TOOLS)
async def test_offset_past_the_end(monkeypatch, tool, base):
    rec = Recorder(_routes(_records(blob="")))
    result = await _call(monkeypatch, rec, tool, {**base, "pageSize": 25, "offset": 1000})
    assert result["data"] == [] and result["summary"]["has_more"] is False and "next_offset" not in result


@pytest.mark.parametrize("tool,base", PAGED_TOOLS)
async def test_offset_wins_over_page(monkeypatch, tool, base):
    rec = Recorder(_routes(_records(blob="")))
    result = await _call(monkeypatch, rec, tool, {**base, "page": 1, "pageSize": 25, "offset": 60})
    assert [r["id"] for r in result["data"]] == list(range(60, 75))
    if tool != "rocketcyber_list_apps":
        assert rec.params()["page"] == "3"


@pytest.mark.parametrize(
    "tool,base,expected",
    [
        ("rocketcyber_list_incidents", {}, {"sort": "createdAt:desc"}),
        ("rocketcyber_list_events", {"appId": 7}, {"appId": "7"}),
        ("rocketcyber_list_agents", {}, {}),
        ("rocketcyber_list_firewalls", {}, {}),
    ],
)
@pytest.mark.parametrize("paging,sent", [({"page": 2, "pageSize": 25}, {"page": "2", "pageSize": "25"}), ({}, {"pageSize": "25"})])
async def test_page_only_call_sends_the_same_request(monkeypatch, tool, base, expected, paging, sent):
    rec = Recorder(_routes(_records(blob="")))
    result = await _call(monkeypatch, rec, tool, {**base, **paging})
    assert rec.params() == {**expected, **sent}
    first = (paging.get("page", 1) - 1) * 25
    assert [r["id"] for r in result["data"]] == list(range(first, first + 25))
    assert result["summary"]["next_page"] == paging.get("page", 1) + 1


async def test_apps_page_only_call_unchanged(monkeypatch):
    rec = Recorder(_routes(_records(blob="")))
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {"page": 2, "pageSize": 25})
    assert rec.params() == {} and [r["id"] for r in result["data"]] == list(range(25, 50))
    result = await _call(monkeypatch, rec, "rocketcyber_list_apps", {})
    assert [r["id"] for r in result["data"]] == list(range(TOTAL)) and "next_offset" not in result


@pytest.mark.parametrize(
    "tool,base,keep",
    [
        ("rocketcyber_list_firewalls", {"hostname": "host-"}, lambda r: True),
        ("rocketcyber_list_firewalls", {"connectivity": "online"}, lambda r: r["id"] % 2),
        ("rocketcyber_list_events", {"appId": 7, "hostname": "host-1"}, lambda r: "host-1" in r["hostname"]),
    ],
)
async def test_locally_filtered_cut_page_retries_from_the_same_offset(monkeypatch, tool, base, keep):
    """A local filter makes returned positions non-consecutive: a cut page gives no next_offset
    but retry_page_size, and retrying from the same offset with that page size loses nothing."""
    records = _records()
    rec = Recorder(_routes(records))
    seen, offset, size, cut = [], 0, 25, False
    for _ in range(200):
        result = await _call(monkeypatch, rec, tool, {**base, "pageSize": size, "offset": offset})
        if result.get("truncated"):
            assert "next_offset" not in result
            cut, size = True, result["retry_page_size"]
            continue
        seen += [r["id"] for r in result["data"]]
        if "next_offset" not in result:
            break
        offset = result["next_offset"]
    assert cut and seen == [r["id"] for r in records if keep(r)]


async def test_cut_page_also_fixes_the_nested_paging_summary(monkeypatch):
    # The paging summary is nested, so the size limit's own cleanup does not reach it: a cut page
    # must not keep summary.next_page (it would skip the cut records) or the full page's count.
    rec = Recorder(_routes(_records()))
    result = await _call(monkeypatch, rec, "rocketcyber_list_agents", {"page": 1, "pageSize": 100})
    returned = len(result["data"])
    assert result["truncated"] is True and 0 < returned < 100 and result["next_offset"] == returned
    assert "next_page" not in result["summary"] and result["summary"]["has_more"] is True
    if "count" in result["summary"]:
        assert result["summary"]["count"] == returned
