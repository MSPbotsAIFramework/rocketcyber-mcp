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
"""tools/list snapshot, filter helpers and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from rocketcyber_mcp.api_client import RocketCyberError
from rocketcyber_mcp.server import INSTRUCTIONS, create_mcp_server
from rocketcyber_mcp.tools._common import date_range, page_summary, sort_param
from rocketcyber_mcp.tools.detections import trim_incidents

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "rocketcyber_test_connection": set(),
    "rocketcyber_get_account": set(),
    "rocketcyber_list_agents": set(),
    "rocketcyber_list_incidents": set(),
    "rocketcyber_list_events": {"appId"},
    "rocketcyber_get_event_summary": set(),
    "rocketcyber_list_firewalls": set(),
    "rocketcyber_list_apps": set(),
    "rocketcyber_get_defender": set(),
    "rocketcyber_get_office": set(),
}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_all_tools_are_read_only(tools, name):
    annotations = tools[name].annotations
    assert annotations.readOnlyHint is True
    assert not annotations.destructiveHint


def test_public_parameter_names_are_camel_case(tools):
    properties = tools["rocketcyber_list_events"].inputSchema["properties"]
    assert {"appId", "pageSize", "accountId"} <= set(properties)


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500


@pytest.mark.parametrize(
    "status,code,retryable",
    [(401, "unauthorized", False), (403, "unauthorized", False), (404, "not_found", False),
     (400, "invalid_argument", False), (429, "rate_limited", True), (500, "upstream_error", True), (0, "upstream_error", True)],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(RocketCyberError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("rocketcyber_test_connection", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"


@pytest.mark.parametrize(
    "value,expected",
    [("2026-01-01|2026-01-31", "2026-01-01|2026-01-31"), ("2026-01-01", "2026-01-01|"),
     (" |2026-02-01 ", "|2026-02-01"), ("", None), (None, None)],
)
def test_date_range(value, expected):
    assert date_range(value) == expected


@pytest.mark.parametrize("value", ["|", "a|b|c"])
def test_date_range_rejects(value):
    with pytest.raises(ValueError):
        date_range(value)


@pytest.mark.parametrize(
    "value,expected", [("createdAt", "createdAt"), ("createdAt:DESC", "createdAt:desc"), (None, None)]
)
def test_sort_param(value, expected):
    assert sort_param(value) == expected


def test_sort_param_rejects():
    with pytest.raises(ValueError):
        sort_param("createdAt desc; drop")


def test_page_summary():
    shaped = page_summary({"totalCount": 30, "currentPage": 1, "totalPages": 2, "data": [{"id": 1}]})
    assert shaped["summary"] == {"count": 1, "total": 30, "page": 1, "total_pages": 2, "has_more": True, "next_page": 2}


def test_trim_incidents():
    long = "word " * 200
    shaped = trim_incidents({"data": [{"id": 1, "description": long, "remediation": "short", "title": long}]})
    item = shaped["data"][0]
    assert len(item["description"]) < 360 and item["description"].endswith("verbose=true for full text]")
    assert item["remediation"] == "short"
    assert item["title"] == long
