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
"""Incidents (confirmed threats) and app events (raw detections)."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import RocketCyberClient
from ._common import (
    READ_ONLY,
    AccountId,
    ClientFactory,
    Dates,
    Page,
    PageSize,
    Sort,
    compact,
    date_range,
    page_params,
    page_summary,
    run_tool,
)

# Incident description / remediation can run to several KB each.
_FREE_TEXT_FIELDS = ("description", "remediation")
_TEXT_LIMIT = 300


def _trim(text: str) -> str:
    if len(text) <= _TEXT_LIMIT:
        return text
    cut = text[:_TEXT_LIMIT]
    space = cut.rfind(" ")
    return (cut[:space] if space > 0 else cut) + "... [truncated; verbose=true for full text]"


def trim_incidents(payload: Any) -> Any:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return payload
    trimmed = [
        {k: _trim(v) if k in _FREE_TEXT_FIELDS and isinstance(v, str) else v for k, v in item.items()}
        if isinstance(item, dict)
        else item
        for item in payload["data"]
    ]
    return {**payload, "data": trimmed}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_list_incidents(
        page: Page = None,
        pageSize: PageSize = None,
        sort: Sort = None,
        accountId: AccountId = None,
        status: Annotated[str | None, Field(description="Incident status, e.g. open, closed, suppressed.")] = None,
        dates: Annotated[
            str | None, Field(description="Created between start|end (ISO dates, either side may be empty), e.g. 2026-01-01|.")
        ] = None,
        title: Annotated[str | None, Field(description="Title filter; * is a wildcard, e.g. *Office*.")] = None,
        verbose: Annotated[
            bool | None, Field(description="Return full description / remediation text (default: trimmed to ~300 characters).")
        ] = None,
    ) -> str:
        """List security incidents (threats the SOC confirmed), newest first by default."""

        async def action(client: RocketCyberClient) -> Any:
            params = page_params(page, pageSize, sort or "createdAt:desc") | compact(
                {
                    "accountId": accountId,
                    "status": status.strip() if status else None,
                    "createdAt": date_range(dates),
                    "title": title.strip() if title else None,
                }
            )
            result = await client.get("incidents", params)
            return page_summary(result if verbose else trim_incidents(result))

        return await run_tool("rocketcyber_list_incidents", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_list_events(
        appId: Annotated[
            int,
            Field(
                description="Detection app the events belong to (required by the API). Get ids from "
                "rocketcyber_get_event_summary (apps with events) or rocketcyber_list_apps."
            ),
        ],
        page: Page = None,
        pageSize: PageSize = None,
        sort: Sort = None,
        accountId: AccountId = None,
        severity: Annotated[
            Literal["malicious", "suspicious", "informational"] | None,
            Field(description="Only events with this verdict."),
        ] = None,
        dates: Dates = None,
        deviceId: Annotated[str | None, Field(description="Only events of this agent device id.")] = None,
        details: Annotated[
            str | None, Field(description="Filter on an event detail field as path:value, e.g. attributes.city:Redmond.")
        ] = None,
    ) -> str:
        """List the events (detections) of one detection app."""

        async def action(client: RocketCyberClient) -> Any:
            params = page_params(page, pageSize, sort) | compact(
                {
                    "appId": appId,
                    "accountId": accountId,
                    "verdict": severity,
                    "dates": date_range(dates),
                    "deviceId": deviceId.strip() if deviceId else None,
                    "details": details.strip() if details else None,
                }
            )
            return page_summary(await client.get("events", params))

        return await run_tool("rocketcyber_list_events", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_get_event_summary(accountId: AccountId = None, dates: Dates = None) -> str:
        """Count events per detection app and verdict; shows which appIds have events."""

        async def action(client: RocketCyberClient) -> Any:
            return await client.get("events/summary", compact({"accountId": accountId, "dates": date_range(dates)}))

        return await run_tool("rocketcyber_get_event_summary", client_factory, action)
