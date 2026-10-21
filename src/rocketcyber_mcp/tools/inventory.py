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
"""Monitored assets and posture: agents, firewalls, detection apps, Defender and Microsoft 365."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import RocketCyberClient
from ._common import (
    READ_ONLY,
    DEFAULT_PAGE_SIZE,
    AccountId,
    ClientFactory,
    Page,
    PageSize,
    Sort,
    compact,
    date_range,
    enum_value,
    local_filter,
    matches_exact,
    matches_substring,
    page_params,
    page_summary,
    run_tool,
    sort_param,
)


# Response fields the local (returned-page) firewall filters look at, first non-empty wins.
_FIREWALL_CONNECTIVITY = ("connectivity", "details.connectivity")
_FIREWALL_HOSTNAME = ("hostname", "details.hostname", "name", "details.name")
Connectivity = Literal["online", "offline"]
AppStatus = Literal["active", "inactive"]


def _text(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None


def slice_apps(payload: Any, page: int | None, page_size: int | None) -> Any:
    """Page the (unpaged) app list locally; without page/pageSize every app is returned."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return payload
    apps = payload["data"]
    size = page_size or (DEFAULT_PAGE_SIZE if page else max(len(apps), 1))
    current = page or 1
    pages = max((len(apps) + size - 1) // size, 1)
    chunk = apps[(current - 1) * size : current * size]
    summary = {"count": len(chunk), "total": len(apps), "page": current, "total_pages": pages, "has_more": current < pages}
    if current < pages:
        summary["next_page"] = current + 1
    rest = {k: v for k, v in payload.items() if k not in ("data", "currentPage", "totalPages", "totalCount", "dataCount")}
    return {"summary": summary, **rest, "dataCount": len(chunk), "data": chunk}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_list_agents(
        page: Page = None,
        pageSize: PageSize = None,
        sort: Sort = None,
        accountId: AccountId = None,
        connectivity: Annotated[Connectivity | str | None, Field(description="Only agents in this state.")] = None,
        hostname: Annotated[str | None, Field(description="Hostname; * is a wildcard, e.g. *-SRV-*.")] = None,
        platform: Annotated[str | None, Field(description="Operating system; * is a wildcard, e.g. Windows*.")] = None,
        dates: Annotated[
            str | None, Field(description="Agent installed between start|end (ISO, either side may be empty), e.g. 2026-01-01|.")
        ] = None,
    ) -> str:
        """List monitored endpoint agents with OS, IP, version and online state."""

        async def action(client: RocketCyberClient) -> Any:
            params = page_params(page, pageSize, sort) | compact(
                {
                    "accountId": accountId,
                    "connectivity": enum_value(connectivity, Connectivity),
                    "hostname": _text(hostname),
                    "os": _text(platform),
                    "created": date_range(dates),
                }
            )
            return page_summary(await client.get("agents", params))

        return await run_tool("rocketcyber_list_agents", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_list_firewalls(
        page: Page = None,
        pageSize: PageSize = None,
        sort: Sort = None,
        accountId: AccountId = None,
        vendor: Annotated[str | None, Field(description="Firewall type (vendor), e.g. sonicwall.")] = None,
        ipAddress: Annotated[str | None, Field(description="Firewall IP address.")] = None,
        macAddress: Annotated[str | None, Field(description="Firewall MAC address.")] = None,
        connectivity: Annotated[
            str | None,
            Field(description="Connection state, e.g. online. Filters the returned page (case-insensitive, exact)."),
        ] = None,
        hostname: Annotated[
            str | None, Field(description="Hostname text. Filters the returned page (case-insensitive substring).")
        ] = None,
    ) -> str:
        """List firewalls sending logs to RocketCyber, with log counters."""

        async def action(client: RocketCyberClient) -> Any:
            params = page_params(page, pageSize, sort) | compact(
                {
                    "accountId": accountId,
                    "type": _text(vendor),
                    "ipAddress": _text(ipAddress),
                    "macAddress": _text(macAddress),
                }
            )
            result = await client.get("firewalls", params)
            wanted_state, wanted_host = _text(connectivity), _text(hostname)
            if wanted_state:
                result = local_filter(
                    result, f"connectivity={wanted_state}",
                    lambda i: matches_exact(i, _FIREWALL_CONNECTIVITY, wanted_state),
                    _FIREWALL_CONNECTIVITY,
                )
            if wanted_host:
                result = local_filter(
                    result, f"hostname containing {wanted_host!r}",
                    lambda i: matches_substring(i, _FIREWALL_HOSTNAME, wanted_host),
                    _FIREWALL_HOSTNAME,
                )
            return page_summary(result)

        return await run_tool("rocketcyber_list_firewalls", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_list_apps(
        page: Annotated[
            int | None, Field(description="Page of the app list, from 1 (paged locally; the API returns every app).", ge=1)
        ] = None,
        pageSize: Annotated[
            int | None,
            Field(description=f"Apps per page (default: all, or {DEFAULT_PAGE_SIZE} when page is set).", ge=1, le=200),
        ] = None,
        sort: Annotated[str | None, Field(description="id or name, optionally :asc / :desc (default id).")] = None,
        accountId: AccountId = None,
        status: Annotated[
            AppStatus | str | None, Field(description="Enabled (active, default) or disabled apps.")
        ] = None,
        name: Annotated[str | None, Field(description="Only apps whose name contains this text.")] = None,
    ) -> str:
        """List detection apps (ids and descriptions); events are grouped by app id."""

        async def action(client: RocketCyberClient) -> Any:
            field, _, order = (sort_param(sort) or "").partition(":")
            if field and field not in ("id", "name"):
                raise ValueError("sort must be id or name, optionally with :asc or :desc.")
            params = compact({"accountId": accountId, "status": enum_value(status, AppStatus), "sort": field or None, "order": order or None})
            result = await client.get("apps", params)
            needle = _text(name)
            if needle and isinstance(result, dict) and isinstance(result.get("data"), list):
                apps = [a for a in result["data"] if needle.lower() in str((a or {}).get("name", "")).lower()]
                result = {**result, "data": apps, "dataCount": len(apps), "note": f"Filtered by name containing {needle!r}."}
            return slice_apps(result, page, pageSize)

        return await run_tool("rocketcyber_list_apps", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_get_defender(accountId: AccountId = None) -> str:
        """Get Microsoft Defender status: endpoint health and Defender detections."""

        async def action(client: RocketCyberClient) -> Any:
            return await client.get("defender", compact({"accountId": accountId}))

        return await run_tool("rocketcyber_get_defender", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_get_office(accountId: AccountId = None) -> str:
        """Get Microsoft 365 security status, such as the Secure Score trend."""

        async def action(client: RocketCyberClient) -> Any:
            return await client.get("office", compact({"accountId": accountId}))

        return await run_tool("rocketcyber_get_office", client_factory, action)
