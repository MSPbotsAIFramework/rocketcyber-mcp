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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import RocketCyberClient, RocketCyberCredentials
from .config import DEFAULT_REGION, REGION_BASE_URLS, Settings

HEADER_API_KEY = "X-Rocketcyber-Api-Key"
HEADER_REGION = "X-Rocketcyber-Region"

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. Nothing credential-related is
# ever stored at module level.
_credentials_var: contextvars.ContextVar[RocketCyberCredentials | None] = contextvars.ContextVar(
    "rocketcyber_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("rocketcyber_request_id", default="-")

INSTRUCTIONS = (
    "RocketCyber is a managed SOC: agents on endpoints and firewall log "
    "collectors feed detection apps, and confirmed threats become incidents.\n"
    "Usage:\n"
    "- Start with rocketcyber_list_incidents (status e.g. open, closed; title; "
    "dates) for what needs attention; text is trimmed unless verbose=true.\n"
    "- accountId scopes any tool to one customer account; without it the "
    "tools cover every account the API key can see. rocketcyber_get_account "
    "lists the account hierarchy and ids.\n"
    "- Events always belong to one detection app: call "
    "rocketcyber_get_event_summary (per-app counts) or rocketcyber_list_apps "
    "first, then rocketcyber_list_events with that appId.\n"
    "- dates filters take start|end (either side may be empty), e.g. "
    "2026-01-01|2026-01-31 or 2026-01-01|.\n"
    "- Lists page with page and pageSize; sort takes field:asc or field:desc.\n"
    "All tools are read-only."
)


def get_client_from_context() -> RocketCyberClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return RocketCyberClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


class GatewayCredentialsMiddleware:
    """Reads the RocketCyber headers on /mcp requests into the request context.

    401 without an API key. A region other than us / eu does not block the request
    (tools/list must work with any values); tools report it instead.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = _clean(request.headers.get(HEADER_API_KEY))
        if not api_key:
            await JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": f"Send the RocketCyber API key in the {HEADER_API_KEY} header",
                    "required_headers": [HEADER_API_KEY],
                },
                status_code=401,
            )(scope, receive, send)
            return

        region = (_clean(request.headers.get(HEADER_REGION)) or DEFAULT_REGION).lower()
        header_error = None
        if region not in REGION_BASE_URLS:
            header_error = f"{HEADER_REGION} must be one of: {', '.join(REGION_BASE_URLS)}"
            region = DEFAULT_REGION

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(RocketCyberCredentials(api_key=api_key, region=region, header_error=header_error))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="rocketcyber-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], RocketCyberClient | None] = get_client_from_context

    from .tools import account, detections, inventory

    for module in (account, detections, inventory):
        module.register(mcp, client_factory)

    return mcp
