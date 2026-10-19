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
"""Async client for the RocketCyber customer API (v3)."""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ._json import error_envelope
from .config import DEFAULT_REGION, REGION_BASE_URLS

logger = logging.getLogger("rocketcyber_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_MAX_RETRIES = 2
_QUOTA = re.compile(r"quota|rate limit|too many requests", re.IGNORECASE)
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own key, so
# sharing the pool across tenants is safe.
_shared_http_client: httpx.AsyncClient | None = None


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _shared_http_client


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class RocketCyberError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"RocketCyber API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class RocketCyberCredentials:
    api_key: str
    region: str = DEFAULT_REGION

    @property
    def base_url(self) -> str:
        return REGION_BASE_URLS[self.region]

    def __repr__(self) -> str:  # never leak the key into logs or tracebacks
        return f"RocketCyberCredentials(region={self.region!r}, api_key=<redacted>)"


class RocketCyberClient:
    """RocketCyber API wrapper for one caller's API key."""

    def __init__(self, credentials: RocketCyberCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.base_url = credentials.base_url.rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        return self._http or _get_shared_http_client()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}/{path.strip('/')}"
        query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        headers = {"Authorization": f"Bearer {self._credentials.api_key}", "Accept": "application/json"}
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: RocketCyberError | None = None
            try:
                resp = await self._client().request(method, url, params=query, headers=headers)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, RocketCyberError(0, f"Timed out calling RocketCyber ({method} {path})")
            except httpx.RequestError as e:
                status = 0
                error = RocketCyberError(0, f"Network error calling RocketCyber ({method} {path}): {type(e).__name__}")

            logger.info(
                "rocketcyber_api method=%s path=%s status=%s ms=%d attempt=%d",
                method, path, status, (time.monotonic() - t0) * 1000, attempt,
            )

            # 429 is refused before processing, so any method may retry it; other
            # failures are retried only for reads, so a write never runs twice.
            retryable = status == 429 or (method == "GET" and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                message = _error_message(resp, path).replace(self._credentials.api_key, "[REDACTED]")
                # Quota exhaustion is reported in the body, sometimes with another status.
                status = 429 if _QUOTA.search(resp.text or "") else resp.status_code
                raise RocketCyberError(status, message)
            return _parse_body(resp)


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _parse_body(resp: httpx.Response) -> Any:
    if not resp.content or not resp.content.strip():
        return None
    try:
        return resp.json()
    except ValueError:
        return {"raw_response": resp.text[:2000]}


def _error_message(resp: httpx.Response, path: str) -> str:
    fallback = f"RocketCyber returned HTTP {resp.status_code} for {path}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, list):  # validation errors come as a list of messages
            message = "; ".join(str(m) for m in message)
        parts = [str(v) for v in (message, payload.get("error"), payload.get("detail")) if isinstance(v, str) and v][:1]
        errors = payload.get("errors")
        if isinstance(errors, dict):
            parts += [f"{field}: {problem}" for field, problem in errors.items()]
        elif isinstance(errors, list):
            parts += [str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in errors]
        if parts:
            return f"{fallback}: {' - '.join(parts)[:500]}"
    return fallback
