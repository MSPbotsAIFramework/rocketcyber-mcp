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
"""Shared argument types, filter helpers and the error-handling wrapper."""

import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, get_args

from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped, error_envelope
from ..api_client import RocketCyberClient, RocketCyberError

logger = logging.getLogger("rocketcyber_mcp.tools")

ClientFactory = Callable[[], RocketCyberClient | None]

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)

NOT_CONFIGURED = error_envelope(
    "not_configured", "RocketCyber credentials are missing for this request (X-Rocketcyber-Api-Key).", False
)

DEFAULT_PAGE_SIZE = 25

AccountId = Annotated[
    int | None,
    Field(description="Only this customer account (see rocketcyber_get_account). Default: every account the key can see."),
]
Page = Annotated[int | None, Field(description="Page number, from 1.", ge=1)]
PageSize = Annotated[int | None, Field(description=f"Results per page (default {DEFAULT_PAGE_SIZE}, max 200).", ge=1, le=200)]
Offset = Annotated[
    int | None,
    Field(description="Record position to start from (0-based, overrides page); pass next_offset from the previous result.", ge=0),
]
Sort = Annotated[str | None, Field(description="field or field:asc / field:desc, e.g. createdAt:desc.")]
Dates = Annotated[
    str | None,
    Field(description="Date range start|end in ISO format; either side may be empty, e.g. 2026-01-01|2026-01-31 or 2026-01-01|."),
]

_SORT = re.compile(r"^[A-Za-z_][\w.]*(:(asc|desc))?$", re.IGNORECASE)


def compact(values: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v is not None and v != ""}


def sort_param(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if not _SORT.match(text):
        raise ValueError(f"sort must look like field, field:asc or field:desc (got {value!r}).")
    field, _, direction = text.partition(":")
    return f"{field}:{direction.lower()}" if direction else field


def date_range(value: str | None, name: str = "dates") -> str | None:
    """Normalise a start|end range; a single date means "from that date on"."""
    if value is None or not value.strip():
        return None
    text = value.strip()
    if "|" not in text:
        return f"{text}|"
    start, _, end = text.partition("|")
    if "|" in end:
        raise ValueError(f"{name} must be start|end with a single '|' (got {value!r}).")
    if not start.strip() and not end.strip():
        raise ValueError(f"{name} needs a start or an end date (got {value!r}).")
    return f"{start.strip()}|{end.strip()}"


def page_params(page: int | None, page_size: int | None, sort: str | None) -> dict[str, Any]:
    return compact({"page": page, "pageSize": page_size or DEFAULT_PAGE_SIZE, "sort": sort_param(sort)})


def locate(offset: int | None, page: int | None, page_size: int | None) -> tuple[int | None, int, int]:
    """(page to request, page size, start) for a read from record ``start``.

    RocketCyber pages by number only, so a position is reached by asking for the page that
    holds it (same page size) and skipping the records before it. Without ``offset`` the page
    to request is ``page`` unchanged (None when not given), so such calls send the same request.
    """
    size = page_size or DEFAULT_PAGE_SIZE
    if offset is None:
        return page, size, ((page or 1) - 1) * size
    return offset // size + 1, size, offset


def page_window(payload: Any, page: int | None, size: int, start: int) -> Any:
    """The fetched page from record ``start`` on (``page`` is the page number that was requested)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return payload
    data = payload["data"][max(start - ((page or 1) - 1) * size, 0) :]
    shaped = {**payload, "data": data}
    if "dataCount" in payload:
        shaped["dataCount"] = len(data)
    return shaped


def window_size(payload: Any) -> int:
    """Number of records in a page window (before any local filter)."""
    return len(payload["data"]) if isinstance(payload, dict) and isinstance(payload.get("data"), list) else 0


def page_summary(payload: Any, start: int | None = None, seen: int = 0, exact: bool = True) -> Any:
    """Add a short paging line to the API's {totalCount, currentPage, totalPages, data} pages.

    With ``start`` (the position of the first record of the window) the result also carries
    ``offset`` and ``next_offset`` (= start + ``seen``, the records of the window before any
    local filter), which continues right after the window also when a result is cut to fit the
    size limit (a page number cannot: the rest of a cut page is on no other page). ``exact`` is
    False when a local filter removed records: positions of the returned records are then not
    consecutive, so a cut result asks for a smaller page size from the same offset instead.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return payload
    current, pages = payload.get("currentPage") or 1, payload.get("totalPages") or 1
    summary = {
        "count": len(payload["data"]),
        "total": payload.get("totalCount"),
        "page": current,
        "total_pages": pages,
        "has_more": current < pages,
    }
    if current < pages:
        summary["next_page"] = current + 1
    if start is None:
        return {"summary": summary, **payload}
    paging: dict[str, Any] = {"offset": start}
    if current < pages:
        paging["next_offset"] = start + seen
    if exact:
        paging["_resume"] = {"key": "next_offset", "start": start}
    return {"summary": summary, **paging, **payload}


def field_value(item: Any, paths: tuple[str, ...]) -> Any:
    """First non-empty value found at one of the dotted ``paths`` of a response item."""
    for path in paths:
        value: Any = item
        for key in path.split("."):
            value = value.get(key) if isinstance(value, dict) else None
        if value not in (None, ""):
            return value
    return None


def local_filter(payload: Any, label: str, keep: Callable[[dict], bool], paths: tuple[str, ...] | None = None) -> Any:
    """Filter the items of one returned page (the API has no such filter); paging stays the API's.

    With ``paths``, the filter is skipped (and the note says so) when no item on the page
    carries any of those fields, so an unexpected response shape never empties the result.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return payload
    items = payload["data"]
    if paths and not any(isinstance(item, dict) and field_value(item, paths) is not None for item in items):
        note = f"Filter {label} not applied: the items on this page carry no such field."
        previous = payload.get("note")
        return {**payload, "note": f"{previous} {note}" if previous else note}
    kept = [item for item in items if isinstance(item, dict) and keep(item)]
    note = (
        f"Filtered locally by {label}: {len(kept)} of {len(items)} items on this page match. "
        "Other pages are not searched; page through them for more."
    )
    previous = payload.get("note")
    return {**payload, "data": kept, "dataCount": len(kept), "note": f"{previous} {note}" if previous else note}


def matches_exact(item: dict, paths: tuple[str, ...], wanted: str) -> bool:
    value = field_value(item, paths)
    return value is not None and str(value).strip().lower() == wanted.strip().lower()


def matches_substring(item: dict, paths: tuple[str, ...], wanted: str) -> bool:
    value = field_value(item, paths)
    return value is not None and wanted.strip().lower() in str(value).lower()


def enum_value(value: Any, choices: Any) -> Any:
    """Canonical spelling of a case-insensitive match in ``choices`` (a Literal type).

    Any other value passes through unchanged, so the API decides (older callers sent free text).
    """
    if not isinstance(value, str):
        return value
    wanted = value.strip().lower()
    return next((c for c in get_args(choices) if isinstance(c, str) and c.lower() == wanted), value)


async def run_tool(
    name: str,
    client_factory: ClientFactory,
    action: Callable[[RocketCyberClient], Awaitable[Any]],
) -> str:
    """Resolve the caller's client, run ``action``, and always return a string.

    Errors never escape as exceptions: they become the standard error envelope.
    """
    client = client_factory()
    if client is None:
        return NOT_CONFIGURED
    if client.header_error:
        return error_envelope("invalid_argument", client.header_error, False)
    started = time.monotonic()
    try:
        result = await action(client)
    except RocketCyberError as e:
        logger.info("tool=%s outcome=error status=%s ms=%d", name, e.status_code, _ms(started))
        return e.to_envelope()
    except ValueError as e:
        logger.info("tool=%s outcome=invalid_argument ms=%d", name, _ms(started))
        return error_envelope("invalid_argument", str(e), False)
    except Exception as e:  # noqa: BLE001 - tools must never raise
        logger.warning("tool=%s outcome=unexpected error=%s ms=%d", name, type(e).__name__, _ms(started))
        return error_envelope("upstream_error", f"Unexpected error: {type(e).__name__}", True)
    logger.info("tool=%s outcome=ok ms=%d", name, _ms(started))
    if result is None:
        result = {"result": None, "note": "RocketCyber returned an empty response."}
    return result if isinstance(result, str) else dump_json_capped(result)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
