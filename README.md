# RocketCyber MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [RocketCyber](https://www.rocketcyber.com)
customer API (v3). RocketCyber is a managed SOC for MSPs: agents on endpoints and firewall log
collectors feed detection apps, and threats the SOC confirms become incidents. This server lets an
AI agent read incidents, app events and event summaries, the agent and firewall inventory, the
detection apps, the account hierarchy, and Microsoft Defender and Microsoft 365 status. Every tool is
read-only.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: the API key arrives on every request as an HTTP header and is
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Rocketcyber-Api-Key` | Yes | string | none | - | RocketCyber customer API access token | `your-api-key` |
| `X-Rocketcyber-Region` | No | string | `us` | `us`, `eu` | Data region of the RocketCyber account | `us` |

Where to get it: in the RocketCyber console, an administrator copies the customer API access
token from the provider account's settings (the API reference links to the step-by-step help
article). The token reads every customer account under that provider account.

How the key is sent to RocketCyber: as `Authorization: Bearer <token>` on every call to
`https://api-us.rocketcyber.com/v3/...` (region `us`) or `https://api-eu.rocketcyber.com/v3/...`
(region `eu`).

A request to `/mcp` without the key gets HTTP 401. A region other than `us` / `eu` does not block
the request (tools/list still works); every tool call then returns an `invalid_argument` error
naming the allowed regions.

## Tools

All tools return a JSON string. Paged lists keep the API's `{totalCount, currentPage, totalPages,
dataCount, data}` and add `summary {count, total, page, total_pages, has_more, next_page}`.
`accountId` scopes a tool to one customer account; without it the tool covers every account the
token can see. `dates` filters take `start|end` (ISO dates, either side may be empty; a single date
means "from that date on"). `sort` takes `field`, `field:asc` or `field:desc`. `pageSize` defaults
to 25 (the API's own default is 1000), max 200.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `rocketcyber_test_connection` | Check the token works in the selected region | - |
| `rocketcyber_get_account` | Account details and child customer account ids | accountId |
| `rocketcyber_list_incidents` | Confirmed incidents, newest first; description / remediation trimmed to ~300 characters unless `verbose` | page, pageSize, sort, accountId, status, dates (created), title (`*` wildcard), severity (local), verbose |
| `rocketcyber_list_events` | Events (detections) of one detection app; `appId` is needed (`invalid_argument` without it) | appId, page, pageSize, sort, accountId, severity (`malicious` / `suspicious` / `informational`), dates, deviceId, details (`path:value`), eventType (local), hostname (local) |
| `rocketcyber_get_event_summary` | Event counts per detection app | accountId, dates |
| `rocketcyber_list_agents` | Endpoint agents with OS, IP, version and online state | page, pageSize, sort, accountId, connectivity (`online` / `offline`), hostname (`*` wildcard), platform (OS, `*` wildcard), dates (installed) |
| `rocketcyber_list_firewalls` | Firewalls sending logs, with log counters | page, pageSize, sort, accountId, vendor, ipAddress, macAddress, connectivity (local), hostname (local) |
| `rocketcyber_list_apps` | Detection apps (ids and descriptions) | page, pageSize (local paging), sort (`id` / `name`, optional `:desc`), accountId, status (`active` / `inactive`), name (contains) |
| `rocketcyber_get_defender` | Microsoft Defender status | accountId |
| `rocketcyber_get_office` | Microsoft 365 security status (Secure Score trend) | accountId |

Parameters marked "(local)" have no RocketCyber API filter: they filter the page the API returned
(case-insensitive; exact match for `severity`, `eventType` and `connectivity`, substring for
`hostname`) and add a `note`. Paging (`summary`, `has_more`) still describes the API's pages, so
use `page` to look further.

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "RocketCyber returned HTTP 401 for account: Authentication failed. Please provide valid credentials.", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Calls are retried with backoff on 429 (honouring `Retry-After`),
5xx and network errors.

## Run locally

```bash
uv sync
uv run python -m rocketcyber_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t rocketcyber-mcp:dev .
docker run --rm -p 8080:8080 rocketcyber-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). The token is never read from the
environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Rocketcyber-Api-Key: your-api-key" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# open incidents created this year
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Rocketcyber-Api-Key: your-api-key" \
  -H "X-Rocketcyber-Region: us" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rocketcyber_list_incidents","arguments":{"status":"open","dates":"2026-01-01|"}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (10).** Kept as is because the tool names and camelCase parameter names are an
  existing contract.
- **API contract.** Requests follow RocketCyber's published customer API reference
  (`https://api-doc.rocketcyber.com`, v3). Older versions passed some filters through under names
  the API does not have; they now map to the documented query parameters:
  agents `platform` -> `os`, agents `dates` -> `created`, incidents `dates` -> `createdAt`, events
  `severity` -> `verdict`, firewalls `vendor` -> `type`, apps `sort` -> `sort` + `order`.
- **Parameters with no API filter** are kept for compatibility and applied locally to the
  returned page: incidents `severity` (a `severity` field, else `<severity> Severity` in the
  title); events `eventType` (`valueType`) and `hostname` (`hostname` / `details.hostname`; prefer
  `deviceId` or `details`); firewalls `connectivity` and `hostname`. Apps `page` and `pageSize`
  slice the app list locally (the apps endpoint is not paged) and return `has_more`; apps `name`
  filters the returned list locally.
- **`appId` on events** is optional in the schema for compatibility with earlier versions, but the
  API needs it: a call without it returns `invalid_argument` pointing to `rocketcyber_list_apps`.
- **Contract test.** `tests/contract_baseline.json` holds the deployed and upstream tool schemas;
  `tests/test_contract.py` checks every tool still exists, accepts every parameter of both and
  requires nothing the deployed version did not.
- **Event summary.** `dates` is passed through as in earlier versions; the API reference lists
  only `accountId` for this endpoint.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
