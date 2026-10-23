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

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

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
They also take `offset` (record position, overriding `page`) and return `offset` / `next_offset`:
when a page is too large for the response size limit and is cut, `next_offset` continues right
after the last record returned, which `page` cannot (the rest of a cut page is on no other page).
With a local filter (below) a cut page gives `retry_page_size` instead: call again with that
`pageSize` and the same `offset`.
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
