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
"""The connection check and the account hierarchy."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..api_client import RocketCyberClient
from ._common import READ_ONLY, AccountId, ClientFactory, compact, run_tool


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_test_connection() -> str:
        """Check the RocketCyber connection: the API key works in the selected region."""

        async def action(client: RocketCyberClient) -> dict:
            await client.get("account")
            return {"connected": True, "base_url": client.base_url}

        return await run_tool("rocketcyber_test_connection", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def rocketcyber_get_account(accountId: AccountId = None) -> str:
        """Get account details: name, type, status, address and child customer account ids.

        Without accountId it covers every account the API key can see; the customers lists give
        the ids the other tools take as accountId.
        """

        async def action(client: RocketCyberClient) -> Any:
            return await client.get("account", compact({"accountId": accountId}))

        return await run_tool("rocketcyber_get_account", client_factory, action)
