"""pii-filter-mcp: an MCP proxy that redacts Canadian PII in both directions.

The proxy exposes the downstream server's tools, resources, and prompts
unchanged, but filters the traffic passing through:

- client -> downstream: PII is redacted from tool call arguments, resource
  URIs are passed through, and prompt arguments are redacted before
  forwarding;
- downstream -> client: PII is redacted from tool result content (text
  blocks and structured content), resource contents, and prompt messages
  before they reach the client.

Run with:  python -m pii_filter.server --config config.json
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server

from .redact import redact_text, redact_value

CONFIG_ENV_VAR = "PII_FILTER_CONFIG"


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load proxy configuration from a JSON file or environment variables."""
    path = path or os.environ.get(CONFIG_ENV_VAR)
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    transport = os.environ.get("PII_FILTER_DOWNSTREAM_TRANSPORT", "stdio")
    downstream: dict[str, Any] = {"transport": transport}
    if transport == "stdio":
        downstream["command"] = os.environ["PII_FILTER_DOWNSTREAM_COMMAND"]
        args = os.environ.get("PII_FILTER_DOWNSTREAM_ARGS", "[]")
        downstream["args"] = json.loads(args) if args.startswith("[") else args.split()
        downstream["env"] = json.loads(os.environ.get("PII_FILTER_DOWNSTREAM_ENV", "{}"))
    else:
        downstream["url"] = os.environ["PII_FILTER_DOWNSTREAM_URL"]
        downstream["headers"] = json.loads(os.environ.get("PII_FILTER_DOWNSTREAM_HEADERS", "{}"))
    return {"downstream": downstream}


@asynccontextmanager
async def downstream_session(config: dict[str, Any]) -> AsyncIterator[ClientSession]:
    """Connect to the configured downstream MCP server."""
    downstream = config["downstream"]
    transport = downstream.get("transport", "stdio")
    if transport == "stdio":
        env = {**os.environ, **downstream.get("env", {})}
        params = StdioServerParameters(
            command=downstream["command"],
            args=downstream.get("args", []),
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    elif transport == "sse":
        async with sse_client(
            downstream["url"], headers=downstream.get("headers")
        ) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    elif transport in ("streamable_http", "streamablehttp"):
        async with streamablehttp_client(
            downstream["url"], headers=downstream.get("headers")
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    else:
        raise ValueError(f"Unknown downstream transport: {transport!r}")


def _redact_tool_result(result: types.CallToolResult) -> types.CallToolResult:
    redacted = result.model_copy(deep=True)
    content: list[Any] = []
    for block in redacted.content:
        if isinstance(block, types.TextContent):
            content.append(block.model_copy(update={"text": redact_text(block.text)}))
        else:
            content.append(block)
    redacted.content = content
    if redacted.structuredContent:
        redacted.structuredContent = redact_value(redacted.structuredContent)
    return redacted


def _redact_resource_contents(
    contents: list[types.TextResourceContents | types.BlobResourceContents],
) -> list[ReadResourceContents]:
    redacted: list[ReadResourceContents] = []
    for item in contents:
        if isinstance(item, types.TextResourceContents):
            redacted.append(
                ReadResourceContents(
                    content=redact_text(item.text), mime_type=item.mimeType
                )
            )
        else:
            redacted.append(
                ReadResourceContents(
                    content=base64.b64decode(item.blob), mime_type=item.mimeType
                )
            )
    return redacted


def _redact_prompt_result(result: types.GetPromptResult) -> types.GetPromptResult:
    redacted = result.model_copy(deep=True)
    messages: list[types.PromptMessage] = []
    for message in redacted.messages:
        content = message.content
        if isinstance(content, types.TextContent):
            content = content.model_copy(update={"text": redact_text(content.text)})
        messages.append(message.model_copy(update={"content": content}))
    redacted.messages = messages
    return redacted


def build_proxy(downstream: ClientSession) -> Server:
    """Build the filtering proxy server around an open downstream session."""
    server = Server("pii-filter-mcp")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return (await downstream.list_tools()).tools

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        redacted_args = redact_value(arguments or {})
        result = await downstream.call_tool(name, redacted_args)
        return _redact_tool_result(result)

    @server.list_resources()
    async def _list_resources() -> list[types.Resource]:
        return (await downstream.list_resources()).resources

    @server.read_resource()
    async def _read_resource(uri: types.AnyUrl) -> list[ReadResourceContents]:
        result = await downstream.read_resource(uri)
        return _redact_resource_contents(list(result.contents))

    @server.list_prompts()
    async def _list_prompts() -> list[types.Prompt]:
        return (await downstream.list_prompts()).prompts

    @server.get_prompt()
    async def _get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        result = await downstream.get_prompt(name, redact_value(arguments or {}))
        return _redact_prompt_result(result)

    return server


async def run_proxy(config: dict[str, Any]) -> None:
    """Connect downstream and serve the filtering proxy over stdio."""
    async with downstream_session(config) as session:
        server = build_proxy(session)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="pii-filter-mcp: PII-redacting MCP proxy")
    parser.add_argument("--config", default=None, help="Path to JSON config file")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    asyncio.run(run_proxy(config))


if __name__ == "__main__":
    main()
