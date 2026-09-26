"""End-to-end proxy tests against a mock downstream MCP server.

The mock downstream exposes tools, a resource, and a prompt. Tests drive
the proxy through a real MCP client session and assert redaction happens
in both directions:

- client -> downstream: PII in tool call arguments is redacted before the
  downstream server ever sees it (proven by the echo tool reflecting the
  redacted arguments back);
- downstream -> client: PII in tool results, resource contents, and prompt
  messages is redacted before it reaches the client.
"""

import asyncio

from mcp import types
from mcp.server import Server
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import AnyUrl

from pii_filter.server import build_proxy

SIN = "046 454 286"
OHIP = "1234567890 AB"
POSTAL = "K1A 0B1"


def build_mock_downstream() -> Server:
    server = Server("mock-downstream")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="echo",
                description="Echoes the input text back",
                inputSchema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            ),
            types.Tool(
                name="leak",
                description="Returns canned text containing PII",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="structured",
                description="Returns structured content containing PII",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> types.CallToolResult:
        if name == "echo":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"you said: {arguments['text']}")]
            )
        if name == "leak":
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"on file: SIN {SIN}, OHIP {OHIP}, postal {POSTAL}",
                    )
                ]
            )
        if name == "structured":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="profile stored")],
                structuredContent={"sin": SIN, "notes": ["clean", OHIP]},
            )
        raise ValueError(f"unknown tool: {name}")

    @server.list_resources()
    async def _list_resources() -> list[types.Resource]:
        return [
            types.Resource(
                uri=AnyUrl("mock://profile"),
                name="profile",
                description="A profile containing PII",
            )
        ]

    @server.read_resource()
    async def _read_resource(uri: AnyUrl):
        return f"profile of holder {SIN} living at {POSTAL}"

    @server.list_prompts()
    async def _list_prompts() -> list[types.Prompt]:
        return [
            types.Prompt(
                name="greet",
                description="Greet someone",
                arguments=[types.PromptArgument(name="name", required=True)],
            )
        ]

    @server.get_prompt()
    async def _get_prompt(name: str, arguments: dict | None) -> types.GetPromptResult:
        return types.GetPromptResult(
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=f"hello {arguments['name']}, your card {OHIP} is ready",
                    ),
                )
            ]
        )

    return server


def run(coro):
    return asyncio.run(coro)


async def _proxy_client():
    """Yield (client, downstream_session_ctx) wired proxy over memory streams."""
    mock = build_mock_downstream()
    downstream_ctx = create_connected_server_and_client_session(mock)
    downstream = await downstream_ctx.__aenter__()
    proxy = build_proxy(downstream)
    proxy_ctx = create_connected_server_and_client_session(proxy)
    client = await proxy_ctx.__aenter__()
    return client, downstream_ctx, proxy_ctx


def test_tools_list_mirrors_downstream():
    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            result = await client.list_tools()
            assert {t.name for t in result.tools} == {"echo", "leak", "structured"}
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())


def test_tool_arguments_redacted_client_to_downstream():
    """The echo tool reflects what the downstream received: redacted args."""

    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            await client.list_tools()  # populate schema caches
            result = await client.call_tool("echo", {"text": f"my SIN is {SIN}"})
            text = result.content[0].text
            assert SIN not in text
            assert text == "you said: my SIN is [REDACTED:CA_SIN]"
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())


def test_tool_results_redacted_downstream_to_client():
    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            await client.list_tools()
            result = await client.call_tool("leak", {})
            text = result.content[0].text
            assert SIN not in text
            assert OHIP not in text
            assert POSTAL not in text
            assert "[REDACTED:CA_SIN]" in text
            assert "[REDACTED:CA_OHIP]" in text
            assert "[REDACTED:CA_POSTAL_CODE]" in text
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())


def test_structured_content_redacted():
    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            await client.list_tools()
            result = await client.call_tool("structured", {})
            assert result.structuredContent == {
                "sin": "[REDACTED:CA_SIN]",
                "notes": ["clean", "[REDACTED:CA_OHIP]"],
            }
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())


def test_resource_contents_redacted():
    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            resources = await client.list_resources()
            assert [str(r.uri) for r in resources.resources] == ["mock://profile"]
            result = await client.read_resource(AnyUrl("mock://profile"))
            text = result.contents[0].text
            assert SIN not in text
            assert POSTAL not in text
            assert "[REDACTED:CA_SIN]" in text
            assert "[REDACTED:CA_POSTAL_CODE]" in text
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())


def test_prompt_messages_and_arguments_redacted():
    async def go():
        client, dctx, pctx = await _proxy_client()
        try:
            prompts = await client.list_prompts()
            assert [p.name for p in prompts.prompts] == ["greet"]
            # prompt argument containing a SIN is redacted before forwarding
            result = await client.get_prompt("greet", {"name": SIN})
            text = result.messages[0].content.text
            assert SIN not in text
            assert OHIP not in text
            assert "[REDACTED:CA_SIN]" in text
            assert "[REDACTED:CA_OHIP]" in text
        finally:
            await pctx.__aexit__(None, None, None)
            await dctx.__aexit__(None, None, None)

    run(go())
