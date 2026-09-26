# pii-filter-mcp

An MCP proxy that redacts Canadian PII from traffic passing between an AI
client and a downstream MCP server, in both directions.

## What it does

The proxy sits between your MCP client and any downstream MCP server. It
exposes the downstream server's tools, resources, and prompts unchanged, so
clients see the downstream's full surface through the filter. The payloads
are filtered:

- **Client to downstream:** PII is redacted from tool call arguments and
  prompt arguments before anything is forwarded. The downstream server never
  sees the raw values.
- **Downstream to client:** PII is redacted from tool results (text content
  and structured content), resource contents, and prompt messages before
  they reach the client.

Tool, resource, and prompt listings pass through untouched, since they are
static server metadata rather than user data.

## Entity types redacted

The filter uses the Canadian recognizer pack from the
[movahedi-ca/presidio](https://github.com/movahedi-ca/presidio) fork
(vendored in `pii_filter/ca_recognizers.py` with attribution, so the proxy
stays dependency-light):

- `CA_SIN`: Canadian Social Insurance Number. `046 454 286`,
  `046-454-286`, `046454286`. Every candidate must pass the Luhn
  (Modulus 10) checksum; 9-digit strings that fail it are left alone.
- `CA_OHIP`: Ontario health card number, 10 digits plus a 2-letter version
  code. `1234567890 AB`, `1234567890AB`, `1234-567-890-AB`.
- `CA_POSTAL_CODE`: Canadian postal code with a validated forward sortation
  area. `K1A 0B1`, `k1a0b1`. US ZIP codes such as `90210` do not match.

Matches are replaced with labelled placeholders (`[REDACTED:CA_SIN]`,
`[REDACTED:CA_OHIP]`, `[REDACTED:CA_POSTAL_CODE]`).

## Setup

Install the one runtime dependency and point the proxy at a downstream
server:

```bash
pip install -r requirements.txt
```

Create a JSON config (see `config.example.json`):

```json
{
  "downstream": {
    "transport": "stdio",
    "command": "python",
    "args": ["-m", "my_downstream_server"],
    "env": {}
  }
}
```

For a server over HTTP instead of stdio:

```json
{
  "downstream": {
    "transport": "streamable_http",
    "url": "http://localhost:8000/mcp",
    "headers": {}
  }
}
```

(`transport: "sse"` with a `url` is also supported.)

Run the proxy (it serves over stdio, like any MCP server):

```bash
python -m pii_filter.server --config config.json
```

Or set `PII_FILTER_CONFIG` to the config path instead of `--config`. Without
a config file, the downstream can be described with environment variables:
`PII_FILTER_DOWNSTREAM_TRANSPORT`, `PII_FILTER_DOWNSTREAM_COMMAND`,
`PII_FILTER_DOWNSTREAM_ARGS` (JSON array or space-separated),
`PII_FILTER_DOWNSTREAM_ENV` (JSON), `PII_FILTER_DOWNSTREAM_URL`,
`PII_FILTER_DOWNSTREAM_HEADERS` (JSON).

Then add it to your MCP client configuration as a stdio server, for
example:

```json
{
  "mcpServers": {
    "filtered-downstream": {
      "command": "python",
      "args": ["-m", "pii_filter.server", "--config", "/path/to/config.json"]
    }
  }
}
```

## Relationship to the movahedi.ca MCP server

This proxy complements the movahedi.ca MCP server but is a separate
project with a separate purpose: the movahedi.ca MCP server exposes
privacy APIs and tools to AI clients, while `pii-filter-mcp` is generic
middleware that wraps *any* downstream MCP server and strips Canadian PII
from the traffic in both directions. The two are independent and neither
depends on the other.

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

`tests/test_redact.py` covers the redaction logic (valid formats, Luhn
failures, lookalikes such as US ZIP codes). `tests/test_proxy.py` runs a
mock downstream MCP server through the real proxy over in-memory MCP
connections and proves redaction happens in both directions.
