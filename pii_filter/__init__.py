"""pii-filter-mcp: an MCP proxy that redacts Canadian PII in both directions."""

from .redact import find_pii, redact_text, redact_value
from .server import build_proxy, load_config, main

__all__ = ["find_pii", "redact_text", "redact_value", "build_proxy", "load_config", "main"]
