"""Redaction helpers: apply the Canadian recognizer pack to text and payloads."""

from __future__ import annotations

from typing import Any

from .ca_recognizers import find_pii

REDACTED_TEMPLATE = "[REDACTED:{entity}]"


def redact_text(text: str) -> str:
    """Replace every detected Canadian PII span with a labelled placeholder."""
    spans = find_pii(text)
    if not spans:
        return text
    parts: list[str] = []
    last = 0
    for start, end, entity in spans:
        parts.append(text[last:start])
        parts.append(REDACTED_TEMPLATE.format(entity=entity))
        last = end
    parts.append(text[last:])
    return "".join(parts)


def redact_value(value: Any) -> Any:
    """Recursively redact PII in JSON-like payloads (dicts, lists, strings).

    Non-string scalars pass through untouched; other types are returned
    as-is.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        redacted = [redact_value(item) for item in value]
        return type(value)(redacted)
    return value
