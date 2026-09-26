"""Canadian PII detection patterns.

Vendored from the movahedi-ca/presidio fork of Microsoft Presidio, with
attribution:

    Source: https://github.com/movahedi-ca/presidio
    Path:   presidio-analyzer/presidio_analyzer/predefined_recognizers/
            country_specific/canada/

The regexes and the SIN Luhn check below mirror that recognizer pack
exactly (same patterns, same case-insensitive matching, same Luhn
validation), so this proxy redacts the same values the Presidio
recognizers detect. They are re-implemented here with only the standard
library so the proxy stays dependency-light instead of pulling in the
full Presidio analyzer stack.
"""

from __future__ import annotations

import re

_FLAGS = re.IGNORECASE  # Presidio PatternRecognizer matches case-insensitively

# (entity type, regexes in priority order, validator or None)
_PATTERNS: list[tuple[str, list[str], object]] = [
    (
        "CA_SIN",
        [
            r"\b\d{3}([- ])\d{3}\1\d{3}\b",  # grouped, consistent separator
            r"\b\d{9}\b",  # plain 9 digits
        ],
        "luhn",
    ),
    (
        "CA_OHIP",
        [
            r"\b\d{4}-\d{3}-\d{3}-[A-Z]{2}\b",  # grouped 4-3-3 + version code
            r"\b\d{10}[ -]?[A-Z]{2}\b",  # 10 digits + 2-letter version code
        ],
        None,
    ),
    (
        "CA_POSTAL_CODE",
        [
            # canonical spaced form, validated forward sortation area
            r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z] \d[ABCEGHJ-NPRSTV-Z]\d\b",
            # no-space form
            r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d\b",
        ],
        None,
    ),
]

_COMPILED: list[tuple[str, list[re.Pattern], object]] = [
    (entity, [re.compile(p, _FLAGS) for p in patterns], validator)
    for entity, patterns, validator in _PATTERNS
]


def luhn_valid(digits: str) -> bool:
    """Validate a digit string with the Luhn (Modulus 10) checksum."""
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_pii(text: str) -> list[tuple[int, int, str]]:
    """Find Canadian PII spans in text.

    Returns a list of (start, end, entity_type) tuples, sorted by start
    position, with overlapping matches resolved in favour of the longest
    span. Mirrors what the Presidio CA recognizers detect.
    """
    candidates: list[tuple[int, int, str]] = []
    for entity, regexes, validator in _COMPILED:
        for rx in regexes:
            for match in rx.finditer(text):
                if validator == "luhn":
                    digits = "".join(c for c in match.group() if c.isdigit())
                    if not luhn_valid(digits):
                        continue
                candidates.append((match.start(), match.end(), entity))
    # longest span wins on overlap; earlier start wins ties
    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))
    accepted: list[tuple[int, int, str]] = []
    for start, end, entity in candidates:
        if all(end <= a_start or start >= a_end for a_start, a_end, _ in accepted):
            accepted.append((start, end, entity))
    accepted.sort(key=lambda c: c[0])
    return accepted
