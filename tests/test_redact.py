"""Unit tests for the Canadian PII redaction logic."""

from pii_filter.redact import find_pii, redact_text, redact_value


def test_sin_all_format_variants_redacted():
    assert redact_text("046 454 286") == "[REDACTED:CA_SIN]"
    assert redact_text("046-454-286") == "[REDACTED:CA_SIN]"
    assert redact_text("046454286") == "[REDACTED:CA_SIN]"
    # other Luhn-valid SINs from the Presidio test suite
    assert redact_text("130 692 544") == "[REDACTED:CA_SIN]"
    assert redact_text("130692544") == "[REDACTED:CA_SIN]"


def test_sin_luhn_failures_not_redacted():
    assert redact_text("130 692 545") == "130 692 545"
    assert redact_text("130692545") == "130692545"
    assert redact_text("435-418-166") == "435-418-166"
    assert redact_text("111 111 111") == "111 111 111"
    assert redact_text("999 999 999") == "999 999 999"


def test_sin_mismatched_delimiters_not_redacted():
    assert redact_text("046-454 286") == "046-454 286"
    assert redact_text("046 454-286") == "046 454-286"


def test_ohip_variants_redacted():
    assert redact_text("1234567890 AB") == "[REDACTED:CA_OHIP]"
    assert redact_text("1234567890AB") == "[REDACTED:CA_OHIP]"
    assert redact_text("1234567890-AB") == "[REDACTED:CA_OHIP]"
    assert redact_text("1234-567-890-AB") == "[REDACTED:CA_OHIP]"
    assert redact_text("1234-567-890-ab") == "[REDACTED:CA_OHIP]"


def test_ohip_lookalikes_not_redacted():
    assert redact_text("1234567890") == "1234567890"  # no version code
    assert redact_text("123456789") == "123456789"  # too short
    assert redact_text("123456789012 AB") == "123456789012 AB"  # too long
    assert redact_text("1234-567-89-AB") == "1234-567-89-AB"  # bad grouping
    assert redact_text("call 1234567890 tomorrow") == "call 1234567890 tomorrow"


def test_postal_code_variants_redacted():
    assert redact_text("K1A 0B1") == "[REDACTED:CA_POSTAL_CODE]"
    assert redact_text("K1A0B1") == "[REDACTED:CA_POSTAL_CODE]"
    assert redact_text("k1a 0b1") == "[REDACTED:CA_POSTAL_CODE]"
    assert redact_text("M5V 3A8") == "[REDACTED:CA_POSTAL_CODE]"


def test_postal_code_invalid_not_redacted():
    assert redact_text("90210") == "90210"  # US ZIP
    assert redact_text("D1A 1A1") == "D1A 1A1"  # invalid FSA letter
    assert redact_text("W1A 1A1") == "W1A 1A1"  # W never starts a code
    assert redact_text("Z1A 1A1") == "Z1A 1A1"  # Z never starts a code
    assert redact_text("1A1 1A1") == "1A1 1A1"  # starts with digit


def test_multiple_entities_in_one_text():
    text = "SIN 046 454 286, OHIP 1234567890 AB, postal K1A 0B1"
    assert redact_text(text) == (
        "SIN [REDACTED:CA_SIN], OHIP [REDACTED:CA_OHIP], "
        "postal [REDACTED:CA_POSTAL_CODE]"
    )


def test_no_double_redaction_on_overlap():
    # grouped SIN must not also match the plain 9-digit pattern inside it
    spans = find_pii("046 454 286")
    assert spans == [(0, 11, "CA_SIN")]


def test_find_pii_span_positions():
    assert find_pii("my SIN is 046-454-286 ok") == [(10, 21, "CA_SIN")]
    assert find_pii("nothing here") == []


def test_redact_value_recurses_through_payloads():
    payload = {
        "name": "Jane",
        "sin": "046 454 286",
        "nested": {"ohip": "1234567890 AB", "tags": ["K1A 0B1", "clean"]},
        "count": 3,
    }
    assert redact_value(payload) == {
        "name": "Jane",
        "sin": "[REDACTED:CA_SIN]",
        "nested": {
            "ohip": "[REDACTED:CA_OHIP]",
            "tags": ["[REDACTED:CA_POSTAL_CODE]", "clean"],
        },
        "count": 3,
    }


def test_redact_value_leaves_non_strings_alone():
    assert redact_value(None) is None
    assert redact_value(42) == 42
    assert redact_value(["a", 1]) == ["a", 1]
