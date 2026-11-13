from typing import Any

import pytest

from tests.conftest import EXAMPLES, VICTIM, rule_ids
from txray.analysis.message import analyze_message, parse_siwe
from txray.errors import InvalidInputError
from txray.models import Verdict

SIWE = (EXAMPLES / "siwe-login.txt").read_text()


def test_parse_siwe_example() -> None:
    msg = parse_siwe(SIWE)
    assert msg is not None
    assert msg.domain == "app.example.org"
    assert msg.address == VICTIM
    assert msg.statement == "Sign in to Example App."
    assert msg.fields["Chain ID"] == "1"
    assert msg.errors == []


def test_not_siwe() -> None:
    assert parse_siwe("hello world") is None


def test_siwe_matching_origin_passes(make_ctx: Any) -> None:
    report = analyze_message(
        "personal_sign", SIWE, make_ctx(origin="https://app.example.org", sender=VICTIM)
    )
    assert report.findings == []
    assert report.verdict is Verdict.PASS


def test_siwe_wrong_origin(make_ctx: Any) -> None:
    report = analyze_message(
        "personal_sign", SIWE, make_ctx(origin="https://app-example-login.net")
    )
    assert "MSG010" in rule_ids(report)


def test_siwe_other_checks(make_ctx: Any) -> None:
    text = SIWE.replace("Chain ID: 1", "Chain ID: 10").replace(
        "Expiration Time: 2030-01-01T00:00:00Z", "Expiration Time: 2020-01-01T00:00:00Z"
    )
    other = "0x0000000000000000000000000000000000000001"
    report = analyze_message(
        "personal_sign", text, make_ctx(origin="app.example.org", sender=other)
    )
    assert {"MSG011", "MSG012", "MSG013"} <= rule_ids(report)


def test_malformed_siwe(make_ctx: Any) -> None:
    text = SIWE.replace("Nonce: 32891756aZ\n", "").replace("Version: 1", "Version: 2")
    report = analyze_message("personal_sign", text, make_ctx(origin="app.example.org"))
    msg014 = next(f for f in report.findings if f.rule_id == "MSG014")
    assert "missing Nonce" in msg014.evidence["errors"]
    assert "Version must be 1" in msg014.evidence["errors"]


def test_eth_sign_raw_hash(make_ctx: Any) -> None:
    report = analyze_message("eth_sign", "0x" + "ab" * 32, make_ctx())
    assert rule_ids(report) == {"MSG001"}
    assert report.verdict is Verdict.BLOCK


def test_personal_sign_binary_hash(make_ctx: Any) -> None:
    assert rule_ids(analyze_message("personal_sign", "0x" + "ff" * 32, make_ctx())) == {"MSG002"}
    assert rule_ids(analyze_message("personal_sign", "0x" + "ff" * 5, make_ctx())) == {"MSG003"}


def test_hex_encoded_text_is_decoded(make_ctx: Any) -> None:
    report = analyze_message("personal_sign", "0x" + b"hello".hex(), make_ctx())
    assert report.decoded["text"] == "hello"
    assert report.findings == []


def test_invalid_method(make_ctx: Any) -> None:
    with pytest.raises(InvalidInputError):
        analyze_message("eth_signTransaction", "x", make_ctx())
    with pytest.raises(InvalidInputError):
        analyze_message("eth_sign", "not hex", make_ctx())


def test_text_starting_with_0x_is_treated_as_text(make_ctx: Any) -> None:
    report = analyze_message("personal_sign", "0xHello, please sign", make_ctx())
    assert report.decoded["text"] == "0xHello, please sign"
