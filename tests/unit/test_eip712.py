import copy
from typing import Any

import pytest

from txray.eip712 import (
    domain_separator,
    encode_type,
    hash_struct,
    parse_typed_data,
    signing_digest,
)
from txray.errors import TypedDataError

# Example from the EIP-712 specification, with its published hashes.
MAIL: dict[str, Any] = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}


def test_spec_vectors() -> None:
    td = parse_typed_data(MAIL)
    assert encode_type("Mail", td.types) == (
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    )
    assert domain_separator(td).hex() == (
        "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    )
    assert hash_struct("Mail", td.message, td.types).hex() == (
        "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    )
    assert signing_digest(td).hex() == (
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    )


def test_domain_type_inferred_when_missing() -> None:
    raw = copy.deepcopy(MAIL)
    del raw["types"]["EIP712Domain"]
    assert signing_digest(parse_typed_data(raw)) == signing_digest(parse_typed_data(MAIL))


def test_arrays_of_structs_hash() -> None:
    raw = {
        "types": {
            "Batch": [{"name": "items", "type": "Item[]"}],
            "Item": [{"name": "id", "type": "uint256"}],
        },
        "primaryType": "Batch",
        "domain": {"chainId": "0x1"},
        "message": {"items": [{"id": "1"}, {"id": 2}]},
    }
    td = parse_typed_data(raw)
    assert len(signing_digest(td)) == 32


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.pop("primaryType"), "missing top-level"),
        (lambda d: d["types"]["Mail"].append({"name": "x", "type": "Unknown"}), "unknown type"),
        (lambda d: d["message"].pop("contents"), "missing value"),
        (lambda d: d["message"].update(extra=1), "not declared"),
        (lambda d: d["message"]["from"].update(wallet="0x1234"), "invalid address"),
        (lambda d: d["domain"].update(chainId=-1), "chainId"),
        (lambda d: d["domain"].update(foo="bar"), "not declared in EIP712Domain"),
        (lambda d: d["types"]["Mail"].append({"name": "to", "type": "string"}), "duplicate"),
    ],
)
def test_invalid_payloads(mutate: Any, message: str) -> None:
    raw = copy.deepcopy(MAIL)
    mutate(raw)
    with pytest.raises(TypedDataError, match=message):
        td = parse_typed_data(raw)
        signing_digest(td)


def test_integer_range_enforced() -> None:
    raw = {
        "types": {"T": [{"name": "v", "type": "uint8"}]},
        "primaryType": "T",
        "domain": {},
        "message": {"v": 256},
    }
    with pytest.raises(TypedDataError, match="out of range"):
        signing_digest(parse_typed_data(raw))


def test_json_string_input() -> None:
    import json

    assert parse_typed_data(json.dumps(MAIL)).primary_type == "Mail"
    with pytest.raises(TypedDataError, match="JSON"):
        parse_typed_data("{not json")
