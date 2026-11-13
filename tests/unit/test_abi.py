import pytest

from txray.abi import REGISTRY, decode, encode, parse_signature, parse_type
from txray.errors import AbiDecodingError

ADDR = "0x" + "11" * 20


@pytest.mark.parametrize(
    "text",
    [
        "uint256",
        "int8",
        "address",
        "bytes32",
        "bytes",
        "string",
        "uint256[]",
        "(address,bytes)[]",
        "(uint8,(address,bool)[2])[]",
    ],
)
def test_type_roundtrip_canonical(text: str) -> None:
    assert parse_type(text).canonical() == text


def test_uint_alias_is_normalized() -> None:
    assert parse_type("uint").canonical() == "uint256"


@pytest.mark.parametrize("bad", ["uint7", "uint264", "bytes33", "fixed128x18", "(address", "x[0]"])
def test_invalid_types(bad: str) -> None:
    with pytest.raises(AbiDecodingError):
        parse_type(bad)


def test_signature_parsing() -> None:
    sig = parse_signature("aggregate3((address,bool,bytes)[])")
    assert sig.name == "aggregate3"
    assert sig.canonical == "aggregate3((address,bool,bytes)[])"


@pytest.mark.parametrize(
    ("types", "values"),
    [
        (["address", "uint256"], [ADDR, 2**256 - 1]),
        (["bytes", "string"], [b"\x01\x02\x03", "héllo"]),
        (["uint256[]", "bool"], [[1, 2, 3], True]),
        (["(address,bytes)[]"], [[(ADDR, b"abc"), (ADDR, b"")]]),
        (["int24", "bytes4"], [-5, b"\xde\xad\xbe\xef"]),
        (["(uint256,uint256)[2]", "bytes[]"], [[(1, 2), (3, 4)], [b"x", b"y" * 40]]),
    ],
)
def test_encode_decode_roundtrip(types: list[str], values: list[object]) -> None:
    parsed = [parse_type(t) for t in types]
    decoded = decode(parsed, encode(parsed, values))
    normalized = [v.lower() if isinstance(v, str) and v.startswith("0x") else v for v in decoded]
    if types == ["(address,bytes)[]"]:
        normalized = [[(a.lower(), b) for a, b in decoded[0]]]
    assert normalized == values


def test_known_vector_transfer() -> None:
    fn = REGISTRY.by_name("transfer(address,uint256)")
    data = bytes.fromhex(
        "000000000000000000000000ab5801a7d398351b8be11c439e05c5b3259aec9b"
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
    )
    to, amount = decode(fn.signature.inputs, data)
    assert to == "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
    assert amount == 10**18


class TestHostileInput:
    def test_truncated(self) -> None:
        with pytest.raises(AbiDecodingError, match="too short"):
            decode([parse_type("uint256")], b"\x00" * 31)

    def test_dirty_address_bits(self) -> None:
        with pytest.raises(AbiDecodingError, match="dirty"):
            decode([parse_type("address")], b"\x01" + b"\x00" * 31)

    def test_bool_out_of_range(self) -> None:
        with pytest.raises(AbiDecodingError):
            decode([parse_type("bool")], (2).to_bytes(32, "big"))

    def test_offset_out_of_bounds(self) -> None:
        with pytest.raises(AbiDecodingError, match="out of bounds"):
            decode([parse_type("bytes")], (10**6).to_bytes(32, "big"))

    def test_huge_array_length_does_not_allocate(self) -> None:
        payload = (32).to_bytes(32, "big") + (2**255).to_bytes(32, "big")
        with pytest.raises(AbiDecodingError, match="exceeds"):
            decode([parse_type("uint256[]")], payload)

    def test_string_length_beyond_data(self) -> None:
        payload = (32).to_bytes(32, "big") + (500).to_bytes(32, "big") + b"a" * 32
        with pytest.raises(AbiDecodingError):
            decode([parse_type("string")], payload)

    def test_invalid_utf8(self) -> None:
        payload = (32).to_bytes(32, "big") + (1).to_bytes(32, "big") + b"\xff" + b"\0" * 31
        with pytest.raises(AbiDecodingError, match="UTF-8"):
            decode([parse_type("string")], payload)

    def test_small_uint_dirty_bits(self) -> None:
        with pytest.raises(AbiDecodingError):
            decode([parse_type("uint8")], (256).to_bytes(32, "big"))


def test_registry_selectors_are_derived_from_signatures() -> None:
    fn = REGISTRY.by_name("setApprovalForAll(address,bool)")
    assert fn.selector.hex() == "a22cb465"
    assert "approval" in fn.tags
    # Permit2's approve shares the name but not the selector with ERC-20 approve.
    assert REGISTRY.by_name("approve(address,address,uint160,uint48)").selector.hex() == "87517c45"
