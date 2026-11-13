import pytest

from txray.errors import InvalidInputError
from txray.hexutil import (
    int_from_hex_or_dec,
    keccak256,
    normalize_address,
    parse_hex,
    selector,
    to_checksum_address,
)


def test_keccak_empty_string_vector() -> None:
    assert (
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_selector_of_transfer() -> None:
    assert selector("transfer(address,uint256)").hex() == "a9059cbb"


@pytest.mark.parametrize(
    "address",
    [
        # EIP-55 reference vectors
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ],
)
def test_eip55_vectors(address: str) -> None:
    assert to_checksum_address(address.lower()) == address
    assert normalize_address(address) == address


def test_bad_checksum_is_rejected() -> None:
    with pytest.raises(InvalidInputError, match="checksum"):
        normalize_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")


def test_lowercase_address_accepted_and_checksummed() -> None:
    assert normalize_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").startswith("0x5aAe")


@pytest.mark.parametrize("bad", ["0x123", "0xzz", "not hex", "0x" + "g" * 40])
def test_parse_hex_rejects_garbage(bad: str) -> None:
    with pytest.raises(InvalidInputError):
        parse_hex(bad)


def test_parse_hex_accepts_bare_and_prefixed() -> None:
    assert parse_hex("0xdead") == parse_hex("DEAD") == b"\xde\xad"


@pytest.mark.parametrize(("raw", "expected"), [("0x10", 16), ("10", 10), (7, 7)])
def test_int_parsing(raw: str | int, expected: int) -> None:
    assert int_from_hex_or_dec(raw) == expected


@pytest.mark.parametrize("bad", ["-1", "0x" + "1" * 65, True, "1.5"])
def test_int_parsing_rejects(bad: object) -> None:
    with pytest.raises(InvalidInputError):
        int_from_hex_or_dec(bad)  # type: ignore[arg-type]
