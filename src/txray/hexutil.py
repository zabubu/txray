"""Hex, hashing and address helpers shared by every module."""

from __future__ import annotations

import re

from Crypto.Hash import keccak as _keccak

from txray.errors import InvalidInputError

UINT256_MAX = (1 << 256) - 1
ZERO_ADDRESS = "0x" + "00" * 20

_ADDRESS_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")


def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def selector(signature: str) -> bytes:
    """4-byte function selector of a canonical signature such as ``transfer(address,uint256)``."""
    return keccak256(signature.encode("ascii"))[:4]


def parse_hex(value: str, *, field: str = "value", allow_empty: bool = True) -> bytes:
    """Decode a ``0x``-prefixed (or bare) hex string, raising :class:`InvalidInputError`."""
    if not isinstance(value, str):
        raise InvalidInputError(f"{field}: expected a hex string")
    text = value.strip()
    if text[:2] in ("0x", "0X"):
        text = text[2:]
    if not text and not allow_empty:
        raise InvalidInputError(f"{field}: empty hex string")
    if len(text) % 2:
        raise InvalidInputError(f"{field}: odd-length hex string")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise InvalidInputError(f"{field}: invalid hex characters") from exc


def to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def is_address(value: object) -> bool:
    return isinstance(value, str) and bool(_ADDRESS_RE.match(value))


def to_checksum_address(value: str | bytes) -> str:
    """EIP-55 mixed-case checksum encoding."""
    if isinstance(value, bytes):
        if len(value) != 20:
            raise InvalidInputError("address must be 20 bytes")
        lower = value.hex()
    else:
        if not is_address(value):
            raise InvalidInputError(f"invalid address: {value!r}")
        lower = value.lower().removeprefix("0x")
    digest = keccak256(lower.encode("ascii")).hex()
    out = "".join(
        ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch for i, ch in enumerate(lower)
    )
    return "0x" + out


def normalize_address(value: str, *, field: str = "address", strict_checksum: bool = False) -> str:
    """Validate an address and return its checksummed form.

    Mixed-case input must carry a valid EIP-55 checksum: a wrong checksum is a classic
    sign of a hand-modified (possibly poisoned) address. All-lower/upper input is accepted.
    """
    if not is_address(value):
        raise InvalidInputError(f"{field}: invalid address {value!r}")
    body = value.removeprefix("0x").removeprefix("0X")
    checksummed = to_checksum_address(value)
    mixed = body != body.lower() and body != body.upper()
    if (mixed or strict_checksum) and checksummed[2:] != body:
        raise InvalidInputError(f"{field}: EIP-55 checksum mismatch for {value}")
    return checksummed


def int_from_hex_or_dec(value: str | int, *, field: str = "value") -> int:
    if isinstance(value, bool):
        raise InvalidInputError(f"{field}: expected an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            result = int(text, 16) if text[:2] in ("0x", "0X") else int(text, 10)
        except ValueError as exc:
            raise InvalidInputError(f"{field}: not an integer: {value!r}") from exc
    else:
        raise InvalidInputError(f"{field}: expected an integer")
    if result < 0 or result > UINT256_MAX:
        raise InvalidInputError(f"{field}: out of uint256 range")
    return result
