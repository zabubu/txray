"""Strict ABI encoder/decoder.

The decoder is written for hostile input: calldata submitted for analysis may be
crafted to crash or exhaust the analyzer. Every offset and length is bounds-checked
against the buffer, array lengths are capped by the bytes actually available, nesting
depth is limited and padding bits are validated (non-canonical encodings are a known
trick to make a payload decode differently in different tools).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from txray.abi.types import AbiType
from txray.errors import AbiDecodingError
from txray.hexutil import to_checksum_address

MAX_DEPTH = 16
WORD = 32


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def word(self, offset: int) -> bytes:
        if offset < 0 or offset + WORD > len(self.data):
            raise AbiDecodingError(f"read past end of data at offset {offset}")
        return self.data[offset : offset + WORD]

    def uint(self, offset: int) -> int:
        return int.from_bytes(self.word(offset), "big")

    def offset_value(self, offset: int, base: int) -> int:
        """Read a relative pointer and turn it into an absolute, in-bounds offset."""
        rel = self.uint(offset)
        target = base + rel
        if rel >= len(self.data) or target > len(self.data):
            raise AbiDecodingError(f"pointer at {offset} out of bounds ({rel})")
        return target


def _decode(t: AbiType, r: _Reader, pos: int, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise AbiDecodingError("ABI nesting too deep")
    k = t.kind
    if k == "uint":
        value = r.uint(pos)
        if value >> t.bits:
            raise AbiDecodingError(f"uint{t.bits} has dirty high bits")
        return value
    if k == "int":
        raw = r.uint(pos)
        value = raw - (1 << 256) if raw >> 255 else raw
        lo, hi = -(1 << (t.bits - 1)), (1 << (t.bits - 1)) - 1
        if not lo <= value <= hi:
            raise AbiDecodingError(f"int{t.bits} out of range")
        return value
    if k == "address":
        word = r.word(pos)
        if any(word[:12]):
            raise AbiDecodingError("address has dirty high bits")
        return to_checksum_address(word[12:])
    if k == "bool":
        value = r.uint(pos)
        if value > 1:
            raise AbiDecodingError("bool is neither 0 nor 1")
        return bool(value)
    if k == "fixed_bytes":
        word = r.word(pos)
        if any(word[t.bits :]):
            raise AbiDecodingError(f"bytes{t.bits} has dirty low bits")
        return word[: t.bits]
    if k in ("bytes", "string"):
        length = r.uint(pos)
        start = pos + WORD
        if length > len(r.data) - start:
            raise AbiDecodingError("byte string length exceeds data")
        payload = r.data[start : start + length]
        if k == "string":
            try:
                return payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AbiDecodingError("string is not valid UTF-8") from exc
        return payload
    if k == "array":
        assert t.item is not None
        if t.length is None:
            count = r.uint(pos)
            base = pos + WORD
        else:
            count = t.length
            base = pos
        # Each element needs at least one word in the head: cheap guard against
        # "length = 2**255" allocation bombs.
        if count * min(t.item.head_size, WORD) > len(r.data) - base:
            raise AbiDecodingError("array length exceeds data")
        return [_decode_element(t.item, r, base, i, depth) for i in range(count)]
    if k == "tuple":
        return tuple(_decode_sequence(t.components, r, pos, depth + 1))
    raise AbiDecodingError(f"cannot decode kind {k}")


def _decode_element(item: AbiType, r: _Reader, base: int, index: int, depth: int) -> Any:
    if item.is_dynamic:
        target = r.offset_value(base + index * WORD, base)
        return _decode(item, r, target, depth + 1)
    return _decode(item, r, base + index * item.head_size, depth + 1)


def _decode_sequence(types: Sequence[AbiType], r: _Reader, base: int, depth: int) -> list[Any]:
    out: list[Any] = []
    head = base
    for t in types:
        if t.is_dynamic:
            out.append(_decode(t, r, r.offset_value(head, base), depth + 1))
        else:
            out.append(_decode(t, r, head, depth + 1))
        head += t.head_size
    return out


def decode(types: Sequence[AbiType], data: bytes) -> list[Any]:
    """Decode an ABI-encoded tuple of ``types`` from ``data``."""
    head = sum(t.head_size for t in types)
    if len(data) < head:
        raise AbiDecodingError(f"data too short: {len(data)} bytes, head needs {head}")
    return _decode_sequence(types, _Reader(data), 0, 0)


# --------------------------------------------------------------------------- encoder


def _pad_right(raw: bytes) -> bytes:
    return raw + b"\x00" * (-len(raw) % WORD)


def _encode_single(t: AbiType, value: Any) -> bytes:
    k = t.kind
    if k == "uint":
        if not isinstance(value, int) or value < 0 or value >> t.bits:
            raise AbiDecodingError(f"value out of range for uint{t.bits}: {value!r}")
        return value.to_bytes(WORD, "big")
    if k == "int":
        if not isinstance(value, int) or not -(1 << (t.bits - 1)) <= value < (1 << (t.bits - 1)):
            raise AbiDecodingError(f"value out of range for int{t.bits}: {value!r}")
        return (value % (1 << 256)).to_bytes(WORD, "big")
    if k == "address":
        raw = bytes.fromhex(str(value).removeprefix("0x")) if isinstance(value, str) else value
        if not isinstance(raw, bytes) or len(raw) != 20:
            raise AbiDecodingError(f"invalid address {value!r}")
        return raw.rjust(WORD, b"\x00")
    if k == "bool":
        return int(bool(value)).to_bytes(WORD, "big")
    if k == "fixed_bytes":
        if not isinstance(value, bytes) or len(value) != t.bits:
            raise AbiDecodingError(f"expected {t.bits} bytes")
        return value.ljust(WORD, b"\x00")
    if k in ("bytes", "string"):
        raw = value.encode("utf-8") if k == "string" else value
        return len(raw).to_bytes(WORD, "big") + _pad_right(raw)
    if k == "array":
        assert t.item is not None
        items = list(value)
        if t.length is not None and len(items) != t.length:
            raise AbiDecodingError("fixed array length mismatch")
        body = encode([t.item] * len(items), items)
        return body if t.length is not None else len(items).to_bytes(WORD, "big") + body
    if k == "tuple":
        return encode(t.components, list(value))
    raise AbiDecodingError(f"cannot encode kind {k}")


def encode(types: Sequence[AbiType], values: Sequence[Any]) -> bytes:
    if len(types) != len(values):
        raise AbiDecodingError("type/value count mismatch")
    head_len = sum(t.head_size for t in types)
    heads: list[bytes] = []
    tails: list[bytes] = []
    tail_offset = head_len
    for t, v in zip(types, values, strict=True):
        enc = _encode_single(t, v)
        if t.is_dynamic:
            heads.append(tail_offset.to_bytes(WORD, "big"))
            tails.append(enc)
            tail_offset += len(enc)
        else:
            heads.append(enc)
    return b"".join(heads) + b"".join(tails)
