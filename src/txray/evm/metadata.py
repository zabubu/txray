"""Solidity metadata trailer parsing.

The Solidity compiler appends a CBOR map to runtime bytecode followed by its length on
two bytes, e.g. ``{"ipfs": <34 bytes>, "solc": <3 bytes>}``. Stripping it matters for
analysis (the trailer would otherwise be disassembled as garbage instructions) and
the compiler version is useful context in reports.

Only the subset of CBOR that compilers emit is supported: a definite-length map with
text keys and byte-string, text, unsigned or boolean values.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class _CborError(ValueError):
    pass


class _Cbor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise _CborError("truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def _argument(self, info: int) -> int:
        if info < 24:
            return info
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in sizes:
            raise _CborError("indefinite or reserved length")
        return int.from_bytes(self._take(sizes[info]), "big")

    def item(self) -> object:
        head = self._take(1)[0]
        major, info = head >> 5, head & 0x1F
        if major == 0:
            return self._argument(info)
        if major == 2:
            return self._take(self._argument(info))
        if major == 3:
            return self._take(self._argument(info)).decode("utf-8", errors="strict")
        if major == 5:
            count = self._argument(info)
            out: dict[str, object] = {}
            for _ in range(count):
                key = self.item()
                if not isinstance(key, str):
                    raise _CborError("non-text key")
                out[key] = self.item()
            return out
        if major == 7 and info in (20, 21):
            return info == 21
        raise _CborError(f"unsupported major type {major}")


@dataclass(frozen=True)
class Metadata:
    raw_length: int  # bytes stripped from the end of the code (CBOR + 2 length bytes)
    fields: dict[str, object] = field(default_factory=dict)

    @property
    def compiler(self) -> str | None:
        solc = self.fields.get("solc")
        if isinstance(solc, bytes) and len(solc) == 3:
            return "solc " + ".".join(str(b) for b in solc)
        if isinstance(solc, str):
            return f"solc {solc}"
        return None

    @property
    def source_hash(self) -> str | None:
        for key in ("ipfs", "bzzr1", "bzzr0"):
            value = self.fields.get(key)
            if isinstance(value, bytes):
                return f"{key}:{value.hex()}"
        return None


def parse_metadata(code: bytes) -> Metadata | None:
    if len(code) < 4:
        return None
    length = int.from_bytes(code[-2:], "big")
    if length == 0 or length + 2 > len(code):
        return None
    blob = code[-2 - length : -2]
    try:
        parser = _Cbor(blob)
        decoded = parser.item()
    except (_CborError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict) or parser.pos != len(blob):
        return None
    if not decoded.keys() & {"ipfs", "bzzr0", "bzzr1", "solc", "experimental"}:
        return None
    return Metadata(length + 2, decoded)
