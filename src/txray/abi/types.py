"""Parser for Solidity ABI type strings and function signatures.

Supports every type that can appear in a canonical signature: ``uintN``, ``intN``,
``address``, ``bool``, ``bytesN``, ``bytes``, ``string``, fixed/dynamic arrays and
tuples (written ``(t1,t2,...)``). Fixed-point types are rejected because no deployed
contract we care about uses them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from txray.errors import AbiDecodingError

_ELEMENTARY = {"address", "bool", "bytes", "string"}


@dataclass(frozen=True)
class AbiType:
    kind: str  # uint | int | address | bool | fixed_bytes | bytes | string | array | tuple
    bits: int = 0  # uint/int bit width, fixed_bytes byte width
    item: AbiType | None = None  # array element type
    length: int | None = None  # fixed array length, None for T[]
    components: tuple[AbiType, ...] = field(default_factory=tuple)

    @property
    def is_dynamic(self) -> bool:
        if self.kind in ("bytes", "string"):
            return True
        if self.kind == "array":
            assert self.item is not None
            return self.length is None or self.item.is_dynamic
        if self.kind == "tuple":
            return any(c.is_dynamic for c in self.components)
        return False

    @property
    def head_size(self) -> int:
        """Bytes occupied in the head section of the enclosing tuple."""
        if self.is_dynamic:
            return 32
        if self.kind == "array":
            assert self.item is not None
            assert self.length is not None
            return self.length * self.item.head_size
        if self.kind == "tuple":
            return sum(c.head_size for c in self.components)
        return 32

    def canonical(self) -> str:
        if self.kind in ("uint", "int"):
            return f"{self.kind}{self.bits}"
        if self.kind == "fixed_bytes":
            return f"bytes{self.bits}"
        if self.kind == "array":
            assert self.item is not None
            suffix = "" if self.length is None else str(self.length)
            return f"{self.item.canonical()}[{suffix}]"
        if self.kind == "tuple":
            return "(" + ",".join(c.canonical() for c in self.components) + ")"
        return self.kind


def _split_top_level(text: str) -> list[str]:
    """Split a comma separated list while respecting nested parentheses."""
    if text == "":
        return []
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise AbiDecodingError(f"unbalanced parentheses in {text!r}")
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    if depth != 0:
        raise AbiDecodingError(f"unbalanced parentheses in {text!r}")
    parts.append(text[start:])
    return parts


def parse_type(text: str) -> AbiType:
    text = text.strip()
    if not text:
        raise AbiDecodingError("empty type")
    # Array suffixes bind last: parse them right-to-left.
    if text.endswith("]"):
        open_idx = text.rfind("[")
        if open_idx <= 0:
            raise AbiDecodingError(f"malformed array type {text!r}")
        inner = text[open_idx + 1 : -1]
        length: int | None = None
        if inner:
            if not inner.isdigit() or int(inner) == 0:
                raise AbiDecodingError(f"invalid array length in {text!r}")
            length = int(inner)
        return AbiType("array", item=parse_type(text[:open_idx]), length=length)
    if text.startswith("("):
        if not text.endswith(")"):
            raise AbiDecodingError(f"malformed tuple {text!r}")
        return AbiType(
            "tuple", components=tuple(parse_type(p) for p in _split_top_level(text[1:-1]))
        )
    if text in _ELEMENTARY:
        return AbiType(text)
    for prefix in ("uint", "int"):
        if text.startswith(prefix):
            width = text[len(prefix) :] or "256"
            if not width.isdigit():
                break
            bits = int(width)
            if bits == 0 or bits > 256 or bits % 8:
                raise AbiDecodingError(f"invalid integer width in {text!r}")
            return AbiType(prefix, bits=bits)
    if text.startswith("bytes"):
        width = text[5:]
        if width.isdigit() and 1 <= int(width) <= 32:
            return AbiType("fixed_bytes", bits=int(width))
    raise AbiDecodingError(f"unsupported ABI type {text!r}")


@dataclass(frozen=True)
class FunctionSignature:
    name: str
    inputs: tuple[AbiType, ...]
    arg_names: tuple[str, ...]

    @property
    def canonical(self) -> str:
        return f"{self.name}(" + ",".join(t.canonical() for t in self.inputs) + ")"


def parse_signature(text: str, arg_names: tuple[str, ...] | None = None) -> FunctionSignature:
    """Parse ``name(type1,type2)``. Argument names are supplied separately."""
    text = text.strip()
    paren = text.find("(")
    if paren <= 0 or not text.endswith(")"):
        raise AbiDecodingError(f"malformed signature {text!r}")
    name = text[:paren]
    if not name.replace("_", "a").isalnum() or name[0].isdigit():
        raise AbiDecodingError(f"invalid function name in {text!r}")
    inputs = tuple(parse_type(p) for p in _split_top_level(text[paren + 1 : -1]))
    names = arg_names if arg_names is not None else tuple(f"arg{i}" for i in range(len(inputs)))
    if len(names) != len(inputs):
        raise AbiDecodingError(f"argument name count mismatch for {text!r}")
    return FunctionSignature(name, inputs, names)
