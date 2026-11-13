"""EIP-712 typed structured data: validation and hashing.

Implements ``encodeType``, ``hashStruct`` and the final signing digest
``keccak256(0x1901 || domainSeparator || hashStruct(message))`` as specified in
EIP-712 (including arrays, as in ``eth_signTypedData_v4``). The digest lets a user
check that what the wallet displays is what will actually be signed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from txray.errors import InvalidInputError, TypedDataError
from txray.hexutil import (
    int_from_hex_or_dec,
    is_address,
    keccak256,
    normalize_address,
    parse_hex,
)

MAX_DEPTH = 32
DOMAIN_FIELDS: list[tuple[str, str]] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
]
_IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_ARRAY = re.compile(r"^(.*)\[(\d*)\]$")


@dataclass(frozen=True)
class TypedData:
    types: dict[str, list[tuple[str, str]]]  # type name -> [(field name, field type)]
    primary_type: str
    domain: dict[str, Any]
    message: dict[str, Any]

    @property
    def domain_chain_id(self) -> int | None:
        value = self.domain.get("chainId")
        return None if value is None else int_from_hex_or_dec(value, field="domain.chainId")

    @property
    def verifying_contract(self) -> str | None:
        value = self.domain.get("verifyingContract")
        return normalize_address(value, field="domain.verifyingContract") if value else None


def _is_atomic(t: str) -> bool:
    if t in ("address", "bool", "bytes", "string"):
        return True
    m = re.fullmatch(r"(u?int)(\d*)", t)
    if m:
        bits = int(m.group(2) or 256)
        return 8 <= bits <= 256 and bits % 8 == 0
    fixed = re.fullmatch(r"bytes(\d+)", t)
    return fixed is not None and 1 <= int(fixed.group(1)) <= 32


def parse_typed_data(raw: dict[str, Any] | str) -> TypedData:
    """Validate an ``eth_signTypedData_v4`` payload."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TypedDataError(f"typed data is not valid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise TypedDataError("typed data must be a JSON object")
    for key in ("types", "primaryType", "domain", "message"):
        if key not in raw:
            raise TypedDataError(f"missing top-level field {key!r}")
    raw_types, primary = raw["types"], raw["primaryType"]
    domain, message = raw["domain"], raw["message"]
    if not isinstance(raw_types, dict) or not isinstance(primary, str):
        raise TypedDataError("types must be an object and primaryType a string")
    if not isinstance(domain, dict) or not isinstance(message, dict):
        raise TypedDataError("domain and message must be objects")

    types: dict[str, list[tuple[str, str]]] = {}
    for name, fields in raw_types.items():
        if not _IDENT.match(name):
            raise TypedDataError(f"invalid type name {name!r}")
        if not isinstance(fields, list):
            raise TypedDataError(f"fields of {name} must be a list")
        parsed: list[tuple[str, str]] = []
        seen: set[str] = set()
        for f in fields:
            if (
                not isinstance(f, dict)
                or not isinstance(f.get("name"), str)
                or not isinstance(f.get("type"), str)
            ):
                raise TypedDataError(f"invalid field definition in {name}")
            if f["name"] in seen:
                raise TypedDataError(f"duplicate field {f['name']!r} in {name}")
            seen.add(f["name"])
            parsed.append((f["name"], f["type"]))
        types[name] = parsed

    if "EIP712Domain" not in types:
        types["EIP712Domain"] = [(n, t) for n, t in DOMAIN_FIELDS if n in domain]
    unknown_domain = set(domain) - {n for n, _ in types["EIP712Domain"]}
    if unknown_domain:
        raise TypedDataError(
            f"domain has fields not declared in EIP712Domain: {sorted(unknown_domain)}"
        )

    for name, fields in types.items():
        for fname, ftype in fields:
            base = ftype
            while (m := _ARRAY.match(base)) is not None:
                base = m.group(1)
            if not (_is_atomic(base) or base in types):
                raise TypedDataError(f"{name}.{fname}: unknown type {ftype!r}")
    if primary not in types:
        raise TypedDataError(f"primaryType {primary!r} is not defined")
    return TypedData(types, primary, domain, message)


def _dependencies(primary: str, types: dict[str, list[tuple[str, str]]]) -> list[str]:
    found: set[str] = set()
    stack = [primary]
    while stack:
        current = stack.pop()
        if current in found or current not in types:
            continue
        found.add(current)
        for _, ftype in types[current]:
            base = ftype.split("[", 1)[0]
            if base in types:
                stack.append(base)
    found.discard(primary)
    return [primary, *sorted(found)]


def encode_type(primary: str, types: dict[str, list[tuple[str, str]]]) -> str:
    return "".join(
        f"{name}(" + ",".join(f"{t} {n}" for n, t in types[name]) + ")"
        for name in _dependencies(primary, types)
    )


def type_hash(primary: str, types: dict[str, list[tuple[str, str]]]) -> bytes:
    return keccak256(encode_type(primary, types).encode())


def _encode_value(
    t: str, value: Any, types: dict[str, list[tuple[str, str]]], path: str, depth: int
) -> bytes:
    if depth > MAX_DEPTH:
        raise TypedDataError("typed data nested too deeply")
    m = _ARRAY.match(t)
    if m:
        item_type, length = m.group(1), m.group(2)
        if not isinstance(value, list):
            raise TypedDataError(f"{path}: expected an array")
        if length and len(value) != int(length):
            raise TypedDataError(f"{path}: expected {length} items, got {len(value)}")
        return keccak256(
            b"".join(
                _encode_value(item_type, v, types, f"{path}[{i}]", depth + 1)
                for i, v in enumerate(value)
            )
        )
    if t in types:
        if not isinstance(value, dict):
            raise TypedDataError(f"{path}: expected an object of type {t}")
        return hash_struct(t, value, types, path, depth + 1)
    try:
        return _encode_atomic(t, value, path)
    except InvalidInputError as exc:
        raise TypedDataError(str(exc)) from exc


def _encode_atomic(t: str, value: Any, path: str) -> bytes:
    if t == "string":
        if not isinstance(value, str):
            raise TypedDataError(f"{path}: expected a string")
        return keccak256(value.encode("utf-8"))
    if t == "bytes":
        if not isinstance(value, str):
            raise TypedDataError(f"{path}: expected hex bytes")
        return keccak256(parse_hex(value, field=path))
    if t == "address":
        if not is_address(value):
            raise TypedDataError(f"{path}: invalid address")
        return bytes.fromhex(value[2:].lower() if value.startswith("0x") else value).rjust(
            32, b"\0"
        )
    if t == "bool":
        if not isinstance(value, bool):
            raise TypedDataError(f"{path}: expected a boolean")
        return int(value).to_bytes(32, "big")
    if t.startswith("bytes"):
        size = int(t[5:])
        raw = parse_hex(value, field=path) if isinstance(value, str) else None
        if raw is None or len(raw) != size:
            raise TypedDataError(f"{path}: expected {size} bytes")
        return raw.ljust(32, b"\0")
    signed = t.startswith("int")
    bits = int(t[3 if signed else 4 :] or 256)
    if signed:
        number = _parse_signed(value, path)
        if not -(1 << (bits - 1)) <= number < (1 << (bits - 1)):
            raise TypedDataError(f"{path}: out of range for {t}")
        return (number % (1 << 256)).to_bytes(32, "big")
    number = int_from_hex_or_dec(value, field=path)
    if number >> bits:
        raise TypedDataError(f"{path}: out of range for {t}")
    return number.to_bytes(32, "big")


def _parse_signed(value: Any, path: str) -> int:
    if isinstance(value, bool):
        raise TypedDataError(f"{path}: expected an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise TypedDataError(f"{path}: not an integer") from exc
    raise TypedDataError(f"{path}: expected an integer")


def hash_struct(
    primary: str,
    data: dict[str, Any],
    types: dict[str, list[tuple[str, str]]],
    path: str = "message",
    depth: int = 0,
) -> bytes:
    fields = types[primary]
    extra = set(data) - {n for n, _ in fields}
    if extra:
        raise TypedDataError(f"{path}: fields not declared in {primary}: {sorted(extra)}")
    encoded = [type_hash(primary, types)]
    for name, ftype in fields:
        if name not in data:
            raise TypedDataError(f"{path}.{name}: missing value")
        encoded.append(_encode_value(ftype, data[name], types, f"{path}.{name}", depth))
    return keccak256(b"".join(encoded))


def domain_separator(td: TypedData) -> bytes:
    return hash_struct("EIP712Domain", td.domain, td.types, "domain")


def signing_digest(td: TypedData) -> bytes:
    if td.primary_type == "EIP712Domain":
        return keccak256(b"\x19\x01" + domain_separator(td))
    return keccak256(
        b"\x19\x01" + domain_separator(td) + hash_struct(td.primary_type, td.message, td.types)
    )
