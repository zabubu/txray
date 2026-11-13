"""Per-request analysis context and checks shared by every analyzer."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from txray.chain import ChainReader, ResolvedContract, resolve_contract
from txray.errors import RpcError
from txray.hexutil import is_address, to_checksum_address
from txray.intel import AddressIntel
from txray.models import Finding
from txray.rules import finding

log = logging.getLogger(__name__)

THIRTY_DAYS = 30 * 24 * 3600


@dataclass
class AnalysisContext:
    chain_id: int | None = None
    sender: str | None = None  # account asked to sign
    origin: str | None = None  # requesting site, e.g. "https://app.example.org"
    reader: ChainReader | None = None
    intel: AddressIntel = field(default_factory=AddressIntel)
    now: int = field(default_factory=lambda: int(time.time()))
    offline: bool = False
    notes: list[str] = field(default_factory=list)
    _resolved: dict[str, ResolvedContract | None] = field(default_factory=dict)
    _checked: set[str] = field(default_factory=set)

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def resolve(self, address: str) -> ResolvedContract | None:
        """Code + proxy resolution through the configured RPC, or None when offline."""
        key = address.lower()
        if key in self._resolved:
            return self._resolved[key]
        result: ResolvedContract | None = None
        if self.reader is None:
            self.note(
                "Offline mode: on-chain checks skipped."
                if self.offline
                else "No RPC endpoint configured for this chain: on-chain checks skipped."
            )
        else:
            try:
                result = resolve_contract(self.reader, address)
            except RpcError as exc:
                log.warning(
                    "contract resolution failed", extra={"address": address, "error": str(exc)}
                )
                self.note(f"RPC error while inspecting {address}: on-chain checks skipped.")
        self._resolved[key] = result
        return result

    def is_contract(self, address: str) -> bool | None:
        resolved = self.resolve(address)
        return None if resolved is None else resolved.is_contract

    def known_label(self, address: str) -> str | None:
        known = self.intel.known_contract(address, self.chain_id)
        if known:
            return known.label
        return self.intel.address_book.get(to_checksum_address(address))

    def address_findings(self, address: str, role: str) -> list[Finding]:
        """Denylist and look-alike checks, reported once per address per analysis."""
        key = address.lower()
        if key in self._checked:
            return []
        self._checked.add(key)
        out: list[Finding] = []
        label = self.intel.denylisted(address)
        if label:
            out.append(
                finding(
                    "INT001",
                    f"The {role} {address} is denylisted ({label}).",
                    address=address,
                    role=role,
                    label=label,
                )
            )
        twin = self.intel.lookalike(address)
        if twin:
            out.append(
                finding(
                    "INT002",
                    f"The {role} {address} imitates {twin.resembles} ({twin.label}): "
                    f"{twin.prefix} leading and {twin.suffix} trailing hex characters match.",
                    address=address,
                    role=role,
                    resembles=twin.resembles,
                    resembles_label=twin.label,
                )
            )
        return out


def collect_addresses(value: Any, path: str = "") -> list[tuple[str, str]]:
    """All address-looking strings in a nested JSON value, with their path."""
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.extend(collect_addresses(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.extend(collect_addresses(v, f"{path}[{i}]"))
    elif isinstance(value, str) and is_address(value) and int(value, 16) != 0:
        out.append((path, to_checksum_address(value)))
    return out


def jsonable(value: Any) -> Any:
    """Convert decoded ABI values for JSON output (big ints as decimal strings)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, list | tuple):
        return [jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    return value
