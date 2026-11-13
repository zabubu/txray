"""Read-only access to chain state through Ethereum JSON-RPC.

Only four methods are used (``eth_chainId``, ``eth_getCode``, ``eth_getStorageAt``,
``eth_call``). Endpoints come exclusively from server-side configuration: API clients
select a chain id, never a URL, which rules out SSRF through the analysis API.
"""

from __future__ import annotations

import itertools
import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from txray.errors import RpcError
from txray.evm.profile import PROXY_SLOTS, BytecodeProfile, profile_bytecode
from txray.hexutil import keccak256, parse_hex, to_checksum_address, to_hex
from txray.storage import Store

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # largest legal code is 24 KiB (EIP-170); be generous
_IMPLEMENTATION_SELECTOR = keccak256(b"implementation()")[:4]


class ChainReader(Protocol):
    chain_id: int

    def get_code(self, address: str) -> bytes: ...

    def get_storage_at(self, address: str, slot: int) -> bytes: ...

    def call(self, address: str, data: bytes) -> bytes: ...


class RpcClient:
    """Minimal synchronous JSON-RPC client with timeouts, retries and size limits."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        retries: int = 2,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise RpcError("RPC URL must use http or https")
        self._url = url
        self._retries = retries
        self._ids = itertools.count(1)
        self._http = httpx.Client(
            timeout=timeout, transport=transport, headers={"user-agent": "txray"}
        )

    def close(self) -> None:
        self._http.close()

    def request(self, method: str, params: list[Any]) -> Any:
        payload = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params}
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                response = self._http.post(self._url, json=payload)
            except httpx.TransportError as exc:
                last_error = exc
                log.warning("rpc transport error", extra={"method": method, "attempt": attempt})
                time.sleep(min(0.25 * 2**attempt, 2.0))
                continue
            if response.status_code == 429 or response.status_code >= 500:
                last_error = RpcError(f"HTTP {response.status_code}")
                time.sleep(min(0.25 * 2**attempt, 2.0))
                continue
            return self._parse(method, response)
        raise RpcError(f"{method} failed after {self._retries + 1} attempts: {last_error}")

    @staticmethod
    def _parse(method: str, response: httpx.Response) -> Any:
        if response.status_code != 200:
            raise RpcError(f"{method}: HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise RpcError(f"{method}: response too large")
        try:
            body = response.json()
        except ValueError as exc:
            raise RpcError(f"{method}: invalid JSON response") from exc
        if not isinstance(body, dict):
            raise RpcError(f"{method}: unexpected response shape")
        if body.get("error"):
            err = body["error"]
            message = err.get("message") if isinstance(err, dict) else str(err)
            raise RpcError(f"{method}: {message}")
        if "result" not in body:
            raise RpcError(f"{method}: missing result")
        return body["result"]

    def chain_id(self) -> int:
        result = self.request("eth_chainId", [])
        if not isinstance(result, str):
            raise RpcError("eth_chainId: result is not a string")
        return int(result, 16)

    def get_code(self, address: str) -> bytes:
        return self._hex_result(self.request("eth_getCode", [address, "latest"]), "eth_getCode")

    def get_storage_at(self, address: str, slot: int) -> bytes:
        result = self.request("eth_getStorageAt", [address, hex(slot), "latest"])
        return self._hex_result(result, "eth_getStorageAt").rjust(32, b"\0")[-32:]

    def call(self, address: str, data: bytes) -> bytes:
        result = self.request("eth_call", [{"to": address, "data": to_hex(data)}, "latest"])
        return self._hex_result(result, "eth_call")

    @staticmethod
    def _hex_result(result: Any, method: str) -> bytes:
        if not isinstance(result, str):
            raise RpcError(f"{method}: result is not a hex string")
        try:
            return parse_hex(result, field=method)
        except ValueError as exc:
            raise RpcError(str(exc)) from exc


class RpcChainReader:
    """:class:`ChainReader` over an :class:`RpcClient`, with a SQLite code cache.

    Code is cached for ``code_ttl`` seconds rather than forever: SELFDESTRUCT within
    the creation transaction and metamorphic contracts mean code at an address is not
    strictly immutable.
    """

    def __init__(
        self,
        client: RpcClient,
        chain_id: int,
        store: Store | None = None,
        code_ttl: int = 3600,
    ) -> None:
        self.client = client
        self.chain_id = chain_id
        self.store = store
        self.code_ttl = code_ttl

    def get_code(self, address: str) -> bytes:
        if self.store is not None:
            cached = self.store.get_code(self.chain_id, address, self.code_ttl)
            if cached is not None:
                return cached
        code = self.client.get_code(address)
        if self.store is not None:
            self.store.put_code(self.chain_id, address, code)
        return code

    def get_storage_at(self, address: str, slot: int) -> bytes:
        return self.client.get_storage_at(address, slot)

    def call(self, address: str, data: bytes) -> bytes:
        return self.client.call(address, data)


@dataclass
class ResolvedContract:
    address: str
    code: bytes
    profile: BytecodeProfile
    implementation: str | None = None  # set for proxies whose implementation was found
    implementation_profile: BytecodeProfile | None = None
    proxy_kind: str | None = None

    @property
    def is_contract(self) -> bool:
        return bool(self.code)

    @property
    def effective_profile(self) -> BytecodeProfile:
        """Profile of the code that actually executes calls (implementation if proxy)."""
        return self.implementation_profile or self.profile


def _word_to_address(word: bytes) -> str | None:
    if len(word) < 20 or any(word[:-20]) or not any(word[-20:]):
        return None
    return to_checksum_address(word[-20:])


def resolve_contract(reader: ChainReader, address: str) -> ResolvedContract:
    """Fetch code and follow one level of proxy indirection."""
    code = reader.get_code(address)
    resolved = ResolvedContract(address, code, profile_bytecode(code))
    if not code:
        return resolved
    impl: str | None = None
    kind: str | None = None
    if resolved.profile.minimal_proxy_target:
        impl, kind = resolved.profile.minimal_proxy_target, "eip-1167"
    else:
        for slot_name in (
            "eip1967.implementation",
            "zeppelinos.implementation",
            "eip1822.proxiable",
        ):
            if slot_name in resolved.profile.proxy_slots:
                impl = _word_to_address(reader.get_storage_at(address, PROXY_SLOTS[slot_name]))
                if impl:
                    kind = slot_name
                    break
        if impl is None and "eip1967.beacon" in resolved.profile.proxy_slots:
            beacon = _word_to_address(reader.get_storage_at(address, PROXY_SLOTS["eip1967.beacon"]))
            if beacon:
                try:
                    impl = _word_to_address(reader.call(beacon, _IMPLEMENTATION_SELECTOR)[-32:])
                    kind = "eip1967.beacon" if impl else None
                except RpcError:
                    log.info("beacon implementation() call failed", extra={"beacon": beacon})
    if impl:
        impl_code = reader.get_code(impl)
        resolved.implementation = impl
        resolved.proxy_kind = kind
        resolved.implementation_profile = profile_bytecode(impl_code)
    return resolved
