import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.conftest import SELFDESTRUCT_CONTRACT, FakeChain
from txray.chain import RpcChainReader, RpcClient, resolve_contract
from txray.config import hash_api_key, load_settings
from txray.errors import ConfigError, RpcError
from txray.evm.profile import PROXY_SLOTS
from txray.hexutil import keccak256
from txray.intel import AddressIntel, find_lookalike, parse_address_list
from txray.storage import Store

ADDR = "0x1111111111111111111111111111111111111111"


# ---------------------------------------------------------------- RPC client
def rpc_transport(handler: Any) -> httpx.MockTransport:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        result = handler(body["method"], body["params"])
        if isinstance(result, httpx.Response):
            return result
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **result})

    return httpx.MockTransport(respond)


def test_rpc_get_code_and_chain_id() -> None:
    def handler(method: str, params: list[Any]) -> dict[str, Any]:
        if method == "eth_chainId":
            return {"result": "0x89"}
        assert method == "eth_getCode"
        assert params == [ADDR, "latest"]
        return {"result": "0x6000"}

    client = RpcClient("https://rpc.invalid", transport=rpc_transport(handler))
    assert client.chain_id() == 137
    assert client.get_code(ADDR) == b"\x60\x00"


def test_rpc_error_object() -> None:
    client = RpcClient(
        "https://rpc.invalid",
        transport=rpc_transport(lambda m, p: {"error": {"code": -32000, "message": "boom"}}),
    )
    with pytest.raises(RpcError, match="boom"):
        client.get_code(ADDR)


def test_rpc_retries_on_server_error_then_fails() -> None:
    calls = []

    def handler(method: str, params: list[Any]) -> httpx.Response:
        calls.append(method)
        return httpx.Response(503)

    client = RpcClient("https://rpc.invalid", retries=1, transport=rpc_transport(handler))
    with pytest.raises(RpcError, match="after 2 attempts"):
        client.get_code(ADDR)
    assert len(calls) == 2


def test_rpc_rejects_non_hex_result() -> None:
    client = RpcClient("https://rpc.invalid", transport=rpc_transport(lambda m, p: {"result": 5}))
    with pytest.raises(RpcError):
        client.get_code(ADDR)


def test_rpc_url_scheme_enforced() -> None:
    with pytest.raises(RpcError):
        RpcClient("file:///etc/passwd")


def test_reader_caches_code() -> None:
    calls = []

    def handler(method: str, params: list[Any]) -> dict[str, Any]:
        calls.append(method)
        return {"result": "0x6001"}

    client = RpcClient("https://rpc.invalid", transport=rpc_transport(handler))
    reader = RpcChainReader(client, 1, Store(":memory:"))
    assert reader.get_code(ADDR) == reader.get_code(ADDR.upper().replace("0X", "0x")) == b"\x60\x01"
    assert calls == ["eth_getCode"]
    reader.code_ttl = -1
    reader.get_code(ADDR)
    assert len(calls) == 2


# ---------------------------------------------------------------- proxy resolution
def _eip1967_proxy_code() -> bytes:
    slot = PROXY_SLOTS["eip1967.implementation"].to_bytes(32, "big")
    # PUSH32 <slot> SLOAD ... DELEGATECALL: enough for slot detection.
    return bytes([0x7F]) + slot + bytes.fromhex("545af400")


def test_resolve_eip1967_proxy() -> None:
    chain = FakeChain()
    impl = "0x000000000000000000000000000000000000beef"
    chain.set_code(ADDR, _eip1967_proxy_code()).set_code(impl, SELFDESTRUCT_CONTRACT)
    chain.storage[(ADDR, PROXY_SLOTS["eip1967.implementation"])] = bytes(12) + bytes.fromhex(
        impl[2:]
    )
    resolved = resolve_contract(chain, ADDR)
    assert resolved.proxy_kind == "eip1967.implementation"
    assert resolved.implementation is not None
    assert resolved.implementation.lower() == impl
    assert "BC001" in {f.rule_id for f in resolved.effective_profile.findings}


def test_resolve_beacon_proxy() -> None:
    chain = FakeChain()
    beacon = "0x000000000000000000000000000000000000b0b0"
    impl = "0x000000000000000000000000000000000000beef"
    slot = PROXY_SLOTS["eip1967.beacon"]
    chain.set_code(ADDR, bytes([0x7F]) + slot.to_bytes(32, "big") + bytes.fromhex("545af400"))
    chain.set_code(impl, b"\x00")
    chain.storage[(ADDR, slot)] = bytes(12) + bytes.fromhex(beacon[2:])
    chain.calls[(beacon, keccak256(b"implementation()")[:4])] = bytes(12) + bytes.fromhex(impl[2:])
    resolved = resolve_contract(chain, ADDR)
    assert resolved.proxy_kind == "eip1967.beacon"
    assert resolved.implementation is not None


def test_resolve_eoa() -> None:
    resolved = resolve_contract(FakeChain(), ADDR)
    assert not resolved.is_contract
    assert resolved.implementation is None


# ---------------------------------------------------------------- config
def test_settings_from_toml_and_env(tmp_path: Path) -> None:
    cfg = tmp_path / "txray.toml"
    key_hash = hash_api_key("secret")
    cfg.write_text(
        f'db_path = "x.db"\nrate_limit_per_minute = 10\napi_key_hashes = ["{key_hash}"]\n'
        '[rpc]\n1 = "https://a.invalid"\n'
    )
    settings = load_settings(
        cfg, env={"TXRAY_RPC_10": "https://b.invalid", "TXRAY_RATE_LIMIT": "5"}
    )
    assert settings.rpc == {1: "https://a.invalid", 10: "https://b.invalid"}
    assert settings.rate_limit_per_minute == 5
    assert settings.api_key_hashes == [key_hash]


@pytest.mark.parametrize(
    "content",
    [
        "unknown_key = 1\n",
        '[rpc]\n1 = "ftp://x"\n',
        'api_key_hashes = ["not-a-hash"]\n',
        'log_level = "LOUD"\n',
        'rate_limit_per_minute = "many"\n',
        "this is not toml",
    ],
)
def test_invalid_settings(tmp_path: Path, content: str) -> None:
    cfg = tmp_path / "bad.toml"
    cfg.write_text(content)
    with pytest.raises(ConfigError):
        load_settings(cfg, env={})


def test_missing_config_file() -> None:
    with pytest.raises(ConfigError):
        load_settings("/nonexistent/txray.toml", env={})


# ---------------------------------------------------------------- storage
def test_store_reports(tmp_path: Path) -> None:
    store = Store(tmp_path / "sub" / "t.db")
    report = {
        "id": "abc",
        "kind": "message",
        "verdict": "pass",
        "score": 0,
        "created_at": "2026-01-01T00:00:00+00:00",
        "chain_id": 1,
        "findings": [],
    }
    store.save_report(report)
    assert store.get_report("abc") == report
    assert store.get_report("missing") is None
    assert store.list_reports()[0]["id"] == "abc"
    store.close()


# ---------------------------------------------------------------- intel
def test_address_list_parsing() -> None:
    parsed = parse_address_list(f"# comment\n{ADDR}, Some label\n\n{ADDR.replace('1', '2')}\n")
    assert list(parsed.values()) == ["Some label", "0x2222222222222222222222222222222222222222"]
    with pytest.raises(ConfigError):
        parse_address_list("0x1234\n")


def test_lookalike_thresholds() -> None:
    trusted = {"0x9f3C8d1Ae6B04C7F5a2D93B8E1C6F0A4d7e2b5c1": "deposit"}
    assert find_lookalike("0x9f3c4E7B1a90d2C6F83b5e0a71d94C2B8F6eb5C1", trusted) is not None
    # 3 + 3 matching characters is below the threshold.
    assert find_lookalike("0x9f30000000000000000000000000000000000b5c1"[:42], trusted) is None
    assert find_lookalike("0x9f3C8d1Ae6B04C7F5a2D93B8E1C6F0A4d7e2b5c1", trusted) is None


def test_known_contracts_are_chain_scoped() -> None:
    intel = AddressIntel()
    router = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
    assert intel.known_contract(router, 1) is not None
    assert intel.known_contract(router, 10) is None
    assert intel.known_contract("0x000000000022D473030F116dDEE9F6B43aC78BA3", 8453) is not None
