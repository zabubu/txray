"""Opt-in tests against a real Ethereum mainnet RPC.

Run with: TXRAY_LIVE_RPC=https://ethereum-rpc.publicnode.com pytest -m live
"""

import os

import pytest

from tests.conftest import USDC, USDC_IMPL, load_bytecode
from txray.chain import RpcChainReader, RpcClient, resolve_contract

LIVE_RPC = os.environ.get("TXRAY_LIVE_RPC")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not LIVE_RPC, reason="TXRAY_LIVE_RPC not set"),
]


@pytest.fixture(scope="module")
def reader() -> RpcChainReader:
    assert LIVE_RPC is not None
    client = RpcClient(LIVE_RPC)
    assert client.chain_id() == 1, "live tests expect Ethereum mainnet"
    return RpcChainReader(client, 1)


def test_weth_code_matches_fixture(reader: RpcChainReader) -> None:
    assert reader.get_code("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2") == load_bytecode("weth9")


def test_usdc_proxy_resolution(reader: RpcChainReader) -> None:
    resolved = resolve_contract(reader, USDC)
    assert resolved.proxy_kind == "zeppelinos.implementation"
    # The implementation changes on upgrades; only check that one was found.
    assert resolved.implementation is not None
    if resolved.implementation.lower() == USDC_IMPL.lower():
        assert resolved.implementation_profile is not None
        assert resolved.implementation_profile.cfg_complete
