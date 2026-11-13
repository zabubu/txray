from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from txray.analysis.context import AnalysisContext
from txray.errors import RpcError
from txray.evm.disassembler import assemble
from txray.hexutil import parse_hex, to_checksum_address
from txray.intel import AddressIntel, load_address_list

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXAMPLES = ROOT / "examples"

# Mainnet addresses whose bytecode is stored in tests/fixtures/bytecode.
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDC_IMPL = "0x43506849D7C04F9138D1A2050bbF3A0c054402dd"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
ZEPPELINOS_SLOT = 0x7050C9E0F4CA769C69BD3A8EF740BC37934F8E2C036E5A723FD8EE048ED3F8C3

VICTIM = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
ATTACKER = "0x7A3B9F1E2c4d5a6b8e9f0A1B2C3D4E5F6a7b8C9d"
EOA = "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB"

# A contract with a single function that can SELFDESTRUCT, built with the assembler.
SELFDESTRUCT_CONTRACT = assemble(
    """
    PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR
    DUP1 PUSH4 0x41c0e1b5 EQ PUSH @kill JUMPI     ; kill()
    DUP1 PUSH4 0x3ccfd60b EQ PUSH @withdraw JUMPI ; withdraw()
    PUSH1 0x00 DUP1 REVERT
    kill: JUMPDEST CALLER SELFDESTRUCT
    withdraw: JUMPDEST STOP
    """
)


def load_bytecode(name: str) -> bytes:
    return parse_hex((FIXTURES / "bytecode" / f"{name}.hex").read_text().strip())


def load_example(name: str) -> dict[str, Any]:
    return dict(json.loads((EXAMPLES / name).read_text()))


class FakeChain:
    """In-memory ChainReader backed by fixture bytecode."""

    def __init__(self, chain_id: int = 1) -> None:
        self.chain_id = chain_id
        self.code: dict[str, bytes] = {}
        self.storage: dict[tuple[str, int], bytes] = {}
        self.calls: dict[tuple[str, bytes], bytes] = {}
        self.requests: list[tuple[str, str]] = []
        self.fail = False

    def set_code(self, address: str, code: bytes) -> FakeChain:
        self.code[address.lower()] = code
        return self

    def get_code(self, address: str) -> bytes:
        self.requests.append(("code", address))
        if self.fail:
            raise RpcError("node down")
        return self.code.get(address.lower(), b"")

    def get_storage_at(self, address: str, slot: int) -> bytes:
        self.requests.append(("storage", address))
        return self.storage.get((address.lower(), slot), b"\0" * 32)

    def call(self, address: str, data: bytes) -> bytes:
        return self.calls.get((address.lower(), data), b"")


@pytest.fixture
def mainnet() -> FakeChain:
    chain = FakeChain(1)
    chain.set_code(USDC, load_bytecode("usdc_proxy"))
    chain.set_code(USDC_IMPL, load_bytecode("usdc_impl"))
    chain.storage[(USDC.lower(), ZEPPELINOS_SLOT)] = bytes(12) + bytes.fromhex(USDC_IMPL[2:])
    chain.set_code(WETH, load_bytecode("weth9"))
    chain.set_code(PERMIT2, load_bytecode("permit2"))
    chain.set_code(MULTICALL3, load_bytecode("multicall3"))
    return chain


@pytest.fixture
def intel() -> AddressIntel:
    return AddressIntel(
        denylist=load_address_list(ROOT / "config" / "denylist.example.txt"),
        address_book=load_address_list(ROOT / "config" / "address_book.example.txt"),
    )


@pytest.fixture
def make_ctx(mainnet: FakeChain, intel: AddressIntel):  # type: ignore[no-untyped-def]
    def factory(**kwargs: Any) -> AnalysisContext:
        kwargs.setdefault("chain_id", 1)
        kwargs.setdefault("reader", mainnet)
        kwargs.setdefault("intel", intel)
        kwargs.setdefault("now", 1_763_000_000)  # 2025-11-13, fixed for deterministic expiry checks
        return AnalysisContext(**kwargs)

    return factory


def rule_ids(report: Any) -> set[str]:
    findings = report["findings"] if isinstance(report, dict) else report.findings
    return {f["rule_id"] if isinstance(f, dict) else f.rule_id for f in findings}


def checksum(address: str) -> str:
    return to_checksum_address(address)
