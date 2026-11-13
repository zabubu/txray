from typing import Any

from tests.conftest import (
    ATTACKER,
    EOA,
    MULTICALL3,
    PERMIT2,
    SELFDESTRUCT_CONTRACT,
    USDC,
    USDC_IMPL,
    VICTIM,
    WETH,
    FakeChain,
    rule_ids,
)
from txray.abi import REGISTRY, encode
from txray.analysis.transaction import TxRequest, analyze_transaction, decode_call
from txray.evm.disassembler import assemble
from txray.hexutil import UINT256_MAX, selector
from txray.models import Severity, Verdict

UNIVERSAL_ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
OPENSEA_CONDUIT = "0x1E0049783F008A0085193E00003D00cd54003c71"
TRUSTED = "0x9f3C8d1Ae6B04C7F5a2D93B8E1C6F0A4d7e2b5c1"
POISONED = "0x9f3c4E7B1a90d2C6F83b5e0a71d94C2B8F6eb5C1"
NFT = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D"


def call(signature: str, *args: Any) -> bytes:
    fn = REGISTRY.by_name(signature)
    return fn.selector + encode(fn.signature.inputs, list(args))


def run(make_ctx: Any, to: str | None, data: bytes = b"", value: int = 0, **ctx: Any) -> Any:
    return analyze_transaction(
        TxRequest(to=to, data=data, value=value, sender=VICTIM), make_ctx(**ctx)
    )


def test_decode_call_unknown_and_short() -> None:
    assert decode_call(USDC, b"\x01\x02")[0].selector is None
    unknown, malformed = decode_call(USDC, b"\xde\xad\xbe\xef")
    assert unknown.function is None
    assert not malformed


def test_known_selector_with_bad_args_is_flagged(make_ctx: Any) -> None:
    data = selector("transfer(address,uint256)") + b"\x01" * 10
    assert "TX012" in rule_ids(run(make_ctx, USDC, data))


def test_unlimited_approval_to_eoa_on_proxied_token(make_ctx: Any) -> None:
    report = run(make_ctx, USDC, call("approve(address,uint256)", EOA, UINT256_MAX))
    assert {"TX001", "TX002"} <= rule_ids(report)
    tx002 = next(f for f in report.findings if f.rule_id == "TX002")
    assert tx002.severity is Severity.CRITICAL
    assert report.verdict is Verdict.BLOCK
    # Proxy resolved to the implementation, whose governance findings are capped at LOW.
    assert any(USDC_IMPL in n for n in report.notes)
    bc006 = next(f for f in report.findings if f.rule_id == "BC006")
    assert bc006.severity is Severity.LOW


def test_unlimited_approval_to_known_router_is_low(make_ctx: Any, mainnet: FakeChain) -> None:
    mainnet.set_code(UNIVERSAL_ROUTER, b"\x60\x00")
    report = run(make_ctx, WETH, call("approve(address,uint256)", UNIVERSAL_ROUTER, UINT256_MAX))
    tx001 = next(f for f in report.findings if f.rule_id == "TX001")
    assert tx001.severity is Severity.LOW
    assert report.verdict is Verdict.PASS


def test_set_approval_for_all(make_ctx: Any, mainnet: FakeChain) -> None:
    nft_code = assemble(
        """
        PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
        DUP1 PUSH4 0xa22cb465 EQ PUSH @a JUMPI
        DUP1 PUSH4 0x6352211e EQ PUSH @a JUMPI
        PUSH1 0 DUP1 REVERT
        a: JUMPDEST STOP
        """
    )
    mainnet.set_code(NFT, nft_code)
    mainnet.set_code(OPENSEA_CONDUIT, b"\x60\x00")
    to_eoa = run(make_ctx, NFT, call("setApprovalForAll(address,bool)", EOA, True))
    assert next(f for f in to_eoa.findings if f.rule_id == "TX003").severity is Severity.CRITICAL
    to_conduit = run(make_ctx, NFT, call("setApprovalForAll(address,bool)", OPENSEA_CONDUIT, True))
    assert next(f for f in to_conduit.findings if f.rule_id == "TX003").severity is Severity.LOW
    revoke = run(make_ctx, NFT, call("setApprovalForAll(address,bool)", EOA, False))
    assert "TX003" not in rule_ids(revoke)
    # approve(address,uint256) on an NFT is a single-token approval, not an allowance.
    single = run(make_ctx, NFT, call("approve(address,uint256)", EOA, 2**255))
    assert "TX001" not in rule_ids(single)
    assert "TX002" in rule_ids(single)


def test_address_poisoning_on_transfer(make_ctx: Any) -> None:
    report = run(make_ctx, USDC, call("transfer(address,uint256)", POISONED, 10**6))
    int002 = next(f for f in report.findings if f.rule_id == "INT002")
    assert int002.evidence["resembles"] == TRUSTED
    assert report.verdict is Verdict.BLOCK
    clean = run(make_ctx, USDC, call("transfer(address,uint256)", TRUSTED, 10**6))
    assert "INT002" not in rule_ids(clean)


def test_transfer_to_token_contract(make_ctx: Any) -> None:
    assert "TX007" in rule_ids(run(make_ctx, WETH, call("transfer(address,uint256)", WETH, 1)))


def test_denylisted_destination(make_ctx: Any) -> None:
    report = run(make_ctx, ATTACKER, b"", value=10**18)
    assert "INT001" in rule_ids(report)


def test_selector_missing_from_dispatcher(make_ctx: Any) -> None:
    data = selector("Claim()")
    report = run(make_ctx, WETH, data, value=10**17)
    tx005 = next(f for f in report.findings if f.rule_id == "TX005")
    assert tx005.severity is Severity.HIGH  # value attached


def test_drainer_named_function_with_value(make_ctx: Any, mainnet: FakeChain) -> None:
    drainer = assemble(
        """
        PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
        DUP1 PUSH4 0x5fa7b584 EQ PUSH @f JUMPI
        PUSH1 0 DUP1 REVERT
        f: JUMPDEST STOP
        """.replace("0x5fa7b584", "0x" + selector("SecurityUpdate()").hex())
    )
    target = "0x00000000000000000000000000000000000Dead1"
    mainnet.set_code(target, drainer)
    report = run(make_ctx, target.lower(), selector("SecurityUpdate()"), value=10**18)
    assert "TX006" in rule_ids(report)
    assert "TX005" not in rule_ids(report)


def test_function_reaching_selfdestruct(make_ctx: Any, mainnet: FakeChain) -> None:
    target = "0x000000000000000000000000000000000000bEEF"
    mainnet.set_code(target, SELFDESTRUCT_CONTRACT)
    assert "TX009" in rule_ids(run(make_ctx, target, selector("kill()")))
    assert "TX009" not in rule_ids(run(make_ctx, target, selector("withdraw()")))


def test_calldata_to_eoa(make_ctx: Any) -> None:
    report = run(make_ctx, EOA, b"hello")
    assert "TX008" in rule_ids(report)


def test_contract_creation(make_ctx: Any) -> None:
    report = run(make_ctx, None, b"\x60\x00")
    assert rule_ids(report) == {"TX010"}


def test_multicall3_inner_calls_are_analyzed(make_ctx: Any) -> None:
    inner = [
        (USDC, False, call("approve(address,uint256)", EOA, UINT256_MAX)),
        (WETH, True, call("transfer(address,uint256)", POISONED, 1)),
    ]
    report = run(make_ctx, MULTICALL3, call("aggregate3((address,bool,bytes)[])", inner))
    assert {"TX011", "TX001", "TX002", "INT002"} <= rule_ids(report)
    decoded = report.decoded["call"]
    assert [c["function"] for c in decoded["inner"]] == [
        "approve(address,uint256)",
        "transfer(address,uint256)",
    ]


def test_permit2_onchain_approve(make_ctx: Any) -> None:
    data = call("approve(address,address,uint160,uint48)", USDC, EOA, 2**160 - 1, 2**48 - 1)
    report = run(make_ctx, PERMIT2, data)
    assert {"TX004", "TX002"} <= rule_ids(report)


def test_offline_mode_notes(make_ctx: Any) -> None:
    report = run(make_ctx, USDC, call("approve(address,uint256)", EOA, 5), reader=None)
    assert "TX002" not in rule_ids(report)  # cannot know that EOA has no code
    assert any("on-chain checks skipped" in n for n in report.notes)


def test_rpc_failure_degrades_gracefully(make_ctx: Any, mainnet: FakeChain) -> None:
    mainnet.fail = True
    report = run(make_ctx, USDC, call("approve(address,uint256)", EOA, UINT256_MAX))
    assert "TX001" in rule_ids(report)
    assert any("RPC error" in n for n in report.notes)


def test_drainer_name_flagged_offline(make_ctx: Any) -> None:
    report = run(make_ctx, ATTACKER, selector("SecurityUpdate()"), value=1, reader=None)
    assert "TX006" in rule_ids(report)


def test_dynamic_delegatecall_disables_missing_selector_rule(
    make_ctx: Any, mainnet: FakeChain
) -> None:
    # Dispatcher knows one selector; the fallback delegates to a storage-loaded address.
    forwarder = assemble(
        """
        PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
        DUP1 PUSH4 0x11223344 EQ PUSH @f JUMPI
        PUSH1 0 DUP1 DUP1 DUP1 PUSH1 0 SLOAD GAS DELEGATECALL STOP
        f: JUMPDEST STOP
        """
    )
    target = "0x000000000000000000000000000000000000f0F0"
    mainnet.set_code(target, forwarder)
    report = run(make_ctx, target, selector("transfer(address,uint256)") + bytes(64))
    assert "TX005" not in rule_ids(report)
    assert "BC002" in rule_ids(report)
