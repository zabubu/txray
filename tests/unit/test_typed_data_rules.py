import copy
from typing import Any

import pytest

from tests.conftest import ATTACKER, EOA, PERMIT2, USDC, VICTIM, FakeChain, load_example, rule_ids
from txray.analysis.typed_data import analyze_typed_data, classify
from txray.eip712 import parse_typed_data
from txray.errors import TypedDataError
from txray.models import Severity, Verdict

UNIVERSAL_ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"


def test_classification_of_examples() -> None:
    assert (
        classify(parse_typed_data(load_example("permit2-batch-sweep.json"))) == "permit2-allowance"
    )
    assert (
        classify(parse_typed_data(load_example("seaport-zero-price-listing.json")))
        == "seaport-order"
    )
    assert (
        classify(parse_typed_data(load_example("erc2612-unlimited-permit.json")))
        == "erc2612-permit"
    )


def test_permit2_batch_sweep(make_ctx: Any) -> None:
    report = analyze_typed_data(load_example("permit2-batch-sweep.json"), make_ctx())
    assert {"SIG020", "SIG021", "SIG011", "SIG013", "INT001"} <= rule_ids(report)
    assert report.verdict is Verdict.BLOCK
    # The four long-lived allowances are reported once, not per token.
    assert sum(f.rule_id == "SIG013" for f in report.findings) == 1


def test_permit2_to_known_router_is_low(make_ctx: Any, mainnet: FakeChain) -> None:
    mainnet.set_code(UNIVERSAL_ROUTER, b"\x60\x00")
    raw = load_example("permit2-batch-sweep.json")
    raw["message"]["spender"] = UNIVERSAL_ROUTER
    raw["message"]["details"] = raw["message"]["details"][:1]
    raw["message"]["details"][0]["expiration"] = str(1_763_000_000 + 3600)
    raw["message"]["details"][0]["amount"] = "1000000"
    report = analyze_typed_data(raw, make_ctx())
    assert report.verdict is Verdict.PASS
    sig020 = next(f for f in report.findings if f.rule_id == "SIG020")
    assert sig020.severity is Severity.LOW
    assert sig020.evidence["spender_label"] == "Uniswap Universal Router"


def test_permit2_impersonation(make_ctx: Any) -> None:
    raw = load_example("permit2-batch-sweep.json")
    raw["domain"]["verifyingContract"] = ATTACKER
    assert "SIG003" in rule_ids(analyze_typed_data(raw, make_ctx()))


def test_seaport_zero_price_listing(make_ctx: Any) -> None:
    report = analyze_typed_data(load_example("seaport-zero-price-listing.json"), make_ctx())
    sig030 = next(f for f in report.findings if f.rule_id == "SIG030")
    assert sig030.severity is Severity.CRITICAL
    assert sig030.evidence["recipients"] == [ATTACKER]
    assert len(sig030.evidence["offered"]) == 2


def test_seaport_fair_listing_passes(make_ctx: Any, mainnet: FakeChain) -> None:
    raw = load_example("seaport-zero-price-listing.json")
    raw["message"]["consideration"] = [
        {
            "itemType": "0",
            "token": "0x0000000000000000000000000000000000000000",
            "identifierOrCriteria": "0",
            "startAmount": str(10**19),
            "endAmount": str(10**19),
            "recipient": VICTIM,
        }
    ]
    report = analyze_typed_data(raw, make_ctx(reader=None))
    assert "SIG030" not in rule_ids(report)
    assert report.verdict is Verdict.PASS


def test_seaport_bulk_order(make_ctx: Any) -> None:
    single = load_example("seaport-zero-price-listing.json")
    bulk = copy.deepcopy(single)
    bulk["primaryType"] = "BulkOrder"
    bulk["types"]["BulkOrder"] = [{"name": "tree", "type": "OrderComponents[2][2]"}]
    order = single["message"]
    bulk["message"] = {"tree": [[order, order], [order, order]]}
    report = analyze_typed_data(bulk, make_ctx(reader=None))
    assert "SIG031" in rule_ids(report)
    assert len(report.decoded["summary"]["orders"]) == 4


def test_erc2612_unlimited_permit_to_eoa(make_ctx: Any) -> None:
    raw = load_example("erc2612-unlimited-permit.json")
    raw["message"]["spender"] = EOA
    report = analyze_typed_data(raw, make_ctx())
    assert {"SIG010", "SIG011", "SIG012", "SIG013"} <= rule_ids(report)
    assert report.verdict is Verdict.BLOCK


def test_chain_mismatch(make_ctx: Any) -> None:
    raw = load_example("erc2612-unlimited-permit.json")
    raw["domain"]["chainId"] = 137
    assert "SIG001" in rule_ids(analyze_typed_data(raw, make_ctx(reader=None)))


def test_verifying_contract_without_code(make_ctx: Any) -> None:
    raw = load_example("erc2612-unlimited-permit.json")
    raw["domain"]["verifyingContract"] = EOA
    assert "SIG002" in rule_ids(analyze_typed_data(raw, make_ctx()))


def test_dai_permit(make_ctx: Any) -> None:
    raw = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "holder", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "expiry", "type": "uint256"},
                {"name": "allowed", "type": "bool"},
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Dai Stablecoin",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        },
        "message": {
            "holder": VICTIM,
            "spender": ATTACKER,
            "nonce": 0,
            "expiry": 0,
            "allowed": True,
        },
    }
    report = analyze_typed_data(raw, make_ctx(reader=None))
    assert {"SIG010", "SIG011", "SIG013"} <= rule_ids(report)
    raw["message"]["allowed"] = False
    assert "SIG011" not in rule_ids(analyze_typed_data(raw, make_ctx(reader=None)))


def test_permit2_signature_transfer(make_ctx: Any) -> None:
    raw = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PermitTransferFrom": [
                {"name": "permitted", "type": "TokenPermissions"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
            "TokenPermissions": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
        },
        "primaryType": "PermitTransferFrom",
        "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2},
        "message": {
            "permitted": {"token": USDC, "amount": "5000000000"},
            "spender": EOA,
            "nonce": "1",
            "deadline": "1763000600",
        },
    }
    report = analyze_typed_data(raw, make_ctx())
    assert {"SIG022", "SIG012"} <= rule_ids(report)


def test_generic_permission_fields(make_ctx: Any) -> None:
    raw = {
        "types": {"Delegation": [{"name": "delegatee", "type": "address"}]},
        "primaryType": "Delegation",
        "domain": {"name": "Some DAO", "chainId": 1},
        "message": {"delegatee": EOA},
    }
    assert "SIG040" in rule_ids(analyze_typed_data(raw, make_ctx(reader=None)))


def test_digest_is_reported(make_ctx: Any) -> None:
    report = analyze_typed_data(load_example("permit2-batch-sweep.json"), make_ctx(reader=None))
    assert report.decoded["digest"].startswith("0x")
    assert len(report.decoded["digest"]) == 66


def test_missing_message_field_is_input_error(make_ctx: Any) -> None:
    raw = load_example("erc2612-unlimited-permit.json")
    del raw["message"]["spender"]
    with pytest.raises(TypedDataError):
        analyze_typed_data(raw, make_ctx(reader=None))
