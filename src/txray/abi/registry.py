"""Registry of function signatures txray understands.

Selectors are computed from the canonical signatures at import time instead of being
hard-coded, so a typo in a signature can never silently map to the wrong selector.

Each entry carries a ``tags`` set used by the rule engine and the bytecode profiler:

* ``approval``      grants a third party the right to move the caller's assets
* ``transfer``      moves assets out of the caller's account
* ``batch``         wraps further calls that must be decoded recursively
* ``privileged-*``  administrative capability (used when profiling contracts)
* ``drainer-name``  names that show up repeatedly in drainer kits ("SecurityUpdate"...);
                    a weak signal on its own, only used in combination with native value
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from txray.abi.types import FunctionSignature, parse_signature
from txray.hexutil import selector


@dataclass(frozen=True)
class KnownFunction:
    signature: FunctionSignature
    selector: bytes
    standard: str
    tags: frozenset[str]

    @property
    def canonical(self) -> str:
        return self.signature.canonical


# (signature, argument names, standard, tags)
_ENTRIES: list[tuple[str, tuple[str, ...], str, tuple[str, ...]]] = [
    # ERC-20
    ("transfer(address,uint256)", ("to", "amount"), "ERC-20", ("transfer",)),
    (
        "transferFrom(address,address,uint256)",
        ("from", "to", "amount"),
        "ERC-20/721",
        ("transfer",),
    ),
    ("approve(address,uint256)", ("spender", "amount"), "ERC-20/721", ("approval",)),
    ("increaseAllowance(address,uint256)", ("spender", "addedValue"), "ERC-20", ("approval",)),
    ("decreaseAllowance(address,uint256)", ("spender", "subtractedValue"), "ERC-20", ()),
    (
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        ("owner", "spender", "value", "deadline", "v", "r", "s"),
        "ERC-2612",
        ("approval",),
    ),
    # ERC-721 / ERC-1155
    ("setApprovalForAll(address,bool)", ("operator", "approved"), "ERC-721/1155", ("approval",)),
    (
        "safeTransferFrom(address,address,uint256)",
        ("from", "to", "tokenId"),
        "ERC-721",
        ("transfer",),
    ),
    (
        "safeTransferFrom(address,address,uint256,bytes)",
        ("from", "to", "tokenId", "data"),
        "ERC-721",
        ("transfer",),
    ),
    (
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        ("from", "to", "id", "amount", "data"),
        "ERC-1155",
        ("transfer",),
    ),
    (
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
        ("from", "to", "ids", "amounts", "data"),
        "ERC-1155",
        ("transfer",),
    ),
    # Uniswap Permit2 (AllowanceTransfer)
    (
        "approve(address,address,uint160,uint48)",
        ("token", "spender", "amount", "expiration"),
        "Permit2",
        ("approval",),
    ),
    ("lockdown((address,address)[])", ("approvals",), "Permit2", ()),
    ("invalidateNonces(address,address,uint48)", ("token", "spender", "newNonce"), "Permit2", ()),
    # WETH
    ("deposit()", (), "WETH", ()),
    ("withdraw(uint256)", ("wad",), "WETH", ()),
    # Batching
    ("multicall(bytes[])", ("data",), "Multicall", ("batch",)),
    ("multicall(uint256,bytes[])", ("deadline", "data"), "Multicall", ("batch",)),
    ("multicall(bytes32,bytes[])", ("previousBlockhash", "data"), "Multicall", ("batch",)),
    ("aggregate((address,bytes)[])", ("calls",), "Multicall3", ("batch",)),
    ("tryAggregate(bool,(address,bytes)[])", ("requireSuccess", "calls"), "Multicall3", ("batch",)),
    ("aggregate3((address,bool,bytes)[])", ("calls",), "Multicall3", ("batch",)),
    ("aggregate3Value((address,bool,uint256,bytes)[])", ("calls",), "Multicall3", ("batch",)),
    # Remaining Permit2 entry points (named so profiles and decoded calls are readable).
    (
        "transferFrom(address,address,uint160,address)",
        ("from", "to", "amount", "token"),
        "Permit2",
        ("transfer",),
    ),
    ("transferFrom((address,address,uint160,address)[])", ("transferDetails",), "Permit2", ()),
    (
        "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
        ("owner", "permitSingle", "signature"),
        "Permit2",
        ("approval",),
    ),
    (
        "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
        ("owner", "permitBatch", "signature"),
        "Permit2",
        ("approval",),
    ),
    (
        "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)",
        ("permit", "transferDetails", "owner", "signature"),
        "Permit2",
        ("transfer",),
    ),
    (
        "permitTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes)",
        ("permit", "transferDetails", "owner", "signature"),
        "Permit2",
        ("transfer",),
    ),
    (
        "permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,"
        "bytes32,string,bytes)",
        ("permit", "transferDetails", "owner", "witness", "witnessTypeString", "signature"),
        "Permit2",
        ("transfer",),
    ),
    (
        "permitWitnessTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],"
        "address,bytes32,string,bytes)",
        ("permit", "transferDetails", "owner", "witness", "witnessTypeString", "signature"),
        "Permit2",
        ("transfer",),
    ),
    ("allowance(address,address,address)", ("owner", "token", "spender"), "Permit2", ()),
    ("nonceBitmap(address,uint256)", ("owner", "wordPos"), "Permit2", ()),
    ("invalidateUnorderedNonces(uint256,uint256)", ("wordPos", "mask"), "Permit2", ()),
    # Read-only functions, for readable bytecode profiles.
    ("name()", (), "view", ()),
    ("symbol()", (), "view", ()),
    ("decimals()", (), "view", ()),
    ("totalSupply()", (), "view", ()),
    ("balanceOf(address)", ("account",), "view", ()),
    ("allowance(address,address)", ("owner", "spender"), "view", ()),
    ("nonces(address)", ("owner",), "view", ()),
    ("DOMAIN_SEPARATOR()", (), "view", ()),
    ("ownerOf(uint256)", ("tokenId",), "view", ()),
    ("getApproved(uint256)", ("tokenId",), "view", ()),
    ("isApprovedForAll(address,address)", ("owner", "operator"), "view", ()),
    ("supportsInterface(bytes4)", ("interfaceId",), "view", ()),
    ("owner()", (), "view", ()),
    ("implementation()", (), "view", ()),
    ("admin()", (), "view", ()),
    # Administrative capabilities, used to profile target contracts.
    ("mint(address,uint256)", ("to", "amount"), "admin", ("privileged-mint",)),
    ("mint(uint256)", ("amount",), "admin", ("privileged-mint",)),
    ("configureMinter(address,uint256)", ("minter", "allowance"), "admin", ("privileged-mint",)),
    ("burn(address,uint256)", ("from", "amount"), "admin", ("privileged-burn",)),
    ("pause()", (), "admin", ("privileged-pause",)),
    ("unpause()", (), "admin", ("privileged-pause",)),
    ("blacklist(address)", ("account",), "admin", ("privileged-blacklist",)),
    ("addBlackList(address)", ("account",), "admin", ("privileged-blacklist",)),
    ("setBots(address[])", ("bots",), "admin", ("privileged-blacklist",)),
    ("destroyBlackFunds(address)", ("account",), "admin", ("privileged-blacklist",)),
    ("setFee(uint256)", ("fee",), "admin", ("privileged-fee",)),
    ("setTaxFeePercent(uint256)", ("fee",), "admin", ("privileged-fee",)),
    ("setFees(uint256,uint256)", ("buy", "sell"), "admin", ("privileged-fee",)),
    ("setMaxTxAmount(uint256)", ("amount",), "admin", ("privileged-limits",)),
    ("excludeFromFee(address)", ("account",), "admin", ("privileged-fee",)),
    ("openTrading()", (), "admin", ("privileged-trading",)),
    ("enableTrading()", (), "admin", ("privileged-trading",)),
    ("setTradingEnabled(bool)", ("enabled",), "admin", ("privileged-trading",)),
    ("upgradeTo(address)", ("implementation",), "admin", ("privileged-upgrade",)),
    (
        "upgradeToAndCall(address,bytes)",
        ("implementation", "data"),
        "admin",
        ("privileged-upgrade",),
    ),
    ("changeAdmin(address)", ("admin",), "admin", ("privileged-upgrade",)),
    ("transferOwnership(address)", ("newOwner",), "admin", ("privileged-ownership",)),
    ("renounceOwnership()", (), "admin", ("privileged-ownership",)),
    (
        "rescueERC20(address,address,uint256)",
        ("token", "to", "amount"),
        "admin",
        ("privileged-withdraw",),
    ),
    ("kill()", (), "admin", ("privileged-destroy",)),
    ("destroy()", (), "admin", ("privileged-destroy",)),
    # Names that recur in drainer contracts deployed for "claim"/"airdrop" lures.
    ("Claim()", (), "suspicious", ("drainer-name",)),
    ("ClaimReward()", (), "suspicious", ("drainer-name",)),
    ("ClaimRewards()", (), "suspicious", ("drainer-name",)),
    ("SecurityUpdate()", (), "suspicious", ("drainer-name",)),
    ("Connect()", (), "suspicious", ("drainer-name",)),
    ("Execute()", (), "suspicious", ("drainer-name",)),
    ("Multicall()", (), "suspicious", ("drainer-name",)),
    ("Swap()", (), "suspicious", ("drainer-name",)),
    ("NetworkMerge()", (), "suspicious", ("drainer-name",)),
]


class FunctionRegistry:
    def __init__(self) -> None:
        self._by_selector: dict[bytes, list[KnownFunction]] = {}
        for sig, names, standard, tags in _ENTRIES:
            fn = parse_signature(sig, names)
            known = KnownFunction(fn, selector(fn.canonical), standard, frozenset(tags))
            self._by_selector.setdefault(known.selector, []).append(known)

    def lookup(self, sel: bytes) -> list[KnownFunction]:
        return list(self._by_selector.get(sel, ()))

    def first(self, sel: bytes) -> KnownFunction | None:
        found = self._by_selector.get(sel)
        return found[0] if found else None

    def by_name(self, canonical: str) -> KnownFunction:
        sel = selector(canonical)
        for fn in self._by_selector.get(sel, ()):
            if fn.canonical == canonical:
                return fn
        raise KeyError(canonical)

    def __iter__(self) -> Iterator[KnownFunction]:
        for fns in self._by_selector.values():
            yield from fns


REGISTRY = FunctionRegistry()
