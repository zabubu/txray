"""Address intelligence: known protocol deployments, denylist, address book.

The bundled protocol list is intentionally short: only contracts whose addresses were
verified on Ethereum mainnet and that the rules need (Permit2, Seaport, routers that
legitimately receive approvals). Deterministic CREATE2 deployments that share one
address across chains are registered for every chain (``chains=None``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from txray.errors import ConfigError, InvalidInputError
from txray.hexutil import normalize_address


@dataclass(frozen=True)
class KnownContract:
    address: str
    label: str
    kind: str  # permit2 | seaport | conduit | router | multicall | token
    chains: frozenset[int] | None = None  # None: same address on every chain


_KNOWN: list[KnownContract] = [
    KnownContract("0x000000000022D473030F116dDEE9F6B43aC78BA3", "Uniswap Permit2", "permit2"),
    KnownContract("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "Seaport 1.5", "seaport"),
    KnownContract("0x0000000000000068F116a894984e2DB1123eB395", "Seaport 1.6", "seaport"),
    KnownContract("0x1E0049783F008A0085193E00003D00cd54003c71", "OpenSea Conduit", "conduit"),
    KnownContract("0xcA11bde05977b3631167028862bE2a173976CA11", "Multicall3", "multicall"),
    KnownContract(
        "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
        "Uniswap Universal Router",
        "router",
        frozenset({1}),
    ),
    KnownContract(
        "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
        "Uniswap Universal Router (v4)",
        "router",
        frozenset({1}),
    ),
    KnownContract(
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "Uniswap V2 Router02",
        "router",
        frozenset({1}),
    ),
    KnownContract(
        "0x1111111254EEB25477B68fb85Ed929f73A960582",
        "1inch Aggregation Router v5",
        "router",
        frozenset({1}),
    ),
    KnownContract(
        "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",
        "0x Exchange Proxy",
        "router",
        frozenset({1}),
    ),
    KnownContract(
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "Wrapped Ether", "token", frozenset({1})
    ),
]

PERMIT2 = _KNOWN[0].address
SEAPORT_ADDRESSES = frozenset(k.address for k in _KNOWN if k.kind == "seaport")


def parse_address_list(text: str, *, source: str = "list") -> dict[str, str]:
    """Parse ``address[,label]`` lines; ``#`` starts a comment."""
    out: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        addr, _, label = line.partition(",")
        try:
            checksummed = normalize_address(addr.strip(), field=f"{source}:{lineno}")
        except InvalidInputError as exc:
            raise ConfigError(str(exc)) from exc
        out[checksummed] = label.strip() or checksummed
    return out


def load_address_list(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        return parse_address_list(path.read_text(encoding="utf-8"), source=path.name)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def _common_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


@dataclass(frozen=True)
class Lookalike:
    address: str
    resembles: str
    label: str
    prefix: int
    suffix: int


def find_lookalike(address: str, trusted: dict[str, str]) -> Lookalike | None:
    """Detect vanity look-alikes of trusted addresses (address poisoning).

    Wallets usually display ``0x1234…abcd``; poisoning addresses are brute-forced to
    match those visible characters. Requiring at least 8 matching characters split over
    both ends keeps the accidental match probability around 16**-8 per pair.
    """
    body = address.lower()[2:]
    best: Lookalike | None = None
    for candidate, label in trusted.items():
        other = candidate.lower()[2:]
        if other == body:
            return None  # it *is* a trusted address
        prefix = _common_prefix(body, other)
        suffix = _common_prefix(body[::-1], other[::-1])
        close = prefix >= 3 and suffix >= 3 and prefix + suffix >= 8
        if close and (best is None or prefix + suffix > best.prefix + best.suffix):
            best = Lookalike(address, candidate, label, prefix, suffix)
    return best


@dataclass
class AddressIntel:
    denylist: dict[str, str] = field(default_factory=dict)
    address_book: dict[str, str] = field(default_factory=dict)
    known: list[KnownContract] = field(default_factory=lambda: list(_KNOWN))

    def known_contract(self, address: str, chain_id: int | None) -> KnownContract | None:
        target = address.lower()
        for k in self.known:
            if k.address.lower() == target and (
                k.chains is None or chain_id is None or chain_id in k.chains
            ):
                return k
        return None

    def denylisted(self, address: str) -> str | None:
        for addr, label in self.denylist.items():
            if addr.lower() == address.lower():
                return label
        return None

    def lookalike(self, address: str) -> Lookalike | None:
        trusted = dict(self.address_book)
        for k in self.known:
            trusted.setdefault(k.address, k.label)
        return find_lookalike(address, trusted)
