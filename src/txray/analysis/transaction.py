"""Analysis of a transaction request (``eth_sendTransaction`` parameters)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from txray.abi.codec import decode
from txray.abi.registry import REGISTRY, KnownFunction
from txray.analysis.context import THIRTY_DAYS, AnalysisContext, jsonable
from txray.errors import AbiDecodingError
from txray.hexutil import UINT256_MAX, selector, to_hex
from txray.intel import PERMIT2
from txray.models import Finding, Report, Severity
from txray.rules import finding

MAX_BATCH_DEPTH = 3
UNLIMITED_THRESHOLD = 1 << 255  # some front-ends use 2**255 or 2**256-1 as "infinite"
UINT160_MAX = (1 << 160) - 1
NFT_HINT_SELECTORS = frozenset(
    {selector("ownerOf(uint256)"), selector("setApprovalForAll(address,bool)")}
)
# Profile findings that are about the contract's governance rather than the call itself
# are downgraded in transaction context, otherwise every stablecoin transfer would warn.
_TX_CONTEXT_CAPS = {"BC005": Severity.LOW, "BC006": Severity.LOW}
_TX_CONTEXT_SKIP = {"BC008", "BC009", "BC010"}


@dataclass
class TxRequest:
    to: str | None
    data: bytes = b""
    value: int = 0
    sender: str | None = None


@dataclass
class DecodedCall:
    target: str
    selector: str | None
    function: KnownFunction | None = None
    args: dict[str, Any] = field(default_factory=dict)
    inner: list[DecodedCall] = field(default_factory=list)
    value: int = 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "target": self.target,
            "selector": self.selector,
            "function": self.function.canonical if self.function else None,
            "standard": self.function.standard if self.function else None,
            "args": jsonable(self.args),
            "value": str(self.value),
        }
        if self.inner:
            out["inner"] = [c.to_dict() for c in self.inner]
        return out


def decode_call(target: str, data: bytes, value: int = 0) -> tuple[DecodedCall, bool]:
    """Decode calldata against the registry.

    Returns the call and whether a known selector failed to decode (TX012).
    """
    if len(data) < 4:
        return DecodedCall(target, None, value=value), False
    sel = data[:4]
    call = DecodedCall(target, to_hex(sel), value=value)
    candidates = REGISTRY.lookup(sel)
    for fn in candidates:
        try:
            values = decode(fn.signature.inputs, data[4:])
        except AbiDecodingError:
            continue
        call.function = fn
        call.args = dict(zip(fn.signature.arg_names, values, strict=True))
        return call, False
    return call, bool(candidates)


def _inner_calls(call: DecodedCall) -> list[tuple[str, bytes, int]]:
    """(target, calldata, value) of each call wrapped by a batching function."""
    assert call.function is not None
    name = call.function.signature.name
    if name == "multicall":
        return [(call.target, d, 0) for d in call.args["data"]]
    if name == "aggregate":
        return [(t, d, 0) for t, d in call.args["calls"]]
    if name == "tryAggregate":
        return [(t, d, 0) for t, d in call.args["calls"]]
    if name == "aggregate3":
        return [(t, d, 0) for t, _allow, d in call.args["calls"]]
    if name == "aggregate3Value":
        return [(t, d, v) for t, _allow, v, d in call.args["calls"]]
    return []


class TransactionAnalyzer:
    def __init__(self, ctx: AnalysisContext) -> None:
        self.ctx = ctx
        self.findings: list[Finding] = []

    def run(self, tx: TxRequest) -> Report:
        ctx = self.ctx
        report = Report(kind="transaction", chain_id=ctx.chain_id)
        if tx.to is None:
            self.findings.append(
                finding("TX010", f"Contract creation with {len(tx.data)} bytes of init code.")
            )
            report.decoded = {"to": None, "value": str(tx.value), "init_code_size": len(tx.data)}
            return self._finish(report)

        self.findings += ctx.address_findings(tx.to, "destination")
        call, malformed = decode_call(tx.to, tx.data, tx.value)
        if malformed:
            self.findings.append(
                finding(
                    "TX012",
                    f"Selector {call.selector} is known but its arguments do not decode.",
                    selector=call.selector,
                )
            )
        if call.function and "drainer-name" in call.function.tags and tx.value:
            self.findings.append(
                finding(
                    "TX006",
                    f"{tx.value} wei sent to {call.function.canonical}.",
                    function=call.function.canonical,
                )
            )
        self._target_checks(tx, call)
        self._call_rules(call, depth=0)
        report.decoded = {
            "from": tx.sender,
            "to": tx.to,
            "value": str(tx.value),
            "call": call.to_dict(),
            "target_label": ctx.known_label(tx.to),
        }
        return self._finish(report)

    def _finish(self, report: Report) -> Report:
        report.findings = self.findings
        report.notes = list(self.ctx.notes)
        return report

    # ----------------------------------------------------------------- target code
    def _target_checks(self, tx: TxRequest, call: DecodedCall) -> None:
        assert tx.to is not None
        resolved = self.ctx.resolve(tx.to)
        if resolved is None:
            return
        if not resolved.is_contract:
            if tx.data:
                self.findings.append(
                    finding(
                        "TX008",
                        f"{len(tx.data)} bytes of calldata sent to an account without code.",
                    )
                )
            return
        profile = resolved.effective_profile
        if resolved.implementation:
            self.ctx.note(
                f"{tx.to} is a {resolved.proxy_kind} proxy for {resolved.implementation}."
            )
        sources = [(tx.to, resolved.profile)]
        if resolved.implementation and resolved.implementation_profile is not None:
            sources.append((resolved.implementation, resolved.implementation_profile))
        for contract, source in sources:
            for f in source.findings:
                if f.rule_id in _TX_CONTEXT_SKIP:
                    continue
                capped = f.model_copy()
                cap = _TX_CONTEXT_CAPS.get(f.rule_id)
                if cap is not None and capped.severity > cap:
                    capped.severity = cap
                capped.evidence = {**f.evidence, "contract": contract}
                self.findings.append(capped)

        if call.selector is None:
            return
        sel = bytes.fromhex(call.selector[2:])
        implemented = profile.implements(sel)
        if implemented is False:
            self.findings.append(
                finding(
                    "TX005",
                    f"{call.selector} is not in the dispatcher of {tx.to}; "
                    "the fallback runs instead.",
                    severity=Severity.HIGH if tx.value else None,
                    selector=call.selector,
                )
            )
        fn = profile.function(sel)
        if fn is not None:
            dangerous = {"SELFDESTRUCT"} & fn.reaches
            if "DELEGATECALL" in fn.reaches and profile.dynamic_delegatecall:
                dangerous.add("DELEGATECALL")
            if dangerous:
                name = call.function.canonical if call.function else call.selector
                self.findings.append(
                    finding(
                        "TX009",
                        f"{name} can reach {', '.join(sorted(dangerous))}.",
                        opcodes=sorted(dangerous),
                    )
                )

    # ----------------------------------------------------------------- call rules
    def _call_rules(self, call: DecodedCall, depth: int) -> None:
        fn = call.function
        if fn is None:
            return
        name = fn.canonical
        args = call.args
        if "batch" in fn.tags:
            self._batch(call, depth)
        elif name == "approve(address,uint256)":
            self._erc20_or_721_approve(call)
        elif name == "increaseAllowance(address,uint256)":
            self._allowance(call, args["spender"], args["addedValue"])
        elif name == "setApprovalForAll(address,bool)":
            self._operator_approval(call)
        elif name == "approve(address,address,uint160,uint48)":
            self._permit2_approve(call)
        elif "transfer" in fn.tags and "to" in args:
            self._recipient(call, args["to"])

    def _batch(self, call: DecodedCall, depth: int) -> None:
        inner = _inner_calls(call)
        self.findings.append(
            finding(
                "TX011",
                f"{call.function.canonical if call.function else ''} wraps {len(inner)} call(s).",
                count=len(inner),
            )
        )
        if depth >= MAX_BATCH_DEPTH:
            self.ctx.note("Batch nesting deeper than 3 levels was not decoded.")
            return
        for target, data, value in inner:
            self.findings += self.ctx.address_findings(target, "inner call target")
            sub, malformed = decode_call(target, data, value)
            if malformed:
                self.findings.append(
                    finding(
                        "TX012",
                        f"Inner call selector {sub.selector} does not decode.",
                        selector=sub.selector,
                    )
                )
            call.inner.append(sub)
            self._call_rules(sub, depth + 1)

    def _recipient(self, call: DecodedCall, to: str) -> None:
        self.findings += self.ctx.address_findings(to, "recipient")
        if to.lower() == call.target.lower():
            self.findings.append(
                finding("TX007", f"Tokens are sent to the token contract {to} itself.", token=to)
            )

    def _is_nft(self, token: str) -> bool:
        resolved = self.ctx.resolve(token)
        if resolved is None or not resolved.is_contract:
            return False
        return bool(resolved.effective_profile.selectors & NFT_HINT_SELECTORS)

    def _erc20_or_721_approve(self, call: DecodedCall) -> None:
        spender, amount = call.args["spender"], call.args["amount"]
        if self._is_nft(call.target):
            self.findings += self.ctx.address_findings(spender, "approved address")
            if self.ctx.is_contract(spender) is False:
                self.findings.append(
                    finding(
                        "TX002",
                        f"NFT #{amount} approved to {spender}, which has no code.",
                        spender=spender,
                        token=call.target,
                    )
                )
            return
        self._allowance(call, spender, amount)

    def _allowance(self, call: DecodedCall, spender: str, amount: int) -> None:
        self.findings += self.ctx.address_findings(spender, "spender")
        known = self.ctx.known_label(spender)
        unlimited = amount >= UNLIMITED_THRESHOLD
        eoa = self.ctx.is_contract(spender) is False
        if unlimited:
            self.findings.append(
                finding(
                    "TX001",
                    f"Unlimited allowance for {known or spender} on {call.target}.",
                    severity=Severity.LOW if known else None,
                    spender=spender,
                    amount="max" if amount == UINT256_MAX else str(amount),
                )
            )
        if eoa and amount > 0:
            self.findings.append(
                finding(
                    "TX002",
                    f"Allowance on {call.target} granted to {spender}, an account without code.",
                    severity=Severity.CRITICAL if unlimited else None,
                    spender=spender,
                )
            )

    def _operator_approval(self, call: DecodedCall) -> None:
        operator, approved = call.args["operator"], call.args["approved"]
        if not approved:
            return
        self.findings += self.ctx.address_findings(operator, "operator")
        known = self.ctx.intel.known_contract(operator, self.ctx.chain_id)
        eoa = self.ctx.is_contract(operator) is False
        severity = None
        if eoa:
            severity = Severity.CRITICAL
        elif known and known.kind in ("conduit", "seaport"):
            severity = Severity.LOW
        self.findings.append(
            finding(
                "TX003",
                f"{known.label if known else operator} becomes operator of all tokens of "
                f"{call.target}" + (" (account without code)" if eoa else "") + ".",
                severity=severity,
                operator=operator,
                collection=call.target,
            )
        )

    def _permit2_approve(self, call: DecodedCall) -> None:
        if call.target.lower() != PERMIT2.lower():
            return
        spender, amount, expiration = (
            call.args["spender"],
            call.args["amount"],
            call.args["expiration"],
        )
        self.findings += self.ctx.address_findings(spender, "spender")
        reasons = []
        if amount >= UINT160_MAX:
            reasons.append("maximum amount")
        if expiration > self.ctx.now + THIRTY_DAYS:
            reasons.append(f"expires in {(expiration - self.ctx.now) // 86400} days")
        if reasons:
            self.findings.append(
                finding(
                    "TX004",
                    "Permit2 allowance with " + " and ".join(reasons) + ".",
                    token=call.args["token"],
                    spender=spender,
                )
            )
        if self.ctx.is_contract(spender) is False:
            self.findings.append(
                finding(
                    "TX002",
                    f"Permit2 allowance granted to {spender}, an account without code.",
                    spender=spender,
                )
            )


def analyze_transaction(tx: TxRequest, ctx: AnalysisContext) -> Report:
    return TransactionAnalyzer(ctx).run(tx)
