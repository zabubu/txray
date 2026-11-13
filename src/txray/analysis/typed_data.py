"""Analysis of EIP-712 signature requests (``eth_signTypedData_v4``)."""

from __future__ import annotations

from typing import Any

from txray.analysis.context import THIRTY_DAYS, AnalysisContext, collect_addresses
from txray.eip712 import TypedData, domain_separator, hash_struct, parse_typed_data, signing_digest
from txray.errors import InvalidInputError, TypedDataError
from txray.hexutil import UINT256_MAX, int_from_hex_or_dec, is_address, normalize_address, to_hex
from txray.intel import PERMIT2, SEAPORT_ADDRESSES
from txray.models import Finding, Report, Severity
from txray.rules import finding

UNLIMITED = 1 << 255
UINT160_MAX = (1 << 160) - 1
SEAPORT_ITEM_TYPES = {
    0: "NATIVE",
    1: "ERC20",
    2: "ERC721",
    3: "ERC1155",
    4: "ERC721_WITH_CRITERIA",
    5: "ERC1155_WITH_CRITERIA",
}
PERMISSION_FIELDS = {"spender", "operator", "delegate", "delegatee", "approved", "allowed"}
PERMIT2_ALLOWANCE = {"PermitSingle", "PermitBatch"}
PERMIT2_TRANSFER = {
    "PermitTransferFrom",
    "PermitBatchTransferFrom",
    "PermitWitnessTransferFrom",
    "PermitBatchWitnessTransferFrom",
}


def _int(value: Any, path: str) -> int:
    try:
        return int_from_hex_or_dec(value, field=path)
    except InvalidInputError as exc:
        raise TypedDataError(str(exc)) from exc


def _addr(value: Any, path: str) -> str:
    if not is_address(value):
        raise TypedDataError(f"{path}: invalid address")
    return normalize_address(value.lower(), field=path)


def classify(td: TypedData) -> str:
    fields = {n for n, _ in td.types[td.primary_type]}
    p = td.primary_type
    if p == "Permit" and {"owner", "spender", "value", "deadline"} <= fields:
        return "erc2612-permit"
    if p == "Permit" and {"holder", "spender", "expiry", "allowed"} <= fields:
        return "dai-permit"
    if p in PERMIT2_ALLOWANCE:
        return "permit2-allowance"
    if p in PERMIT2_TRANSFER:
        return "permit2-transfer"
    if p == "OrderComponents":
        return "seaport-order"
    if p == "BulkOrder":
        return "seaport-bulk-order"
    return "generic"


class TypedDataAnalyzer:
    def __init__(self, ctx: AnalysisContext) -> None:
        self.ctx = ctx
        self.findings: list[Finding] = []

    def run(self, raw: dict[str, Any] | str) -> Report:
        td = parse_typed_data(raw)
        digest = signing_digest(td)
        kind = classify(td)
        report = Report(kind="typed_data", chain_id=self.ctx.chain_id)
        report.decoded = {
            "primary_type": td.primary_type,
            "classification": kind,
            "domain": td.domain,
            "domain_separator": to_hex(domain_separator(td)),
            "message_hash": None
            if td.primary_type == "EIP712Domain"
            else to_hex(hash_struct(td.primary_type, td.message, td.types)),
            "digest": to_hex(digest),
        }
        self._domain(td, kind)
        handler = {
            "erc2612-permit": self._erc2612,
            "dai-permit": self._dai,
            "permit2-allowance": self._permit2_allowance,
            "permit2-transfer": self._permit2_transfer,
            "seaport-order": self._seaport_order,
            "seaport-bulk-order": self._seaport_bulk,
            "generic": self._generic,
        }[kind]
        summary = handler(td)
        if summary:
            report.decoded["summary"] = summary
        for path, address in collect_addresses(td.message, "message"):
            self.findings += self.ctx.address_findings(address, path)
        report.findings = self.findings
        report.notes = list(self.ctx.notes)
        return report

    # ------------------------------------------------------------------ domain
    def _domain(self, td: TypedData, kind: str) -> None:
        try:
            chain = td.domain_chain_id
            vc = td.verifying_contract
        except InvalidInputError as exc:
            raise TypedDataError(str(exc)) from exc
        if chain is not None and self.ctx.chain_id is not None and chain != self.ctx.chain_id:
            self.findings.append(
                finding(
                    "SIG001",
                    f"Domain chainId {chain}, wallet is on chain {self.ctx.chain_id}.",
                    domain_chain_id=chain,
                    wallet_chain_id=self.ctx.chain_id,
                )
            )
        name = str(td.domain.get("name", ""))
        expected: frozenset[str] | None = None
        if name == "Permit2" or kind.startswith("permit2"):
            expected = frozenset({PERMIT2})
        elif name == "Seaport" or kind.startswith("seaport"):
            expected = SEAPORT_ADDRESSES
        if expected is not None and vc is not None and vc not in expected:
            self.findings.append(
                finding(
                    "SIG003",
                    f"Domain claims to be {name or kind} but verifyingContract is {vc}.",
                    verifying_contract=vc,
                    expected=sorted(expected),
                )
            )
        if vc is not None:
            self.findings += self.ctx.address_findings(vc, "verifying contract")
            if self.ctx.is_contract(vc) is False:
                self.findings.append(
                    finding("SIG002", f"{vc} has no code on this chain.", verifying_contract=vc)
                )

    # ------------------------------------------------------------------ helpers
    def _spender_checks(
        self, spender: str, *, baseline: str, unknown_severity: Severity | None
    ) -> bool:
        """Emit the baseline finding (downgraded for known spenders). Returns True if EOA."""
        known = self.ctx.intel.known_contract(spender, self.ctx.chain_id)
        eoa = self.ctx.is_contract(spender) is False
        if eoa:
            self.findings.append(
                finding("SIG012", f"Spender {spender} has no code.", spender=spender)
            )
        self.findings.append(
            finding(
                baseline,
                f"Spender: {known.label if known else spender}.",
                severity=Severity.LOW if known else unknown_severity,
                spender=spender,
                spender_label=known.label if known else None,
            )
        )
        return eoa

    def _lifetime(self, value: int, *, zero_is_infinite: bool = False) -> str | None:
        """Human description when a deadline is more than 30 days away, else None."""
        if zero_is_infinite and value == 0:
            return "never"
        if value <= self.ctx.now + THIRTY_DAYS:
            return None
        if value >= (1 << 48) - 1:
            return "never"
        return f"in {(value - self.ctx.now) // 86400} days"

    def _deadline(self, value: int, what: str, *, zero_is_infinite: bool = False) -> None:
        lifetime = self._lifetime(value, zero_is_infinite=zero_is_infinite)
        if lifetime:
            self.findings.append(finding("SIG013", f"{what} expires {lifetime}.", value=str(value)))

    # ------------------------------------------------------------------ permits
    def _erc2612(self, td: TypedData) -> dict[str, Any]:
        m = td.message
        spender = _addr(m["spender"], "message.spender")
        value = _int(m["value"], "message.value")
        deadline = _int(m["deadline"], "message.deadline")
        self._spender_checks(spender, baseline="SIG010", unknown_severity=None)
        if value >= UNLIMITED:
            self.findings.append(
                finding(
                    "SIG011",
                    "Permit value is unlimited.",
                    value="max" if value == UINT256_MAX else str(value),
                )
            )
        self._deadline(deadline, "Permit")
        self._owner_matches(m.get("owner"))
        return {
            "token": td.verifying_contract,
            "spender": spender,
            "value": str(value),
            "deadline": deadline,
        }

    def _dai(self, td: TypedData) -> dict[str, Any]:
        m = td.message
        spender = _addr(m["spender"], "message.spender")
        allowed = m["allowed"]
        expiry = _int(m["expiry"], "message.expiry")
        if allowed is not True:
            return {"spender": spender, "allowed": False}
        self._spender_checks(spender, baseline="SIG010", unknown_severity=None)
        self.findings.append(
            finding("SIG011", "DAI-style permit: allowed=true grants an unlimited allowance.")
        )
        self._deadline(expiry, "Permit", zero_is_infinite=True)
        self._owner_matches(m.get("holder"))
        return {
            "token": td.verifying_contract,
            "spender": spender,
            "allowed": True,
            "expiry": expiry,
        }

    def _owner_matches(self, owner: Any) -> None:
        if self.ctx.sender and is_address(owner) and str(owner).lower() != self.ctx.sender.lower():
            self.ctx.note(f"Permit owner {owner} is not the signing account {self.ctx.sender}.")

    def _permit2_allowance(self, td: TypedData) -> dict[str, Any]:
        m = td.message
        details = m["details"] if isinstance(m["details"], list) else [m["details"]]
        spender = _addr(m["spender"], "message.spender")
        tokens = []
        unlimited = []
        long_lived: dict[str, str] = {}
        for i, d in enumerate(details):
            token = _addr(d["token"], f"message.details[{i}].token")
            amount = _int(d["amount"], f"message.details[{i}].amount")
            expiration = _int(d["expiration"], f"message.details[{i}].expiration")
            tokens.append(token)
            if amount >= UINT160_MAX:
                unlimited.append(token)
            lifetime = self._lifetime(expiration)
            if lifetime:
                long_lived[token] = lifetime
        if long_lived:
            lifetimes = sorted(set(long_lived.values()))
            self.findings.append(
                finding(
                    "SIG013",
                    f"Allowance for {len(long_lived)} token(s) expires {', '.join(lifetimes)}.",
                    tokens=sorted(long_lived),
                )
            )
        known = self.ctx.intel.known_contract(spender, self.ctx.chain_id)
        self._spender_checks(spender, baseline="SIG020", unknown_severity=None)
        if unlimited:
            self.findings.append(
                finding(
                    "SIG011",
                    f"Unlimited Permit2 allowance for {len(unlimited)} token(s).",
                    severity=Severity.MEDIUM if known else None,
                    tokens=unlimited,
                )
            )
        if len(tokens) >= 3 and not known:
            self.findings.append(
                finding(
                    "SIG021",
                    f"{len(tokens)} tokens approved at once to {spender}.",
                    spender=spender,
                    tokens=tokens,
                )
            )
        return {"spender": spender, "tokens": tokens}

    def _permit2_transfer(self, td: TypedData) -> dict[str, Any]:
        m = td.message
        permitted = m["permitted"] if isinstance(m["permitted"], list) else [m["permitted"]]
        spender = _addr(m["spender"], "message.spender")
        items = [
            {
                "token": _addr(p["token"], f"message.permitted[{i}].token"),
                "amount": str(_int(p["amount"], f"message.permitted[{i}].amount")),
            }
            for i, p in enumerate(permitted)
        ]
        known = self.ctx.intel.known_contract(spender, self.ctx.chain_id)
        self._spender_checks(spender, baseline="SIG022", unknown_severity=None)
        if len(items) >= 3 and not known:
            self.findings.append(
                finding(
                    "SIG021",
                    f"{len(items)} tokens can be pulled at once by {spender}.",
                    spender=spender,
                    tokens=[i["token"] for i in items],
                )
            )
        self._deadline(_int(m["deadline"], "message.deadline"), "Signature transfer")
        return {"spender": spender, "permitted": items}

    # ------------------------------------------------------------------ seaport
    def _seaport_order(self, td: TypedData) -> dict[str, Any]:
        return self._analyze_order(td.message, "message")

    def _seaport_bulk(self, td: TypedData) -> dict[str, Any]:
        orders: list[tuple[str, dict[str, Any]]] = []

        def walk(node: Any, path: str) -> None:
            if isinstance(node, list):
                for i, child in enumerate(node):
                    walk(child, f"{path}[{i}]")
            elif isinstance(node, dict):
                orders.append((path, node))

        walk(td.message.get("tree"), "message.tree")
        self.findings.append(
            finding("SIG031", f"The signature covers {len(orders)} orders.", orders=len(orders))
        )
        return {"orders": [self._analyze_order(o, p) for p, o in orders]}

    def _analyze_order(self, order: dict[str, Any], path: str) -> dict[str, Any]:
        offerer = _addr(order["offerer"], f"{path}.offerer")
        offer = [self._item(o, f"{path}.offer[{i}]") for i, o in enumerate(order["offer"])]
        consideration = [
            {
                **self._item(c, f"{path}.consideration[{i}]"),
                "recipient": _addr(c["recipient"], f"{path}.consideration[{i}].recipient"),
            }
            for i, c in enumerate(order["consideration"])
        ]
        gives = [o for o in offer if o["max_amount"] > 0]
        receives = [c for c in consideration if c["recipient"] == offerer and c["max_amount"] > 0]
        if gives and not receives:
            others = sorted({c["recipient"] for c in consideration if c["max_amount"] > 0})
            self.findings.append(
                finding(
                    "SIG030",
                    f"{offerer} offers {len(gives)} item(s) and receives nothing"
                    + (f"; consideration goes to {', '.join(others)}." if others else "."),
                    path=path,
                    offered=[_display_item(o) for o in gives],
                    recipients=others,
                )
            )
        if self.ctx.sender and offerer.lower() != self.ctx.sender.lower():
            self.ctx.note(f"Order offerer {offerer} is not the signing account.")
        return {
            "path": path,
            "offerer": offerer,
            "offer": [_display_item(o) for o in offer],
            "consideration": [
                {**_display_item(c), "recipient": c["recipient"]} for c in consideration
            ],
        }

    def _item(self, item: dict[str, Any], path: str) -> dict[str, Any]:
        item_type = _int(item["itemType"], f"{path}.itemType")
        start = _int(item["startAmount"], f"{path}.startAmount")
        end = _int(item["endAmount"], f"{path}.endAmount")
        return {
            "type": SEAPORT_ITEM_TYPES.get(item_type, f"UNKNOWN({item_type})"),
            "token": _addr(item["token"], f"{path}.token"),
            "identifier": str(_int(item["identifierOrCriteria"], f"{path}.identifierOrCriteria")),
            "max_amount": max(start, end),
        }

    # ------------------------------------------------------------------ generic
    def _generic(self, td: TypedData) -> dict[str, Any] | None:
        hits: list[str] = []

        def walk(type_name: str, value: Any, path: str) -> None:
            if type_name not in td.types or not isinstance(value, dict):
                return
            for fname, ftype in td.types[type_name]:
                if fname.lower() in PERMISSION_FIELDS:
                    hits.append(f"{path}.{fname}")
                walk(ftype.split("[", 1)[0], value.get(fname), f"{path}.{fname}")

        walk(td.primary_type, td.message, "message")
        if hits:
            self.findings.append(
                finding(
                    "SIG040", "Permission-related fields: " + ", ".join(hits) + ".", fields=hits
                )
            )
            return {"permission_fields": hits}
        return None


def _display_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **{k: v for k, v in item.items() if k != "max_amount"},
        "amount": str(item["max_amount"]),
    }


def analyze_typed_data(raw: dict[str, Any] | str, ctx: AnalysisContext) -> Report:
    try:
        return TypedDataAnalyzer(ctx).run(raw)
    except KeyError as exc:
        raise TypedDataError(f"missing field {exc.args[0]!r} for this message type") from exc
    except (TypeError, AttributeError) as exc:
        raise TypedDataError(f"unexpected value shape: {exc}") from exc
