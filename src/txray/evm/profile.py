"""Static profile of deployed (runtime) bytecode.

The profile answers the questions the transaction analyzer needs about a target
contract, without source code or verification:

* which function selectors the dispatcher handles, and their names when known;
* which dangerous instructions each function can reach (per-function CFG exploration);
* whether the contract is a proxy (EIP-1167 clone, EIP-1967 / ZeppelinOS slots);
* compiler metadata, hard-coded addresses, and rule findings (``BC0xx``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from txray.abi.registry import REGISTRY
from txray.evm.cfg import ControlFlowGraph
from txray.evm.disassembler import Instruction, disassemble
from txray.evm.metadata import Metadata, parse_metadata
from txray.hexutil import keccak256, to_checksum_address, to_hex
from txray.models import Finding, Severity
from txray.rules import finding

EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


def _slot_minus_one(label: str) -> int:
    return int.from_bytes(keccak256(label.encode()), "big") - 1


PROXY_SLOTS: dict[str, int] = {
    "eip1967.implementation": _slot_minus_one("eip1967.proxy.implementation"),
    "eip1967.beacon": _slot_minus_one("eip1967.proxy.beacon"),
    "eip1967.admin": _slot_minus_one("eip1967.proxy.admin"),
    "zeppelinos.implementation": int.from_bytes(
        keccak256(b"org.zeppelinos.proxy.implementation"), "big"
    ),
    "eip1822.proxiable": int.from_bytes(keccak256(b"PROXIABLE"), "big"),
}
IMPLEMENTATION_SLOTS = ("eip1967.implementation", "zeppelinos.implementation", "eip1822.proxiable")

NOTABLE = (
    "SELFDESTRUCT",
    "DELEGATECALL",
    "CALLCODE",
    "CALL",
    "SSTORE",
    "CREATE",
    "CREATE2",
    "ORIGIN",
)
_ADDRESS_MASK = (1 << 160) - 1


@dataclass
class FunctionProfile:
    selector: bytes
    entry: int
    names: list[str]
    tags: set[str]
    reaches: set[str]
    complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": to_hex(self.selector),
            "entry": self.entry,
            "names": self.names,
            "reaches": sorted(self.reaches),
            "complete": self.complete,
        }


@dataclass
class BytecodeProfile:
    code_hash: str
    size: int
    metadata: Metadata | None = None
    minimal_proxy_target: str | None = None
    proxy_slots: list[str] = field(default_factory=list)
    functions: list[FunctionProfile] = field(default_factory=list)
    reachable_opcodes: set[str] = field(default_factory=set)
    cfg_complete: bool = True
    hardcoded_addresses: list[str] = field(default_factory=list)
    delegatecall_constant_targets: list[str] = field(default_factory=list)
    dynamic_delegatecall: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return self.size == 0

    @property
    def is_proxy(self) -> bool:
        return self.minimal_proxy_target is not None or any(
            s in self.proxy_slots for s in (*IMPLEMENTATION_SLOTS, "eip1967.beacon")
        )

    @property
    def selectors(self) -> set[bytes]:
        return {f.selector for f in self.functions}

    def function(self, sel: bytes) -> FunctionProfile | None:
        return next((f for f in self.functions if f.selector == sel), None)

    def implements(self, sel: bytes) -> bool | None:
        """True/False when the dispatcher was understood, None when we cannot tell
        (proxy forwarding everything, dynamic DELEGATECALL that may forward unknown
        selectors as diamonds do, or no selector table recognized)."""
        if self.is_proxy or self.dynamic_delegatecall or not self.functions:
            return None
        return sel in self.selectors

    def to_dict(self) -> dict[str, Any]:
        return {
            "code_hash": self.code_hash,
            "size": self.size,
            "compiler": self.metadata.compiler if self.metadata else None,
            "source_hash": self.metadata.source_hash if self.metadata else None,
            "minimal_proxy_target": self.minimal_proxy_target,
            "proxy_slots": self.proxy_slots,
            "cfg_complete": self.cfg_complete,
            "reachable_opcodes": sorted(self.reachable_opcodes & set(NOTABLE)),
            "functions": [f.to_dict() for f in self.functions],
            "hardcoded_addresses": self.hardcoded_addresses,
        }


def extract_dispatch(instructions: list[Instruction]) -> dict[bytes, int]:
    """Find ``PUSH4 <selector> ... EQ PUSHn <dest> JUMPI`` sequences.

    Covers the linear dispatch emitted by solc (``DUP1 PUSH4 s EQ`` and
    ``PUSH4 s DUP2 EQ``). Selectors behind other dispatch schemes (Vyper's hash-bucket
    jump tables, hand-written assembly) are not extracted; ``implements`` then returns
    None so no "selector missing" finding is produced.
    """
    out: dict[bytes, int] = {}
    n = len(instructions)
    for i, ins in enumerate(instructions):
        if ins.name != "PUSH4":
            continue
        j = i + 1
        while j < n and j <= i + 2 and instructions[j].name != "EQ":
            if not instructions[j].name.startswith("DUP"):
                break
            j += 1
        if j >= n or instructions[j].name != "EQ":
            continue
        k = j + 1
        if k + 1 < n and instructions[k].op.push_size and instructions[k + 1].name == "JUMPI":
            out.setdefault(ins.arg, instructions[k].value)
    return out


def _minimal_proxy_target(code: bytes) -> str | None:
    if len(code) == 45 and code.startswith(EIP1167_PREFIX) and code.endswith(EIP1167_SUFFIX):
        return to_checksum_address(code[10:30])
    return None


@lru_cache(maxsize=256)
def profile_bytecode(code: bytes) -> BytecodeProfile:
    """Build a :class:`BytecodeProfile`. Results are memoized by code content."""
    profile = BytecodeProfile(code_hash=to_hex(keccak256(code)), size=len(code))
    if not code:
        profile.findings.append(finding("BC010", "The account has no runtime bytecode."))
        return profile

    target = _minimal_proxy_target(code)
    if target:
        profile.minimal_proxy_target = target
        profile.findings.append(
            finding("BC004", f"Every call is delegated to {target}.", implementation=target)
        )
        return profile

    meta = parse_metadata(code)
    profile.metadata = meta
    body = code[: len(code) - meta.raw_length] if meta else code
    instructions = disassemble(body)
    cfg = ControlFlowGraph(instructions)

    root = cfg.explore(0)
    profile.cfg_complete = root.complete
    profile.reachable_opcodes = cfg.opcodes_in(root.reachable)
    present = {i.name for i in instructions}
    if not root.complete:
        # Dynamic jumps: anything present in the code might be reachable.
        profile.reachable_opcodes |= present & set(NOTABLE)

    push32 = {i.value for i in instructions if i.name == "PUSH32"}
    profile.proxy_slots = [name for name, slot in PROXY_SLOTS.items() if slot in push32]

    addresses: list[str] = []
    for ins in instructions:
        if ins.name == "PUSH20" and ins.value not in (0, _ADDRESS_MASK) and ins.value > 0xFFFF:
            addr = to_checksum_address(ins.arg)
            if addr not in addresses:
                addresses.append(addr)
    profile.hardcoded_addresses = addresses[:32]

    for sel, entry in sorted(extract_dispatch(instructions).items(), key=lambda kv: kv[1]):
        known = REGISTRY.lookup(sel)
        sub = cfg.explore(entry)
        profile.functions.append(
            FunctionProfile(
                selector=sel,
                entry=entry,
                names=[k.canonical for k in known],
                tags=set().union(*(k.tags for k in known)) if known else set(),
                reaches=cfg.opcodes_in(sub.reachable) & set(NOTABLE),
                complete=sub.complete,
            )
        )

    targets = set().union(*root.delegatecalls.values()) if root.delegatecalls else set()
    dynamic = None in targets
    profile.dynamic_delegatecall = dynamic
    profile.delegatecall_constant_targets = sorted(
        to_checksum_address(t.to_bytes(20, "big"))
        for t in targets
        if t is not None and 0 < t <= _ADDRESS_MASK
    )
    profile.findings.extend(_bytecode_findings(profile, dynamic))
    return profile


def _functions_reaching(profile: BytecodeProfile, opcode: str) -> list[str]:
    return [
        (f.names[0] if f.names else to_hex(f.selector))
        for f in profile.functions
        if opcode in f.reaches
    ]


def _bytecode_findings(profile: BytecodeProfile, dynamic_delegatecall: bool) -> list[Finding]:
    out: list[Finding] = []
    ops = profile.reachable_opcodes

    if "SELFDESTRUCT" in ops:
        via = _functions_reaching(profile, "SELFDESTRUCT")
        detail = "SELFDESTRUCT is reachable" + (f" from {', '.join(via)}." if via else ".")
        out.append(finding("BC001", detail, functions=via))

    impl_slots = [s for s in profile.proxy_slots if s in (*IMPLEMENTATION_SLOTS, "eip1967.beacon")]
    if impl_slots and "DELEGATECALL" in ops:
        out.append(
            finding(
                "BC005",
                "Proxy storage slots referenced: " + ", ".join(impl_slots) + ".",
                slots=impl_slots,
            )
        )
    elif "DELEGATECALL" in ops and dynamic_delegatecall:
        out.append(
            finding(
                "BC002",
                "DELEGATECALL with a target that is not a code constant, outside a recognized "
                "proxy layout.",
                functions=_functions_reaching(profile, "DELEGATECALL"),
            )
        )

    if "ORIGIN" in ops:
        out.append(
            finding(
                "BC003",
                "The ORIGIN opcode is reachable.",
                functions=_functions_reaching(profile, "ORIGIN"),
            )
        )

    privileged: dict[str, list[str]] = {}
    for fn in profile.functions:
        for tag in fn.tags:
            if tag.startswith("privileged-"):
                privileged.setdefault(tag.removeprefix("privileged-"), []).append(fn.names[0])
    if privileged:
        severe = privileged.keys() & {"blacklist", "fee", "trading", "mint"}
        out.append(
            finding(
                "BC006",
                "Administrative capabilities: " + ", ".join(sorted(privileged)) + ".",
                severity=Severity.MEDIUM if len(severe) >= 2 else None,
                capabilities={k: sorted(v) for k, v in sorted(privileged.items())},
            )
        )

    if "CREATE2" in ops and "SELFDESTRUCT" in ops:
        out.append(finding("BC007", "Both CREATE2 and SELFDESTRUCT are reachable."))

    if not profile.cfg_complete:
        out.append(
            finding(
                "BC008",
                "Exploration budget exhausted or dynamic jumps found; reachability results "
                "are lower bounds and opcode presence is used as a fallback.",
            )
        )

    if profile.hardcoded_addresses:
        out.append(
            finding(
                "BC009",
                f"{len(profile.hardcoded_addresses)} address constant(s) in code.",
                addresses=profile.hardcoded_addresses,
            )
        )
    return out
