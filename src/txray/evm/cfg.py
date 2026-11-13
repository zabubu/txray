"""Control-flow graph construction with stack-aware jump resolution.

EVM jumps take their destination from the stack, so a CFG cannot be built from the
instruction stream alone. We run a small abstract interpreter over basic blocks where
each stack slot is either a known constant or ``None`` (unknown). Jump targets pushed
by one block and consumed by another (internal function calls and their return
addresses) are therefore resolved, and exploring from a function's entry point keeps
return edges precise: a shared internal function returns to the caller that pushed
the return label, not to every caller.

The state space is bounded (distinct stack states per block and a global step budget);
when a bound is hit, the exploration is flagged ``truncated`` and reachability becomes
a lower bound. The same holds for jumps whose target is not a constant (``unresolved``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from txray.evm.disassembler import Instruction
from txray.evm.opcodes import TERMINATORS

MAX_TRACKED_STACK = 48
MASK = (1 << 256) - 1

Stack = tuple[int | None, ...]


@dataclass
class BasicBlock:
    start: int
    instructions: list[Instruction]
    fallthrough: int | None = None

    @property
    def last(self) -> Instruction:
        return self.instructions[-1]

    @property
    def names(self) -> set[str]:
        return {i.name for i in self.instructions}


def _is_terminator(ins: Instruction) -> bool:
    return ins.name in TERMINATORS or ins.name.startswith("UNKNOWN_")


def build_blocks(instructions: list[Instruction]) -> dict[int, BasicBlock]:
    blocks: dict[int, BasicBlock] = {}
    current: list[Instruction] = []

    def close(next_pc: int | None) -> None:
        if not current:
            return
        block = BasicBlock(current[0].pc, list(current))
        if not _is_terminator(block.last):
            block.fallthrough = next_pc
        blocks[block.start] = block
        current.clear()

    for ins in instructions:
        if ins.name == "JUMPDEST" and current:
            close(ins.pc)
        current.append(ins)
        if _is_terminator(ins) or ins.name == "JUMPI":
            close(ins.pc + ins.size)
    close(None)
    return blocks


def _binop(name: str, a: int, b: int) -> int | None:
    if name == "ADD":
        return (a + b) & MASK
    if name == "SUB":
        return (a - b) & MASK
    if name == "MUL":
        return (a * b) & MASK
    if name == "AND":
        return a & b
    if name == "OR":
        return a | b
    if name == "XOR":
        return a ^ b
    if name == "EQ":
        return int(a == b)
    if name == "SHL":  # SHL(shift=a, value=b)
        return (b << a) & MASK if a < 256 else 0
    if name == "SHR":
        return b >> a if a < 256 else 0
    return None


_FOLDABLE = {"ADD", "SUB", "MUL", "AND", "OR", "XOR", "EQ", "SHL", "SHR"}


def _execute(ins: Instruction, stack: list[int | None]) -> None:
    """Apply one non-jump instruction to the abstract stack (top = end of list)."""
    name = ins.name
    if ins.op.push_size:
        stack.append(ins.value)
        return
    if name == "PUSH0":
        stack.append(0)
        return
    if name == "PC":
        stack.append(ins.pc)
        return
    if name.startswith("DUP"):
        n = int(name[3:])
        _ensure(stack, n)
        stack.append(stack[-n])
        return
    if name.startswith("SWAP"):
        n = int(name[4:])
        _ensure(stack, n + 1)
        stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
        return
    if name in _FOLDABLE:
        a, b = _pop(stack), _pop(stack)
        stack.append(_binop(name, a, b) if a is not None and b is not None else None)
        return
    for _ in range(ins.op.pops):
        _pop(stack)
    for _ in range(ins.op.pushes):
        stack.append(None)


def _ensure(stack: list[int | None], depth: int) -> None:
    if len(stack) < depth:
        stack[:0] = [None] * (depth - len(stack))


def _pop(stack: list[int | None]) -> int | None:
    return stack.pop() if stack else None


def _address_like(value: int) -> bool:
    return 145 <= value.bit_length() <= 160


def _canonical(stack: list[int | None], keep: frozenset[int] | None = None) -> Stack:
    """Normalize a stack for use as a state key.

    With ``keep``, constants that are neither valid jump destinations nor address-sized
    values are forgotten at block boundaries. Code addresses are needed to resolve
    jumps and 160-bit constants to identify DELEGATECALL targets; dropping loop
    counters and other data keeps the number of distinct states per block small.
    """
    trimmed = stack[-MAX_TRACKED_STACK:]
    if keep is not None:
        trimmed = [
            v if v is not None and (v in keep or _address_like(v)) else None for v in trimmed
        ]
    start = 0
    while start < len(trimmed) and trimmed[start] is None:
        start += 1
    return tuple(trimmed[start:])


@dataclass
class Exploration:
    entry: int
    reachable: set[int] = field(default_factory=set)
    edges: dict[int, set[int]] = field(default_factory=dict)
    unresolved: set[int] = field(default_factory=set)  # blocks ending in a dynamic jump
    # pc of each reachable DELEGATECALL -> constant target addresses seen (None = dynamic)
    delegatecalls: dict[int, set[int | None]] = field(default_factory=dict)
    truncated: bool = False

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.unresolved


class ControlFlowGraph:
    def __init__(
        self,
        instructions: list[Instruction],
        *,
        max_states_per_block: int = 256,
        max_steps: int = 100_000,
    ) -> None:
        self.instructions = instructions
        self.blocks = build_blocks(instructions)
        self.jumpdests = frozenset(i.pc for i in instructions if i.name == "JUMPDEST")
        self.max_states_per_block = max_states_per_block
        self.max_steps = max_steps

    def explore(self, entry: int = 0, initial: Iterable[int | None] = ()) -> Exploration:
        result = Exploration(entry)
        seen: dict[int, set[Stack]] = {}
        work: list[tuple[int, Stack]] = [(entry, _canonical(list(initial), self.jumpdests))]
        steps = 0
        while work:
            start, state = work.pop()
            block = self.blocks.get(start)
            if block is None:
                continue
            states = seen.setdefault(start, set())
            if state in states:
                continue
            result.reachable.add(start)
            if len(states) >= self.max_states_per_block or steps >= self.max_steps:
                result.truncated = True
                continue
            states.add(state)
            steps += 1

            stack = list(state)
            targets: list[int | None] = []
            for ins in block.instructions:
                if ins.name == "JUMP":
                    targets.append(_pop(stack))
                elif ins.name == "JUMPI":
                    targets.append(_pop(stack))
                    _pop(stack)
                else:
                    if ins.name == "DELEGATECALL":
                        target = stack[-2] if len(stack) >= 2 else None
                        result.delegatecalls.setdefault(ins.pc, set()).add(target)
                    _execute(ins, stack)
            if block.fallthrough is not None:
                targets.append(block.fallthrough)

            next_state = _canonical(stack, self.jumpdests)
            for target in targets:
                if target is None:
                    result.unresolved.add(start)
                    continue
                is_fallthrough = target == block.fallthrough
                if not is_fallthrough and target not in self.jumpdests:
                    continue  # invalid destination: that path reverts
                result.edges.setdefault(start, set()).add(target)
                work.append((target, next_state))
        return result

    def opcodes_in(self, block_starts: Iterable[int]) -> set[str]:
        names: set[str] = set()
        for start in block_starts:
            block = self.blocks.get(start)
            if block is not None:
                names |= block.names
        return names
