"""Linear-sweep disassembler and a small assembler.

The assembler exists so tests (and users) can build precise bytecode samples
(``PUSH1 0x80 PUSH1 0x40 MSTORE ...``) without a Solidity toolchain. Labels
(``@name``) are supported to compute jump destinations.
"""

from __future__ import annotations

from dataclasses import dataclass

from txray.errors import BytecodeError
from txray.evm.opcodes import BY_NAME, OPCODES, OpInfo


@dataclass(frozen=True)
class Instruction:
    pc: int
    op: OpInfo
    arg: bytes = b""  # PUSH immediate (may be shorter than declared if code is truncated)

    @property
    def name(self) -> str:
        return self.op.name

    @property
    def size(self) -> int:
        return 1 + self.op.push_size

    @property
    def value(self) -> int:
        return int.from_bytes(self.arg, "big") if self.arg else 0

    def __str__(self) -> str:
        if self.op.push_size:
            return f"{self.pc:05x}  {self.name} 0x{self.arg.hex()}"
        return f"{self.pc:05x}  {self.name}"


_UNKNOWN_CACHE: dict[int, OpInfo] = {}


def _unknown(code: int) -> OpInfo:
    if code not in _UNKNOWN_CACHE:
        _UNKNOWN_CACHE[code] = OpInfo(code, f"UNKNOWN_0x{code:02x}", 0, 0)
    return _UNKNOWN_CACHE[code]


def disassemble(code: bytes) -> list[Instruction]:
    """Decode bytecode into instructions. Undefined opcodes become ``UNKNOWN_0x..``
    (they behave like INVALID when executed) instead of aborting the sweep."""
    out: list[Instruction] = []
    pc = 0
    n = len(code)
    while pc < n:
        byte = code[pc]
        op = OPCODES.get(byte) or _unknown(byte)
        size = op.push_size
        arg = code[pc + 1 : pc + 1 + size] if size else b""
        # Truncated PUSH at end of code: the EVM pads with zeros.
        if size and len(arg) < size:
            arg = arg.ljust(size, b"\x00")
        out.append(Instruction(pc, op, arg))
        pc += 1 + size
    return out


def jumpdests(code: bytes) -> frozenset[int]:
    """Valid JUMPDEST offsets (i.e. 0x5b bytes that are not inside PUSH data)."""
    return frozenset(i.pc for i in disassemble(code) if i.name == "JUMPDEST")


def assemble(source: str) -> bytes:
    """Assemble whitespace separated mnemonics.

    * ``PUSHn 0x..`` / ``PUSH 0x..`` (size inferred) push immediates
    * ``@label`` as a PUSH argument refers to the offset of ``label:``
    * ``label:`` emits nothing but records a position (put a JUMPDEST after it)
    * ``;`` starts a comment until end of line
    """
    tokens: list[str] = []
    for line in source.splitlines():
        tokens.extend(line.split(";", 1)[0].split())

    # Two passes: label references use PUSH2 so sizes are known before resolution.
    items: list[tuple[str, str | None]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        upper = tok.upper()
        if tok.endswith(":"):
            items.append(("LABEL", tok[:-1]))
            i += 1
            continue
        if upper.startswith("PUSH") and upper != "PUSH0":
            if i + 1 >= len(tokens):
                raise BytecodeError(f"{tok} without argument")
            items.append((upper, tokens[i + 1]))
            i += 2
            continue
        if upper not in BY_NAME:
            raise BytecodeError(f"unknown mnemonic {tok!r}")
        items.append((upper, None))
        i += 1

    def push_bytes(mnemonic: str, arg: str, labels: dict[str, int] | None) -> bytes:
        if arg.startswith("@"):
            target = labels.get(arg[1:], 0) if labels is not None else 0
            if labels is not None and arg[1:] not in labels:
                raise BytecodeError(f"undefined label {arg}")
            width = 2 if mnemonic == "PUSH" else int(mnemonic[4:])
            if not 2 <= width <= 32:
                raise BytecodeError(f"{mnemonic} {arg}: label references need PUSH2 or wider")
            raw = target.to_bytes(width, "big")
        else:
            value = int(arg, 0)
            if value < 0:
                raise BytecodeError("negative PUSH argument")
            minimal = max(1, (value.bit_length() + 7) // 8)
            width = minimal if mnemonic == "PUSH" else int(mnemonic[4:])
            if not 1 <= width <= 32 or minimal > width:
                raise BytecodeError(f"{mnemonic} {arg}: value does not fit")
            raw = value.to_bytes(width, "big")
        return bytes([0x5F + width]) + raw.rjust(width, b"\x00")

    def emit(labels: dict[str, int] | None) -> tuple[bytes, dict[str, int]]:
        out = bytearray()
        found: dict[str, int] = {}
        for mnemonic, arg in items:
            if mnemonic == "LABEL":
                assert arg is not None
                found[arg] = len(out)
            elif arg is not None:
                out += push_bytes(mnemonic, arg, labels)
            else:
                out.append(BY_NAME[mnemonic].code)
        return bytes(out), found

    _, labels = emit(None)
    code, _ = emit(labels)
    return code
