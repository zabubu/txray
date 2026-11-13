"""EVM opcode table (Cancun).

Each entry is ``(mnemonic, stack_inputs, stack_outputs)``. Stack arity is what the
abstract interpreter in :mod:`txray.evm.cfg` needs to keep track of jump targets.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpInfo:
    code: int
    name: str
    pops: int
    pushes: int

    @property
    def push_size(self) -> int:
        return self.code - 0x5F if 0x60 <= self.code <= 0x7F else 0


_TABLE: dict[int, tuple[str, int, int]] = {
    0x00: ("STOP", 0, 0),
    0x01: ("ADD", 2, 1),
    0x02: ("MUL", 2, 1),
    0x03: ("SUB", 2, 1),
    0x04: ("DIV", 2, 1),
    0x05: ("SDIV", 2, 1),
    0x06: ("MOD", 2, 1),
    0x07: ("SMOD", 2, 1),
    0x08: ("ADDMOD", 3, 1),
    0x09: ("MULMOD", 3, 1),
    0x0A: ("EXP", 2, 1),
    0x0B: ("SIGNEXTEND", 2, 1),
    0x10: ("LT", 2, 1),
    0x11: ("GT", 2, 1),
    0x12: ("SLT", 2, 1),
    0x13: ("SGT", 2, 1),
    0x14: ("EQ", 2, 1),
    0x15: ("ISZERO", 1, 1),
    0x16: ("AND", 2, 1),
    0x17: ("OR", 2, 1),
    0x18: ("XOR", 2, 1),
    0x19: ("NOT", 1, 1),
    0x1A: ("BYTE", 2, 1),
    0x1B: ("SHL", 2, 1),
    0x1C: ("SHR", 2, 1),
    0x1D: ("SAR", 2, 1),
    0x20: ("KECCAK256", 2, 1),
    0x30: ("ADDRESS", 0, 1),
    0x31: ("BALANCE", 1, 1),
    0x32: ("ORIGIN", 0, 1),
    0x33: ("CALLER", 0, 1),
    0x34: ("CALLVALUE", 0, 1),
    0x35: ("CALLDATALOAD", 1, 1),
    0x36: ("CALLDATASIZE", 0, 1),
    0x37: ("CALLDATACOPY", 3, 0),
    0x38: ("CODESIZE", 0, 1),
    0x39: ("CODECOPY", 3, 0),
    0x3A: ("GASPRICE", 0, 1),
    0x3B: ("EXTCODESIZE", 1, 1),
    0x3C: ("EXTCODECOPY", 4, 0),
    0x3D: ("RETURNDATASIZE", 0, 1),
    0x3E: ("RETURNDATACOPY", 3, 0),
    0x3F: ("EXTCODEHASH", 1, 1),
    0x40: ("BLOCKHASH", 1, 1),
    0x41: ("COINBASE", 0, 1),
    0x42: ("TIMESTAMP", 0, 1),
    0x43: ("NUMBER", 0, 1),
    0x44: ("PREVRANDAO", 0, 1),
    0x45: ("GASLIMIT", 0, 1),
    0x46: ("CHAINID", 0, 1),
    0x47: ("SELFBALANCE", 0, 1),
    0x48: ("BASEFEE", 0, 1),
    0x49: ("BLOBHASH", 1, 1),
    0x4A: ("BLOBBASEFEE", 0, 1),
    0x50: ("POP", 1, 0),
    0x51: ("MLOAD", 1, 1),
    0x52: ("MSTORE", 2, 0),
    0x53: ("MSTORE8", 2, 0),
    0x54: ("SLOAD", 1, 1),
    0x55: ("SSTORE", 2, 0),
    0x56: ("JUMP", 1, 0),
    0x57: ("JUMPI", 2, 0),
    0x58: ("PC", 0, 1),
    0x59: ("MSIZE", 0, 1),
    0x5A: ("GAS", 0, 1),
    0x5B: ("JUMPDEST", 0, 0),
    0x5C: ("TLOAD", 1, 1),
    0x5D: ("TSTORE", 2, 0),
    0x5E: ("MCOPY", 3, 0),
    0x5F: ("PUSH0", 0, 1),
    0xA0: ("LOG0", 2, 0),
    0xA1: ("LOG1", 3, 0),
    0xA2: ("LOG2", 4, 0),
    0xA3: ("LOG3", 5, 0),
    0xA4: ("LOG4", 6, 0),
    0xF0: ("CREATE", 3, 1),
    0xF1: ("CALL", 7, 1),
    0xF2: ("CALLCODE", 7, 1),
    0xF3: ("RETURN", 2, 0),
    0xF4: ("DELEGATECALL", 6, 1),
    0xF5: ("CREATE2", 4, 1),
    0xFA: ("STATICCALL", 6, 1),
    0xFD: ("REVERT", 2, 0),
    0xFE: ("INVALID", 0, 0),
    0xFF: ("SELFDESTRUCT", 1, 0),
}

for _n in range(1, 33):
    _TABLE[0x5F + _n] = (f"PUSH{_n}", 0, 1)
for _n in range(1, 17):
    _TABLE[0x7F + _n] = (f"DUP{_n}", _n, _n + 1)
    _TABLE[0x8F + _n] = (f"SWAP{_n}", _n + 1, _n + 1)

OPCODES: dict[int, OpInfo] = {
    code: OpInfo(code, name, pops, pushes) for code, (name, pops, pushes) in _TABLE.items()
}
BY_NAME: dict[str, OpInfo] = {op.name: op for op in OPCODES.values()}

# Instructions after which execution never falls through to the next instruction.
TERMINATORS = frozenset({"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT", "JUMP"})
EXTERNAL_CALLS = frozenset({"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"})
