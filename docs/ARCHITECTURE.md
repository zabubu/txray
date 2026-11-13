# Architecture and design notes

This document explains how txray is put together and why. The README covers usage.

## Request flow

1. **Entry point.** `cli.py` or `api.py` validates the raw input (hex, addresses with
   EIP-55 checksum, integers within uint256) and builds an `AnalysisContext` through
   `service.Txray.context()`: chain id, signer, requesting origin, the RPC reader for that
   chain (or none when offline) and the address intelligence.
2. **Analyzer.** One of `analysis/transaction.py`, `analysis/typed_data.py`,
   `analysis/message.py` decodes the request and applies its rules. Findings are created
   only through `rules.finding()`, which pulls title and default severity from the catalog
   in `rules.py`.
3. **On-chain context.** When a rule needs to know whether an address has code, or what a
   contract can do, it calls `ctx.resolve(address)`. This fetches code once per analysis,
   follows one level of proxy indirection and returns a `ResolvedContract` holding the
   bytecode profile of the code that will actually execute.
4. **Report.** `models.Report` derives `verdict`, `score` and `max_severity` from the
   findings. The service persists the public JSON form when a database is configured.

## Bytecode analysis (`evm/`)

### Disassembly

`disassembler.disassemble` is a linear sweep. PUSH immediates are skipped (so `0x5b`
bytes inside push data are not jump destinations), truncated PUSHes at the end of code are
zero-padded as the EVM does, and undefined opcodes become `UNKNOWN_0x..` terminators.
The Solidity CBOR metadata trailer is stripped first (`metadata.py`) so it is not decoded as
instructions.

### CFG by abstract interpretation

EVM jumps read their destination from the stack, so edges cannot be read off the
instruction stream. `cfg.ControlFlowGraph.explore` interprets basic blocks over an abstract
stack where each slot is a constant or unknown:

- PUSH/DUP/SWAP move constants; `ADD SUB MUL AND OR XOR EQ SHL SHR` fold when both
  operands are known; every other opcode pops its inputs and pushes unknowns.
- `JUMP`/`JUMPI` targets taken from the abstract stack become edges when they are valid
  `JUMPDEST`s; an unknown target is recorded as *unresolved*.
- States are keyed by `(block, stack)`. At block boundaries, constants that are neither
  valid jump destinations nor 160-bit values are forgotten. Loop counters and other data
  would otherwise create one state per iteration; jump destinations (internal call return
  addresses) and address-sized constants (DELEGATECALL targets) are what the analysis
  needs. With this abstraction WETH9, Permit2, Multicall3 and the 23 KB USDC
  implementation all get complete CFGs.
- Exploration is bounded (256 states per block, 100k block visits). Hitting a bound sets
  `truncated`; results are then lower bounds and the profile falls back to opcode presence.

Because the stack is tracked across blocks, internal function calls resolve naturally: a
caller pushes its return label, the callee's final `JUMP` pops it. Exploring from each
function's dispatcher entry with an empty stack therefore gives a per-function reachable
set in which a shared internal function returns only to the caller that invoked it.

### Profile

`profile.profile_bytecode` combines:

- selector extraction from the solc dispatcher (`PUSH4 s … EQ PUSHn dest JUMPI`);
- per-selector exploration to compute which notable opcodes each function can reach;
- proxy detection by the EIP-1167 byte pattern and by `PUSH32` constants equal to the
  EIP-1967 / ZeppelinOS / EIP-1822 slots (computed from their defining strings at import);
- DELEGATECALL targets observed on the abstract stack, to tell linked-library calls
  (constant address) from dynamic delegation;
- `BC0xx` findings.

Profiles are memoized with `lru_cache` keyed by the code bytes, so a contract seen in many
requests is analyzed once per process.

## Rule design

- **Context changes severity, not rule identity.** `TX001` (unlimited allowance) is
  medium by default, low when the spender is a known router, and the companion `TX002`
  becomes critical when the spender has no code. The catalog stays small and each finding
  explains which context applied.
- **Unknown is not safe.** When a check cannot run (no RPC, RPC error, unrecognized
  dispatcher), the analyzer adds a note instead of a finding. `BytecodeProfile.implements`
  returns `None` rather than `False` when the dispatcher was not understood, so `TX005`
  (selector missing) is never raised on a guess.
- **Transaction context caps governance findings.** A USDC transfer should not warn
  because USDC is upgradeable and has a blacklist; `BC005`/`BC006` are capped at `low` in
  transaction reports but keep their default severity in bytecode reports.
- **One finding per fact.** Address checks (denylist, look-alike) are deduplicated per
  analysis; Permit2 batch expirations are aggregated into one `SIG013`.

## Input hardening

| Input | Measure |
|---|---|
| ABI calldata | bounds-checked offsets, array lengths capped by available bytes, nesting depth limit, dirty-bit checks on `address`/`bool`/`uintN`/`bytesN`, strict UTF-8 |
| EIP-712 | type graph validation (unknown types, duplicate fields, undeclared fields or domain keys), integer ranges per type, depth limit |
| Addresses | EIP-55 checksum enforced on mixed-case input |
| HTTP body | size cap applied to the received stream, so chunked bodies without `Content-Length` are limited too |
| RPC responses | size cap, JSON shape and hex validation; URLs restricted to http(s) and set only in server configuration |

## Persistence

`storage.Store` wraps one SQLite connection behind a lock (FastAPI runs sync endpoints in
a thread pool) with WAL mode for file databases. Two tables: `code_cache` (keyed by chain
and lower-case address, with a TTL because code at an address is not strictly immutable:
SELFDESTRUCT within the creation transaction and metamorphic deployments) and `reports`.

## Authentication and rate limiting

API keys are random tokens (`txray keygen`); the server stores only their SHA-256. A fast
hash is appropriate because keys have 256 bits of entropy (there is no dictionary to slow
down). The presented key is hashed and compared to every configured digest with
`hmac.compare_digest`. Rate limiting is an in-process token bucket per key digest (or per
client IP in anonymous mode); a multi-instance deployment would need a shared store.
