# Contributing

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
make check        # lint, format check, mypy --strict, tests
```

## Adding a rule

1. Declare it in `src/txray/rules.py` with an ID in the right family (`INT`, `TX`, `SIG`,
   `MSG`, `BC`), a default severity and a rationale a user can understand.
2. Emit it from the relevant analyzer with `finding(rule_id, detail, **evidence)`. Put
   machine-readable data in `evidence`; keep `detail` a single sentence.
3. Add tests for the positive case and at least one negative case (the legitimate request
   that must not trigger it).
4. Regenerate the catalog: `make docs` (a test fails if `docs/RULES.md` is stale).

## Adding function signatures or known contracts

- Signatures go in `src/txray/abi/registry.py`; selectors are computed from the canonical
  signature, never typed by hand.
- Known contracts go in `src/txray/intel.py`. Only add deployments whose address you have
  checked on-chain, and scope them to the chains where they exist.

## Bytecode fixtures

`tests/fixtures/bytecode/*.hex` hold runtime code fetched with `eth_getCode` from Ethereum
mainnet. When adding one, note the address in `tests/conftest.py`. For targeted behaviour,
prefer a small contract written with `txray.evm.disassembler.assemble`.

## Style

- `ruff format` and `ruff check` must pass; `mypy --strict` must pass on `src/`.
- Raise `InvalidInputError` (or a subclass) for bad user input; never let a decoding error
  surface as a 500.
- Do not log analyzed payloads.

## Commits and pull requests

Keep pull requests focused, describe the attack shape a new rule targets and include an
example payload in `examples/` when it helps reviewers.
