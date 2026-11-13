"""Exception hierarchy.

Every error raised deliberately by txray derives from :class:`TxrayError`, so callers
(the CLI and the HTTP API) can distinguish input problems from bugs.
"""

from __future__ import annotations


class TxrayError(Exception):
    """Base class for all txray errors."""


class InvalidInputError(TxrayError):
    """User supplied data that cannot be parsed (bad hex, malformed typed data, ...)."""


class AbiDecodingError(InvalidInputError):
    """ABI payload is truncated, has out-of-range offsets or does not match its type."""


class TypedDataError(InvalidInputError):
    """EIP-712 payload is structurally invalid (unknown type, missing field, cycle...)."""


class BytecodeError(InvalidInputError):
    """Bytecode cannot be decoded."""


class RpcError(TxrayError):
    """JSON-RPC transport or protocol failure."""


class ConfigError(TxrayError):
    """Invalid configuration file or environment."""
