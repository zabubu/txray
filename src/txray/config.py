"""Configuration from an optional TOML file, overridden by environment variables.

Example ``txray.toml``::

    db_path = "data/txray.db"
    denylist = "config/denylist.txt"
    address_book = "config/address_book.txt"
    rate_limit_per_minute = 120
    api_key_hashes = ["<sha256 hex of an API key>"]

    [rpc]
    1 = "https://ethereum-rpc.publicnode.com"

Environment: ``TXRAY_CONFIG``, ``TXRAY_DB``, ``TXRAY_RPC_<chainId>``,
``TXRAY_API_KEY_HASHES`` (comma separated), ``TXRAY_ALLOW_ANONYMOUS``,
``TXRAY_RATE_LIMIT``, ``TXRAY_DENYLIST``, ``TXRAY_ADDRESS_BOOK``,
``TXRAY_LOG_LEVEL``, ``TXRAY_LOG_JSON``.
"""

from __future__ import annotations

import hashlib
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from txray.errors import ConfigError

_HASH = re.compile(r"^[0-9a-f]{64}$")
_TRUE = {"1", "true", "yes", "on"}


def hash_api_key(key: str) -> str:
    """API keys are stored as SHA-256 digests. Keys are random 256-bit tokens, so a
    fast hash is sufficient (no dictionary to protect against, unlike passwords)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass
class Settings:
    rpc: dict[int, str] = field(default_factory=dict)
    db_path: str | None = None
    api_key_hashes: list[str] = field(default_factory=list)
    allow_anonymous: bool = False
    rate_limit_per_minute: int = 120
    max_body_bytes: int = 256 * 1024
    denylist: Path | None = None
    address_book: Path | None = None
    code_cache_ttl: int = 3600
    rpc_timeout: float = 10.0
    log_level: str = "INFO"
    log_json: bool = False

    def validate(self) -> Settings:
        for chain_id, url in self.rpc.items():
            if chain_id <= 0:
                raise ConfigError(f"invalid chain id {chain_id}")
            if not url.startswith(("http://", "https://")):
                raise ConfigError(f"RPC URL for chain {chain_id} must be http(s)")
        for h in self.api_key_hashes:
            if not _HASH.match(h):
                raise ConfigError("api_key_hashes must contain lowercase SHA-256 hex digests")
        if self.rate_limit_per_minute < 0:
            raise ConfigError("rate_limit_per_minute must be >= 0 (0 disables)")
        if self.max_body_bytes < 1024:
            raise ConfigError("max_body_bytes must be at least 1024")
        if self.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ConfigError(f"invalid log level {self.log_level!r}")
        return self


def _apply(settings: Settings, data: Mapping[str, Any]) -> None:
    known = {
        "db_path",
        "api_key_hashes",
        "allow_anonymous",
        "rate_limit_per_minute",
        "max_body_bytes",
        "denylist",
        "address_book",
        "code_cache_ttl",
        "rpc_timeout",
        "log_level",
        "log_json",
        "rpc",
    }
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")
    try:
        if "rpc" in data:
            settings.rpc.update({int(k): str(v) for k, v in dict(data["rpc"]).items()})
        for key in ("db_path", "log_level"):
            if key in data:
                setattr(settings, key, str(data[key]))
        for key in ("denylist", "address_book"):
            if key in data:
                setattr(settings, key, Path(data[key]))
        for key in ("rate_limit_per_minute", "max_body_bytes", "code_cache_ttl"):
            if key in data:
                setattr(settings, key, int(data[key]))
        if "rpc_timeout" in data:
            settings.rpc_timeout = float(data["rpc_timeout"])
        for key in ("allow_anonymous", "log_json"):
            if key in data:
                value = data[key]
                setattr(
                    settings, key, value if isinstance(value, bool) else str(value).lower() in _TRUE
                )
        if "api_key_hashes" in data:
            value = data["api_key_hashes"]
            items = value.split(",") if isinstance(value, str) else list(value)
            settings.api_key_hashes = [str(v).strip().lower() for v in items if str(v).strip()]
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"invalid configuration value: {exc}") from exc


def load_settings(path: str | Path | None = None, env: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    settings = Settings()
    config_path = path or env.get("TXRAY_CONFIG")
    if config_path:
        try:
            with open(config_path, "rb") as fh:
                _apply(settings, tomllib.load(fh))
        except OSError as exc:
            raise ConfigError(f"cannot read config {config_path}: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc

    overrides: dict[str, Any] = {}
    mapping = {
        "TXRAY_DB": "db_path",
        "TXRAY_API_KEY_HASHES": "api_key_hashes",
        "TXRAY_ALLOW_ANONYMOUS": "allow_anonymous",
        "TXRAY_RATE_LIMIT": "rate_limit_per_minute",
        "TXRAY_MAX_BODY_BYTES": "max_body_bytes",
        "TXRAY_DENYLIST": "denylist",
        "TXRAY_ADDRESS_BOOK": "address_book",
        "TXRAY_LOG_LEVEL": "log_level",
        "TXRAY_LOG_JSON": "log_json",
    }
    for var, key in mapping.items():
        if env.get(var):
            overrides[key] = env[var]
    rpc = {
        var.removeprefix("TXRAY_RPC_"): url
        for var, url in env.items()
        if var.startswith("TXRAY_RPC_") and var.removeprefix("TXRAY_RPC_").isdigit()
    }
    if rpc:
        overrides["rpc"] = rpc
    _apply(settings, overrides)
    return settings.validate()
