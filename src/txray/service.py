"""Application service: wires settings, intel, storage and RPC readers to analyzers.

Both the CLI and the HTTP API go through :class:`Txray`, so they produce identical
reports for identical inputs.
"""

from __future__ import annotations

import logging
from typing import Any

from txray.analysis.context import AnalysisContext
from txray.analysis.message import analyze_message
from txray.analysis.transaction import TxRequest, analyze_transaction
from txray.analysis.typed_data import analyze_typed_data
from txray.chain import ChainReader, RpcChainReader, RpcClient, resolve_contract
from txray.config import Settings
from txray.errors import InvalidInputError
from txray.evm.profile import profile_bytecode
from txray.hexutil import normalize_address
from txray.intel import AddressIntel, load_address_list
from txray.models import Report
from txray.rules import finding
from txray.storage import Store

log = logging.getLogger(__name__)


class Txray:
    def __init__(
        self,
        settings: Settings,
        *,
        readers: dict[int, ChainReader] | None = None,
        store: Store | None = None,
    ) -> None:
        self.settings = settings
        self.store = (
            store if store is not None else (Store(settings.db_path) if settings.db_path else None)
        )
        self.intel = AddressIntel(
            denylist=load_address_list(settings.denylist),
            address_book=load_address_list(settings.address_book),
        )
        self._clients: list[RpcClient] = []
        if readers is None:
            readers = {}
            for chain_id, url in settings.rpc.items():
                client = RpcClient(url, timeout=settings.rpc_timeout)
                self._clients.append(client)
                readers[chain_id] = RpcChainReader(
                    client, chain_id, self.store, settings.code_cache_ttl
                )
        self.readers = readers

    def close(self) -> None:
        for client in self._clients:
            client.close()
        if self.store is not None:
            self.store.close()

    def context(
        self,
        chain_id: int | None,
        sender: str | None = None,
        origin: str | None = None,
        *,
        offline: bool = False,
    ) -> AnalysisContext:
        return AnalysisContext(
            chain_id=chain_id,
            sender=normalize_address(sender, field="from") if sender else None,
            origin=origin,
            reader=None if offline or chain_id is None else self.readers.get(chain_id),
            intel=self.intel,
            offline=offline,
        )

    def _record(self, report: Report) -> dict[str, Any]:
        public = report.to_public()
        if self.store is not None:
            self.store.save_report(public)
        log.info(
            "analysis complete",
            extra={
                "report_id": report.id,
                "kind": report.kind,
                "verdict": public["verdict"],
                "score": public["score"],
            },
        )
        return public

    # ------------------------------------------------------------------ analyses
    def transaction(self, tx: TxRequest, ctx: AnalysisContext) -> dict[str, Any]:
        return self._record(analyze_transaction(tx, ctx))

    def typed_data(self, payload: dict[str, Any] | str, ctx: AnalysisContext) -> dict[str, Any]:
        return self._record(analyze_typed_data(payload, ctx))

    def message(self, method: str, payload: str, ctx: AnalysisContext) -> dict[str, Any]:
        return self._record(analyze_message(method, payload, ctx))

    def bytecode(
        self,
        *,
        code: bytes | None = None,
        address: str | None = None,
        ctx: AnalysisContext,
    ) -> dict[str, Any]:
        if (code is None) == (address is None):
            raise InvalidInputError("provide exactly one of code or address")
        report = Report(kind="bytecode", chain_id=ctx.chain_id)
        if code is not None:
            profile = profile_bytecode(code)
            report.decoded = {"profile": profile.to_dict()}
            report.findings = list(profile.findings)
            return self._record(report)

        assert address is not None
        address = normalize_address(address)
        report.findings += ctx.address_findings(address, "contract")
        if ctx.reader is None:
            raise InvalidInputError(f"no RPC endpoint configured for chain {ctx.chain_id}")
        resolved = resolve_contract(ctx.reader, address)
        report.decoded = {"address": address, "profile": resolved.profile.to_dict()}
        report.findings += resolved.profile.findings
        if resolved.implementation and resolved.implementation_profile is not None:
            report.decoded["implementation"] = {
                "address": resolved.implementation,
                "kind": resolved.proxy_kind,
                "profile": resolved.implementation_profile.to_dict(),
            }
            for f in resolved.implementation_profile.findings:
                f = f.model_copy()
                f.evidence = {**f.evidence, "contract": resolved.implementation}
                report.findings.append(f)
        if not resolved.is_contract and not report.findings:
            report.findings.append(finding("BC010", f"{address} has no code."))
        report.notes = list(ctx.notes)
        return self._record(report)
