"""HTTP API (FastAPI).

Security measures, in request order:

1. body size cap, enforced on the received stream (not only on Content-Length);
2. API key authentication: keys are compared by SHA-256 digest with
   :func:`hmac.compare_digest`; the server refuses to start without keys unless
   anonymous access is explicitly enabled;
3. per-client token-bucket rate limiting (keyed by API key digest, else client IP);
4. strict request schemas (unknown fields rejected) and typed error responses that
   never echo stack traces;
5. RPC endpoints are fixed by server configuration; requests can only pick a chain id.
"""

from __future__ import annotations

import hmac
import logging
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from txray import __version__
from txray.analysis.transaction import TxRequest
from txray.config import Settings, hash_api_key
from txray.errors import ConfigError, InvalidInputError, RpcError
from txray.hexutil import int_from_hex_or_dec, normalize_address, parse_hex
from txray.rules import RULES
from txray.service import Txray

log = logging.getLogger("txray.api")


# ---------------------------------------------------------------------- schemas
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Context(_Strict):
    chain_id: int | None = Field(default=None, gt=0, description="Chain the wallet is connected to")
    origin: str | None = Field(default=None, max_length=512, description="Requesting site")
    offline: bool = Field(default=False, description="Skip all RPC lookups")


class TransactionBody(_Strict):
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    data: str = Field(default="0x", max_length=200_000)
    value: str | int = "0"
    context: Context = Field(default_factory=Context)


class TypedDataBody(_Strict):
    from_: str | None = Field(default=None, alias="from")
    typed_data: dict[str, Any]
    context: Context = Field(default_factory=Context)


class MessageBody(_Strict):
    from_: str | None = Field(default=None, alias="from")
    method: Literal["personal_sign", "eth_sign"] = "personal_sign"
    message: str = Field(max_length=100_000)
    context: Context = Field(default_factory=Context)


class BytecodeBody(_Strict):
    code: str | None = Field(default=None, max_length=200_000)
    address: str | None = None
    context: Context = Field(default_factory=Context)


# ---------------------------------------------------------------------- rate limit
class TokenBucket:
    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Returns (allowed, seconds until a token is available)."""
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1 - tokens) / self.rate


class _BodyTooLargeError(Exception):
    pass


def _error(status: int, code: str, message: str, request_id: str | None = None) -> JSONResponse:
    headers = {"x-request-id": request_id} if request_id else None
    return JSONResponse(
        {"error": {"code": code, "message": message}}, status_code=status, headers=headers
    )


def create_app(settings: Settings, service: Txray | None = None) -> FastAPI:
    if not settings.api_key_hashes and not settings.allow_anonymous:
        raise ConfigError(
            "no API keys configured: set TXRAY_API_KEY_HASHES (see `txray keygen`) "
            "or explicitly allow anonymous access"
        )
    txray = service or Txray(settings)
    key_hashes = [bytes.fromhex(h) for h in settings.api_key_hashes]
    limiter = (
        TokenBucket(settings.rate_limit_per_minute) if settings.rate_limit_per_minute else None
    )

    app = FastAPI(
        title="txray",
        version=__version__,
        description="Pre-signing risk analysis for EVM transactions and signature requests.",
    )
    app.state.txray = txray

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex[:16]
        started = time.perf_counter()
        path = request.url.path

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_body_bytes:
            return _error(413, "body_too_large", "request body too large", request_id)
        if request.method in ("POST", "PUT", "PATCH"):
            chunks, size = [], 0
            try:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > settings.max_body_bytes:
                        raise _BodyTooLargeError
                    chunks.append(chunk)
            except _BodyTooLargeError:
                return _error(413, "body_too_large", "request body too large", request_id)
            request._body = b"".join(chunks)

        client_key = request.client.host if request.client else "unknown"
        if path != "/health" and key_hashes:
            presented = request.headers.get("x-api-key", "")
            digest = bytes.fromhex(hash_api_key(presented)) if presented else b""
            # Compare against every key so timing does not reveal which one matched.
            matched = False
            for expected in key_hashes:
                matched |= hmac.compare_digest(digest, expected)
            if not matched:
                return _error(401, "unauthorized", "missing or invalid X-API-Key", request_id)
            client_key = "key:" + digest.hex()[:16]

        if limiter is not None and path != "/health":
            allowed, retry_after = limiter.allow(client_key)
            if not allowed:
                limited = _error(429, "rate_limited", "too many requests", request_id)
                limited.headers["retry-after"] = str(max(1, int(retry_after + 0.999)))
                return limited

        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["cache-control"] = "no-store"
        log.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )
        return response

    @app.exception_handler(InvalidInputError)
    async def invalid_input(_: Request, exc: InvalidInputError) -> JSONResponse:
        return _error(422, "invalid_input", str(exc))

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return _error(
            exc.status_code, "not_found" if exc.status_code == 404 else "error", str(exc.detail)
        )

    @app.exception_handler(RpcError)
    async def rpc_error(_: Request, exc: RpcError) -> JSONResponse:
        log.warning("rpc failure", extra={"error": str(exc)})
        return _error(502, "rpc_error", "upstream RPC request failed")

    def ctx_for(body_ctx: Context, sender: str | None) -> Any:
        return txray.context(body_ctx.chain_id, sender, body_ctx.origin, offline=body_ctx.offline)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "chains": sorted(txray.readers)}

    @app.get("/v1/rules")
    def rules() -> list[dict[str, str]]:
        return [
            {"id": r.id, "severity": r.severity.label, "title": r.title, "rationale": r.rationale}
            for r in RULES.values()
        ]

    @app.post("/v1/analyze/transaction")
    def analyze_transaction(body: TransactionBody) -> dict[str, Any]:
        tx = TxRequest(
            to=normalize_address(body.to, field="to") if body.to else None,
            data=parse_hex(body.data, field="data"),
            value=int_from_hex_or_dec(body.value, field="value"),
            sender=body.from_,
        )
        return txray.transaction(tx, ctx_for(body.context, body.from_))

    @app.post("/v1/analyze/typed-data")
    def analyze_typed_data(body: TypedDataBody) -> dict[str, Any]:
        return txray.typed_data(body.typed_data, ctx_for(body.context, body.from_))

    @app.post("/v1/analyze/message")
    def analyze_message(body: MessageBody) -> dict[str, Any]:
        return txray.message(body.method, body.message, ctx_for(body.context, body.from_))

    @app.post("/v1/analyze/bytecode")
    def analyze_bytecode(body: BytecodeBody) -> dict[str, Any]:
        code = parse_hex(body.code, field="code") if body.code is not None else None
        return txray.bytecode(code=code, address=body.address, ctx=ctx_for(body.context, None))

    @app.get("/v1/reports")
    def list_reports(limit: int = 50) -> list[dict[str, Any]]:
        if txray.store is None:
            raise HTTPException(404, "report storage disabled")
        return txray.store.list_reports(max(1, min(limit, 500)))

    @app.get("/v1/reports/{report_id}")
    def get_report(report_id: str) -> dict[str, Any]:
        if txray.store is None:
            raise HTTPException(404, "report storage disabled")
        if not report_id.isalnum() or len(report_id) > 64:
            raise HTTPException(404, "report not found")
        report = txray.store.get_report(report_id)
        if report is None:
            raise HTTPException(404, "report not found")
        return report

    return app
