"""End-to-end tests of the HTTP API: real app, real analyzers, fixture-backed chain."""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import EOA, ROOT, USDC, FakeChain, load_example, rule_ids
from txray.api import TokenBucket, create_app
from txray.config import Settings, hash_api_key
from txray.errors import ConfigError
from txray.service import Txray
from txray.storage import Store

KEY = "test-key-0123456789"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        api_key_hashes=[hash_api_key(KEY)],
        rate_limit_per_minute=1000,
        max_body_bytes=64 * 1024,
        denylist=ROOT / "config" / "denylist.example.txt",
        address_book=ROOT / "config" / "address_book.example.txt",
    )


@pytest.fixture
def client(settings: Settings, mainnet: FakeChain) -> Iterator[TestClient]:
    service = Txray(settings, readers={1: mainnet}, store=Store(":memory:"))
    with TestClient(create_app(settings, service)) as c:
        c.headers["x-api-key"] = KEY
        yield c


def test_health_is_public(client: TestClient) -> None:
    del client.headers["x-api-key"]
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["chains"] == [1]


@pytest.mark.parametrize("key", [None, "wrong"])
def test_auth_required(client: TestClient, key: str | None) -> None:
    del client.headers["x-api-key"]
    headers = {"x-api-key": key} if key else {}
    response = client.get("/v1/rules", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_rules_catalog(client: TestClient) -> None:
    rules = client.get("/v1/rules").json()
    assert {"INT002", "SIG030", "MSG001", "BC007"} <= {r["id"] for r in rules}


def test_poisoned_transfer_request(client: TestClient) -> None:
    response = client.post(
        "/v1/analyze/transaction", json=load_example("requests/poisoned-transfer.json")
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "block"
    assert "INT002" in rule_ids(body)
    assert body["decoded"]["call"]["function"] == "transfer(address,uint256)"
    assert response.headers["x-request-id"]
    # Report persisted and retrievable.
    stored = client.get(f"/v1/reports/{body['id']}").json()
    assert stored["id"] == body["id"]
    assert client.get("/v1/reports").json()[0]["id"] == body["id"]


def test_permit2_request(client: TestClient) -> None:
    body = client.post(
        "/v1/analyze/typed-data", json=load_example("requests/permit2-batch-sweep.json")
    ).json()
    assert {"SIG021", "INT001"} <= rule_ids(body)
    assert body["findings"][0]["severity"] == "critical"  # sorted by severity


def test_siwe_request(client: TestClient) -> None:
    body = client.post(
        "/v1/analyze/message", json=load_example("requests/siwe-wrong-origin.json")
    ).json()
    assert "MSG010" in rule_ids(body)


def test_bytecode_by_address_follows_proxy(client: TestClient) -> None:
    body = client.post(
        "/v1/analyze/bytecode", json={"address": USDC, "context": {"chain_id": 1}}
    ).json()
    assert body["decoded"]["implementation"]["kind"] == "zeppelinos.implementation"
    assert {"BC005", "BC006"} <= rule_ids(body)


def test_bytecode_inline(client: TestClient) -> None:
    body = client.post("/v1/analyze/bytecode", json={"code": "0x33ff"}).json()
    assert "BC001" in rule_ids(body)


def test_bytecode_unknown_chain_is_input_error(client: TestClient) -> None:
    response = client.post(
        "/v1/analyze/bytecode", json={"address": USDC, "context": {"chain_id": 5}}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_input"


@pytest.mark.parametrize(
    "payload",
    [
        {"to": "0x1234", "data": "0x"},
        {"to": USDC, "data": "0xzz"},
        {"to": USDC, "value": "-5"},
        {"to": USDC, "unexpected": True},
    ],
)
def test_invalid_transaction_input(client: TestClient, payload: dict[str, Any]) -> None:
    response = client.post("/v1/analyze/transaction", json=payload)
    assert response.status_code == 422


def test_invalid_typed_data(client: TestClient) -> None:
    response = client.post("/v1/analyze/typed-data", json={"typed_data": {"types": {}}})
    assert response.status_code == 422
    assert "missing top-level" in response.json()["error"]["message"]


def test_body_size_limit(client: TestClient) -> None:
    response = client.post(
        "/v1/analyze/message",
        content=b'{"message": "' + b"a" * 70_000 + b'"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_body_size_limit_without_content_length(client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"message": "'
        for _ in range(100):
            yield b"a" * 1000
        yield b'"}'

    response = client.post(
        "/v1/analyze/message", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


def test_rate_limit(settings: Settings, mainnet: FakeChain) -> None:
    settings.rate_limit_per_minute = 2
    service = Txray(settings, readers={1: mainnet})
    with TestClient(create_app(settings, service)) as c:
        c.headers["x-api-key"] = KEY
        statuses = [c.get("/v1/rules").status_code for _ in range(3)]
    assert statuses == [200, 200, 429]


def test_token_bucket_refills() -> None:
    now = [0.0]
    bucket = TokenBucket(60, clock=lambda: now[0])
    assert all(bucket.allow("k")[0] for _ in range(60))
    allowed, retry = bucket.allow("k")
    assert not allowed and retry == pytest.approx(1.0)
    now[0] += 1.0
    assert bucket.allow("k")[0]


def test_refuses_to_start_without_keys() -> None:
    with pytest.raises(ConfigError):
        create_app(Settings())


def test_anonymous_mode(mainnet: FakeChain) -> None:
    settings = Settings(allow_anonymous=True)
    with TestClient(create_app(settings, Txray(settings, readers={1: mainnet}))) as c:
        body = c.post(
            "/v1/analyze/transaction",
            json={
                "to": USDC,
                "data": "0x095ea7b3" + EOA[2:].lower().rjust(64, "0") + "f" * 64,
                "context": {"chain_id": 1},
            },
        ).json()
    assert "TX002" in rule_ids(body)


def test_reports_disabled_without_store(settings: Settings, mainnet: FakeChain) -> None:
    with TestClient(create_app(settings, Txray(settings, readers={1: mainnet}))) as c:
        response = c.get("/v1/reports/abc", headers={"x-api-key": KEY})
    assert response.status_code == 404
