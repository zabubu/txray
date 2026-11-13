"""CLI tests run the real entry point (offline, or with a fixture database)."""

import io
import json
from pathlib import Path

import pytest

from tests.conftest import EXAMPLES, FIXTURES, ROOT
from txray.cli import EXIT_FINDINGS, main


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("TXRAY_CONFIG", "TXRAY_RPC_1", "TXRAY_API_KEY_HASHES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TXRAY_DB", str(tmp_path / "cli.db"))
    monkeypatch.setenv("TXRAY_DENYLIST", str(ROOT / "config" / "denylist.example.txt"))
    monkeypatch.setenv("TXRAY_ADDRESS_BOOK", str(ROOT / "config" / "address_book.example.txt"))


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


def test_typed_data_json_output() -> None:
    code, out = run(
        "--json", "typed-data", str(EXAMPLES / "seaport-zero-price-listing.json"), "--offline"
    )
    assert code == 0
    report = json.loads(out)
    assert report["verdict"] == "block"
    assert "SIG030" in {f["rule_id"] for f in report["findings"]}


def test_fail_on_exit_code() -> None:
    code, _ = run(
        "--fail-on", "high", "typed-data", str(EXAMPLES / "permit2-batch-sweep.json"), "--offline"
    )
    assert code == EXIT_FINDINGS


def test_text_output_for_poisoned_transfer() -> None:
    request = json.loads((EXAMPLES / "requests" / "poisoned-transfer.json").read_text())
    code, out = run("tx", "--to", request["to"], "--data", request["data"], "--offline")
    assert code == 0
    assert out.startswith("BLOCK")
    assert "INT002" in out
    assert "Offline mode" in out


def test_message_and_report_roundtrip() -> None:
    code, out = run(
        "--json",
        "message",
        "--file",
        str(EXAMPLES / "siwe-login.txt"),
        "--origin",
        "https://app.example.org",
        "--offline",
    )
    assert code == 0
    report_id = json.loads(out)["id"]
    code, out = run("--json", "report", report_id)
    assert code == 0
    assert json.loads(out)["id"] == report_id


def test_bytecode_and_disasm() -> None:
    code, out = run("bytecode", "--file", str(FIXTURES / "bytecode" / "weth9.hex"), "--offline")
    assert code == 0
    assert "deposit()" in out
    code, out = run("disasm", "--code", "0x6001600201")
    assert out.splitlines()[:3] == ["00000  PUSH1 0x01", "00002  PUSH1 0x02", "00004  ADD"]
    code, out = run("disasm", "--blocks", "--code", "0x600456005b00")
    assert "block 0x0 -> [0x4]" in out


def test_rules_and_keygen() -> None:
    code, out = run("rules")
    assert code == 0 and "INT002" in out
    code, out = run("keygen")
    assert code == 0 and "sha256" in out


def test_input_errors_return_1(capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run("tx", "--to", "0x1234", "--offline")
    assert code == 1
    assert "invalid address" in capsys.readouterr().err
    code, _ = run("bytecode", "--address", "0x" + "11" * 20)
    assert code == 1  # no RPC configured


def test_rules_doc_is_up_to_date() -> None:
    code, out = run("rules", "--markdown")
    assert code == 0
    assert (ROOT / "docs" / "RULES.md").read_text() == out, "regenerate docs/RULES.md"
