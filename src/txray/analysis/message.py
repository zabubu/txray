"""Analysis of ``personal_sign`` / ``eth_sign`` requests, including EIP-4361 (SIWE)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from txray.analysis.context import AnalysisContext
from txray.errors import InvalidInputError
from txray.hexutil import is_address, parse_hex
from txray.models import Report
from txray.rules import finding

SIWE_HEADER = re.compile(
    r"^(?:(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://)?(?P<domain>\S+)"
    r" wants you to sign in with your Ethereum account:$"
)
_FIELD = re.compile(
    r"^(URI|Version|Chain ID|Nonce|Issued At|Expiration Time|Not Before|Request ID): (.*)$"
)
_NONCE = re.compile(r"^[A-Za-z0-9]{8,}$")
MAX_DISPLAY = 2000


@dataclass
class SiweMessage:
    domain: str
    address: str
    statement: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    resources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def parse_siwe(text: str) -> SiweMessage | None:
    """Parse an EIP-4361 message. Returns None if the text is not SIWE at all;
    structural problems are collected in ``errors`` instead of raising."""
    lines = text.replace("\r\n", "\n").split("\n")
    header = SIWE_HEADER.match(lines[0]) if lines else None
    if header is None:
        return None
    msg = SiweMessage(
        domain=header.group("domain"), address=lines[1].strip() if len(lines) > 1 else ""
    )
    if not is_address(msg.address):
        msg.errors.append("second line is not an Ethereum address")
    rest = lines[2:]
    if rest and rest[0] == "":
        rest = rest[1:]
    if rest and not _FIELD.match(rest[0]) and rest[0] != "":
        msg.statement = rest[0]
        rest = rest[1:]
    in_resources = False
    for line in rest:
        if not line:
            continue
        if in_resources and line.startswith("- "):
            msg.resources.append(line[2:])
            continue
        if line == "Resources:":
            in_resources = True
            continue
        m = _FIELD.match(line)
        if m is None:
            msg.errors.append(f"unexpected line: {line[:80]!r}")
            continue
        if m.group(1) in msg.fields:
            msg.errors.append(f"duplicate field {m.group(1)}")
        msg.fields[m.group(1)] = m.group(2)

    for required in ("URI", "Version", "Chain ID", "Nonce", "Issued At"):
        if required not in msg.fields:
            msg.errors.append(f"missing {required}")
    if msg.fields.get("Version", "1") != "1":
        msg.errors.append("Version must be 1")
    if "Chain ID" in msg.fields and not msg.fields["Chain ID"].isdigit():
        msg.errors.append("Chain ID is not a number")
    if "Nonce" in msg.fields and not _NONCE.match(msg.fields["Nonce"]):
        msg.errors.append("Nonce must be at least 8 alphanumeric characters")
    for key in ("Issued At", "Expiration Time", "Not Before"):
        if key in msg.fields and _parse_time(msg.fields[key]) is None:
            msg.errors.append(f"{key} is not an RFC 3339 timestamp")
    return msg


def _origin_host(origin: str) -> str:
    parsed = urlsplit(origin if "://" in origin else f"https://{origin}")
    host = (parsed.hostname or "").lower()
    return f"{host}:{parsed.port}" if parsed.port else host


class MessageAnalyzer:
    def __init__(self, ctx: AnalysisContext) -> None:
        self.ctx = ctx

    def run(self, method: str, payload: str) -> Report:
        if method not in ("personal_sign", "eth_sign"):
            raise InvalidInputError("method must be personal_sign or eth_sign")
        report = Report(kind="message", chain_id=self.ctx.chain_id)
        findings = report.findings
        decoded: dict[str, Any] = {"method": method}

        is_hex = payload.startswith(("0x", "0X"))
        if is_hex:
            try:
                raw = parse_hex(payload, field="message")
            except InvalidInputError:
                if method == "eth_sign":
                    raise
                # Wallets display personal_sign input that is not valid hex as text.
                is_hex, raw = False, payload.encode("utf-8")
        else:
            raw = payload.encode("utf-8")
        decoded["length"] = len(raw)

        if method == "eth_sign":
            if not is_hex:
                raise InvalidInputError("eth_sign expects a hex-encoded payload")
            if len(raw) == 32:
                findings.append(
                    finding(
                        "MSG001",
                        "eth_sign of a 32-byte value: the signer cannot know what it authorizes.",
                        hash="0x" + raw.hex(),
                    )
                )
                decoded["hex"] = "0x" + raw.hex()
                return self._finish(report, decoded)

        try:
            text = raw.decode("utf-8")
            printable = all(c.isprintable() or c in "\n\r\t" for c in text)
        except UnicodeDecodeError:
            text, printable = None, False

        if text is None or not printable:
            decoded["hex"] = "0x" + raw.hex()
            if len(raw) == 32:
                findings.append(
                    finding("MSG002", "The message is a 32-byte binary value.", hex=decoded["hex"])
                )
            else:
                findings.append(finding("MSG003", f"{len(raw)} bytes of binary data."))
            return self._finish(report, decoded)

        decoded["text"] = text[:MAX_DISPLAY]
        siwe = parse_siwe(text)
        if siwe is not None:
            decoded["siwe"] = {
                "domain": siwe.domain,
                "address": siwe.address,
                "statement": siwe.statement,
                **{k.lower().replace(" ", "_"): v for k, v in siwe.fields.items()},
                "resources": siwe.resources,
            }
            self._siwe_rules(siwe, report)
        return self._finish(report, decoded)

    def _finish(self, report: Report, decoded: dict[str, Any]) -> Report:
        report.decoded = decoded
        report.notes = list(self.ctx.notes)
        return report

    def _siwe_rules(self, siwe: SiweMessage, report: Report) -> None:
        f = report.findings
        if siwe.errors:
            f.append(finding("MSG014", "; ".join(siwe.errors) + ".", errors=siwe.errors))
        if self.ctx.origin:
            expected = _origin_host(self.ctx.origin)
            claimed = siwe.domain.lower()
            if claimed != expected:
                f.append(
                    finding(
                        "MSG010",
                        f"Message is for {siwe.domain!r} but was requested by {expected!r}.",
                        message_domain=siwe.domain,
                        origin=expected,
                    )
                )
        else:
            self.ctx.note("Requesting origin not provided: SIWE domain binding not checked.")
        if (
            self.ctx.sender
            and is_address(siwe.address)
            and siwe.address.lower() != self.ctx.sender.lower()
        ):
            f.append(
                finding(
                    "MSG011",
                    f"Message address {siwe.address} differs from signer {self.ctx.sender}.",
                )
            )
        chain = siwe.fields.get("Chain ID")
        if (
            chain
            and chain.isdigit()
            and self.ctx.chain_id is not None
            and int(chain) != self.ctx.chain_id
        ):
            f.append(
                finding("MSG012", f"Message Chain ID {chain}, wallet is on {self.ctx.chain_id}.")
            )
        now = self.ctx.now
        exp = _parse_time(siwe.fields.get("Expiration Time", ""))
        nbf = _parse_time(siwe.fields.get("Not Before", ""))
        if exp is not None and exp.timestamp() < now:
            f.append(finding("MSG013", f"Expired at {siwe.fields['Expiration Time']}."))
        if nbf is not None and nbf.timestamp() > now:
            f.append(finding("MSG013", f"Not valid before {siwe.fields['Not Before']}."))


def analyze_message(method: str, payload: str, ctx: AnalysisContext) -> Report:
    return MessageAnalyzer(ctx).run(method, payload)
