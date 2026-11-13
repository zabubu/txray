"""Report data model shared by the analyzers, the CLI and the HTTP API."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 20,
    Severity.HIGH: 45,
    Severity.CRITICAL: 80,
}


class Verdict(enum.StrEnum):
    PASS = "pass"  # noqa: S105 - verdict label, not a credential; nothing above LOW
    WARN = "warn"  # MEDIUM or HIGH findings: the user must read before signing
    BLOCK = "block"  # at least one CRITICAL finding


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    detail: str
    evidence: dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": False}

    def to_public(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


class Report(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    kind: str  # transaction | typed_data | message | bytecode
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    chain_id: int | None = None
    findings: list[Finding] = Field(default_factory=list)
    decoded: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def score(self) -> int:
        return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in self.findings))

    @property
    def verdict(self) -> Verdict:
        top = self.max_severity
        if top >= Severity.CRITICAL:
            return Verdict.BLOCK
        if top >= Severity.MEDIUM:
            return Verdict.WARN
        return Verdict.PASS

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.rule_id))

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "created_at": self.created_at,
            "chain_id": self.chain_id,
            "verdict": self.verdict.value,
            "score": self.score,
            "max_severity": self.max_severity.label,
            "findings": [f.to_public() for f in self.sorted_findings()],
            "decoded": self.decoded,
            "notes": self.notes,
        }
