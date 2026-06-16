from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    title: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "title": self.title,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    operational_errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        severities = {finding.severity for finding in self.findings}
        if "critical" in severities or "high" in severities:
            return "BLOCKED"
        if severities:
            return "WARNING"
        return "PASS"

    def counts(self) -> dict[str, int]:
        result = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (
                -SEVERITY_ORDER[item.severity],
                item.rule_id,
                item.path,
                item.evidence,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "tool": "repo-publication-gate",
            "verdict": self.verdict,
            "root": str(self.root),
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "counts": self.counts(),
            "operational_errors": self.operational_errors,
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
        }
