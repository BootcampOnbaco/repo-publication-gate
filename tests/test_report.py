from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_publication_gate.models import Finding, ScanResult
from repo_publication_gate.report import render_json, render_markdown


class ReportTests(unittest.TestCase):
    def test_json_is_machine_readable(self) -> None:
        result = ScanResult(root=Path("/synthetic"))
        result.findings.append(
            Finding(
                rule_id="RPG009",
                severity="low",
                path="LICENSE",
                title="Missing",
                evidence="synthetic",
                remediation="add it",
            )
        )
        payload = json.loads(render_json(result))
        self.assertEqual(payload["verdict"], "WARNING")
        self.assertEqual(payload["findings"][0]["rule_id"], "RPG009")

    def test_markdown_contains_summary_and_details(self) -> None:
        result = ScanResult(root=Path("/synthetic"), scanned_files=3)
        result.findings.append(
            Finding(
                rule_id="RPG001",
                severity="high",
                path=".env",
                title="Environment file detected",
                evidence="synthetic",
                remediation="remove it",
            )
        )
        payload = render_markdown(result)
        self.assertIn("**BLOCKED**", payload)
        self.assertIn("RPG001", payload)
        self.assertIn("remove it", payload)


if __name__ == "__main__":
    unittest.main()
