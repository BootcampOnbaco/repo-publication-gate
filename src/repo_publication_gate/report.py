from __future__ import annotations

import json

from .models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        "# Repository Publication Gate",
        "",
        f"- Verdict: **{result.verdict}**",
        f"- Root: `{result.root}`",
        f"- Scanned files: {result.scanned_files}",
        f"- Skipped entries: {result.skipped_files}",
        (
            "- Findings: "
            f"critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, info={counts['info']}"
        ),
        "",
    ]

    if result.operational_errors:
        lines.extend(["## Operational errors", ""])
        for error in result.operational_errors:
            lines.append(f"- {error}")
        lines.append("")

    if not result.findings:
        lines.extend(
            [
                "## Result",
                "",
                "No publication findings were detected.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "## Findings",
            "",
            "| Severity | Rule | Path | Finding |",
            "|---|---|---|---|",
        ]
    )

    for finding in result.sorted_findings():
        safe_title = finding.title.replace("|", "\\|")
        safe_path = finding.path.replace("|", "\\|")
        lines.append(
            f"| {finding.severity.upper()} | `{finding.rule_id}` | "
            f"`{safe_path}` | {safe_title} |"
        )

    lines.extend(["", "## Evidence and remediation", ""])

    for index, finding in enumerate(result.sorted_findings(), start=1):
        lines.extend(
            [
                f"### {index}. {finding.rule_id} — {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Path: `{finding.path}`",
                f"- Evidence: `{finding.evidence.replace('`', chr(39))}`",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation",
            "",
            "This report reduces publication risk but does not prove that the repository "
            "is safe, legally publishable, or free of sensitive information.",
            "",
        ]
    )
    return "\n".join(lines)
