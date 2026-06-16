from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from .config import GateConfig
from .models import Finding, ScanResult
from .rules import (
    BINARY_SUFFIXES,
    GENERATED_DIR_NAMES,
    GOVERNANCE_FILES,
    LOCAL_PATH_RULES,
    RECOMMENDED_GITIGNORE_PATTERNS,
    SECRET_RULES,
    SENSITIVE_EXACT_NAMES,
    SENSITIVE_SUFFIXES,
)


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _is_allowed(path: str, config: GateConfig) -> bool:
    return _matches_any(path, config.allow_paths)


def _is_ignored(path: str, config: GateConfig) -> bool:
    return _matches_any(path, config.ignore_paths)


def _safe_excerpt(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    if len(line) > 160:
        line = line[:157] + "..."
    return line


def _scan_file_content(path: Path, relative: str, config: GateConfig) -> list[Finding]:
    findings: list[Finding] = []

    if path.suffix.lower() in BINARY_SUFFIXES:
        return findings

    try:
        if path.stat().st_size > config.content_scan_max_bytes:
            return findings
        raw = path.read_bytes()
    except OSError:
        return findings

    if b"\x00" in raw:
        return findings

    text = raw.decode("utf-8", errors="replace")

    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            evidence = _safe_excerpt(text, match.start(), match.end())
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    path=relative,
                    title=rule.title,
                    evidence=evidence,
                    remediation=rule.remediation,
                )
            )

    for pattern in LOCAL_PATH_RULES:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id="RPG005",
                    severity="medium",
                    path=relative,
                    title="Absolute local workstation path detected",
                    evidence=match.group(0),
                    remediation=(
                        "Replace the local path with a relative path, environment variable, "
                        "or documented placeholder."
                    ),
                )
            )

    return findings


def _check_gitignore(root: Path) -> list[Finding]:
    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        return [
            Finding(
                rule_id="RPG010",
                severity="medium",
                path=".gitignore",
                title=".gitignore is missing",
                evidence="No .gitignore file exists at repository root.",
                remediation="Add a .gitignore covering secrets, local data, and generated files.",
            )
        ]

    try:
        lines = {
            line.strip()
            for line in gitignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError as exc:
        return [
            Finding(
                rule_id="RPG010",
                severity="medium",
                path=".gitignore",
                title=".gitignore could not be read",
                evidence=str(exc),
                remediation="Make the file readable and verify its protection rules.",
            )
        ]

    findings: list[Finding] = []
    for required, remediation in sorted(RECOMMENDED_GITIGNORE_PATTERNS.items()):
        if required not in lines:
            findings.append(
                Finding(
                    rule_id="RPG010",
                    severity="medium",
                    path=".gitignore",
                    title="Recommended .gitignore protection is missing",
                    evidence=f"Missing pattern: {required}",
                    remediation=remediation,
                )
            )
    return findings


def _check_governance(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    names = {path.name.upper() for path in root.iterdir() if path.is_file()}

    for required, remediation in GOVERNANCE_FILES.items():
        if required.upper() not in names:
            findings.append(
                Finding(
                    rule_id="RPG009",
                    severity="low",
                    path=required,
                    title="Recommended governance document is missing",
                    evidence=f"{required} was not found at repository root.",
                    remediation=remediation,
                )
            )
    return findings


def scan_repository(root: Path, config: GateConfig) -> ScanResult:
    root = root.resolve()
    result = ScanResult(root=root)

    if not root.exists():
        result.operational_errors.append(f"Path does not exist: {root}")
        return result
    if not root.is_dir():
        result.operational_errors.append(f"Path is not a directory: {root}")
        return result

    result.findings.extend(_check_governance(root))
    result.findings.extend(_check_gitignore(root))

    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current_root)
        relative_current = (
            "." if current_path == root else _relative_posix(current_path, root)
        )

        original_dirnames = list(dirnames)
        kept_dirs: list[str] = []

        for dirname in original_dirnames:
            full_dir = current_path / dirname
            relative_dir = _relative_posix(full_dir, root)

            if relative_dir == ".git":
                continue

            if _is_ignored(relative_dir + "/**", config) or _is_ignored(relative_dir, config):
                result.skipped_files += 1
                continue

            if full_dir.is_symlink():
                result.findings.append(
                    Finding(
                        rule_id="RPG011",
                        severity="medium",
                        path=relative_dir,
                        title="Symlinked directory requires manual review",
                        evidence=f"Directory symlink: {relative_dir}",
                        remediation=(
                            "Verify the symlink target is intended, portable, and contains no "
                            "private material before publication."
                        ),
                    )
                )
                continue

            if dirname == ".git":
                result.findings.append(
                    Finding(
                        rule_id="RPG008",
                        severity="high",
                        path=relative_dir,
                        title="Nested Git metadata detected",
                        evidence=f"Nested .git directory at {relative_dir}",
                        remediation=(
                            "Remove nested repository metadata or explicitly publish it as a "
                            "submodule with documented intent."
                        ),
                    )
                )
                continue

            if dirname in GENERATED_DIR_NAMES:
                result.findings.append(
                    Finding(
                        rule_id="RPG007",
                        severity="medium",
                        path=relative_dir,
                        title="Generated or runtime directory detected",
                        evidence=f"Directory name: {dirname}",
                        remediation=(
                            "Remove generated/runtime content from the publication set and add "
                            "an appropriate .gitignore rule."
                        ),
                    )
                )

            kept_dirs.append(dirname)

        dirnames[:] = kept_dirs

        for filename in filenames:
            full_path = current_path / filename
            relative = _relative_posix(full_path, root)

            if _is_ignored(relative, config):
                result.skipped_files += 1
                continue

            if full_path.is_symlink():
                result.findings.append(
                    Finding(
                        rule_id="RPG011",
                        severity="medium",
                        path=relative,
                        title="Symlinked file requires manual review",
                        evidence=f"File symlink: {relative}",
                        remediation=(
                            "Verify the symlink target is intended, portable, and contains no "
                            "private material before publication."
                        ),
                    )
                )
                continue

            try:
                size = full_path.stat().st_size
            except OSError as exc:
                result.operational_errors.append(f"Cannot stat {relative}: {exc}")
                continue

            result.scanned_files += 1

            if size > config.max_file_size_bytes:
                result.findings.append(
                    Finding(
                        rule_id="RPG006",
                        severity="medium",
                        path=relative,
                        title="Oversized file detected",
                        evidence=f"{size} bytes exceeds {config.max_file_size_bytes} bytes.",
                        remediation=(
                            "Remove the artifact, use release assets or Git LFS, or explicitly "
                            "raise the configured threshold after review."
                        ),
                    )
                )

            lower_name = filename.lower()
            allowed = _is_allowed(relative, config)

            if not allowed and (
                lower_name in SENSITIVE_EXACT_NAMES
                or (lower_name.startswith(".env.") and lower_name not in {".env.example", ".env.template"})
            ):
                result.findings.append(
                    Finding(
                        rule_id="RPG001",
                        severity="high",
                        path=relative,
                        title="Environment file detected",
                        evidence=f"Sensitive filename: {filename}",
                        remediation=(
                            "Remove the file, rotate exposed values, and publish only a safe "
                            "placeholder such as .env.example."
                        ),
                    )
                )

            if not allowed and full_path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
                result.findings.append(
                    Finding(
                        rule_id="RPG002",
                        severity="high",
                        path=relative,
                        title="Private key or certificate container detected",
                        evidence=f"Sensitive suffix: {full_path.suffix.lower()}",
                        remediation=(
                            "Remove the file and rotate or revoke related credentials before "
                            "publication."
                        ),
                    )
                )

            if not allowed and full_path.suffix.lower() in {
                ".sqlite",
                ".sqlite3",
                ".db",
                ".bak",
                ".dump",
                ".backup",
            }:
                result.findings.append(
                    Finding(
                        rule_id="RPG003",
                        severity="high",
                        path=relative,
                        title="Local database, dump, or backup detected",
                        evidence=f"Sensitive suffix: {full_path.suffix.lower()}",
                        remediation=(
                            "Remove private data artifacts. Publish a schema or synthetic fixture "
                            "instead."
                        ),
                    )
                )

            result.findings.extend(_scan_file_content(full_path, relative, config))

    return result
