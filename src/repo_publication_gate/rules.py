from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ContentRule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    remediation: str


SECRET_RULES = [
    ContentRule(
        "RPG004",
        "critical",
        "Private key material detected",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Remove the private key, rotate it, and purge it from Git history before publication.",
    ),
    ContentRule(
        "RPG004",
        "high",
        "OpenAI-style secret detected",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "Remove and rotate the credential. Use environment variables or a secret manager.",
    ),
    ContentRule(
        "RPG004",
        "high",
        "GitHub token-like value detected",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        "Remove and revoke the token before publication.",
    ),
    ContentRule(
        "RPG004",
        "high",
        "AWS access key-like value detected",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Remove and rotate the credential before publication.",
    ),
    ContentRule(
        "RPG004",
        "high",
        "Hard-coded credential assignment detected",
        re.compile(
            r"""(?ix)
            \b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)
            \s*[:=]\s*
            ["'][^"'{}\n]{8,}["']
            """
        ),
        "Replace the value with a safe placeholder and load the real secret outside the repository.",
    ),
]

LOCAL_PATH_RULES = [
    re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s\"']+", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[^/\s\"']+"),
]

SENSITIVE_EXACT_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

SENSITIVE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".bak",
    ".dump",
    ".backup",
}

GENERATED_DIR_NAMES = {
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "coverage",
    ".coverage",
}

GOVERNANCE_FILES = {
    "LICENSE": "Add an explicit open-source license.",
    "SECURITY.md": "Add a vulnerability-reporting policy.",
    "CONTRIBUTING.md": "Add contribution and validation instructions.",
    "CODE_OF_CONDUCT.md": "Add contributor conduct expectations.",
}

RECOMMENDED_GITIGNORE_PATTERNS = {
    ".env": "Protect environment files.",
    "*.pem": "Protect private key/certificate files.",
    "*.key": "Protect private key files.",
    "*.sqlite": "Protect local database files.",
    "*.db": "Protect local database files.",
    ".venv/": "Protect local virtual environments.",
    "node_modules/": "Protect generated dependency directories.",
}

BINARY_SUFFIXES = {
    ".7z",
    ".avi",
    ".bmp",
    ".class",
    ".dll",
    ".doc",
    ".docx",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".pyc",
    ".so",
    ".tar",
    ".tgz",
    ".webp",
    ".xls",
    ".xlsx",
    ".zip",
}
